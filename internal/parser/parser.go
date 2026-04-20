package parser

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aaronflorey/strace-analyser/internal/model"
)

type fdInfo struct {
	Kind     string
	Path     string
	Proto    string
	Peer     string
	Endpoint string
}

var (
	rePort4   = regexp.MustCompile(`sin_port=htons\((\d+)\)`)
	reAddr4   = regexp.MustCompile(`sin_addr=inet_addr\("([^"]+)"\)`)
	rePort6   = regexp.MustCompile(`sin6_port=htons\((\d+)\)`)
	reAddr6   = regexp.MustCompile(`inet_pton\(AF_INET6, "([^"]+)"`)
	reSun     = regexp.MustCompile(`sun_path="([^"]+)"`)
	reTime    = regexp.MustCompile(`<([0-9]+\.[0-9]+)>\s*$`)
	reErrno   = regexp.MustCompile(`=\s*-1\s+([A-Z0-9_]+)\b`)
	reFDPair  = regexp.MustCompile(`\[(\d+),\s*(\d+)\]`)
	rePIDTail = regexp.MustCompile(`\.(\d+)$`)
)

func AnalyzeDir(dir string) (*model.Report, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory %q: %w", dir, err)
	}

	report := model.NewReport()
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if !(strings.Contains(name, "strace") || strings.HasSuffix(name, ".trace")) {
			continue
		}
		pid := parsePIDFromName(name)
		fullPath := filepath.Join(dir, name)
		if err := parseFile(fullPath, pid, report); err != nil {
			return nil, fmt.Errorf("parse %q: %w", fullPath, err)
		}
		report.ParsedFiles++
	}

	if report.ParsedFiles == 0 {
		return nil, fmt.Errorf("no strace-like files found in %q", dir)
	}
	return report, nil
}

func parseFile(path string, pid int, report *model.Report) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fdMap := make(map[int]fdInfo, 256)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "<unfinished ...>") || strings.Contains(line, "resumed>") {
			continue
		}

		sys := callName(line)
		if sys == "" {
			continue
		}

		if errno, ok := parseErrno(line); ok {
			target := extractTarget(line, sys)
			addError(report, sys, errno, target)
		}

		switch sys {
		case "open", "openat", "openat2":
			handleOpen(line, fdMap, report)
		case "close":
			handleClose(line, fdMap)
		case "dup":
			handleDup(line, fdMap)
		case "dup2", "dup3":
			handleDup2(line, fdMap)
		case "read", "pread", "pread64", "readv", "preadv", "preadv2":
			handleReadLike(line, fdMap, report, true)
		case "write", "pwrite", "pwrite64", "writev", "pwritev", "pwritev2":
			handleReadLike(line, fdMap, report, false)
		case "mmap":
			handleMmap(line, fdMap, report)
		case "munmap":
			handleMunmap(line, report)
		case "brk", "mprotect", "madvise":
			addMemory(report, sys, 1, 0)
		case "socket":
			handleSocket(line, fdMap)
		case "connect":
			handleConnect(line, fdMap, report)
		case "accept", "accept4":
			handleAccept(line, fdMap, report)
		case "recv", "recvfrom", "recvmsg", "recvmmsg":
			handleNetIO(line, fdMap, report, false)
		case "send", "sendto", "sendmsg", "sendmmsg":
			handleNetIO(line, fdMap, report, true)
		case "futex":
			handleFutex(line, report)
		case "clone", "fork", "vfork":
			handleSpawn(line, pid, report)
		case "execve":
			handleExec(line, report)
		case "wait4", "waitid", "waitpid":
			report.Process.WaitCalls++
		case "exit", "exit_group":
			report.Process.ExitCalls++
		case "poll", "ppoll", "epoll_wait", "epoll_pwait", "epoll_pwait2", "select", "pselect6":
			handlePoll(line, sys, report)
		case "pipe", "pipe2", "socketpair", "eventfd", "eventfd2", "signalfd", "signalfd4":
			handleIPCSetup(line, sys, fdMap, report)
		}

		if isMetadataSyscall(sys) {
			handleMetadata(line, sys, fdMap, report)
		}
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func handleOpen(line string, fdMap map[int]fdInfo, report *model.Report) {
	fd, path, ok := parseOpenLine(line)
	if !ok || fd < 0 {
		return
	}
	fdMap[fd] = fdInfo{Kind: "file", Path: path}

	stat := report.Files[path]
	if stat == nil {
		stat = &model.FileStat{Path: path}
		report.Files[path] = stat
	}
	stat.Opens++
}

func handleClose(line string, fdMap map[int]fdInfo) {
	fd, ok := parseFirstIntArg(line)
	if ok {
		delete(fdMap, fd)
	}
}

func handleDup(line string, fdMap map[int]fdInfo) {
	oldFD, ok := parseFirstIntArg(line)
	if !ok {
		return
	}
	newFD, ok := parseReturnInt(line)
	if !ok || newFD < 0 {
		return
	}
	if info, exists := fdMap[oldFD]; exists {
		fdMap[newFD] = info
	}
}

func handleDup2(line string, fdMap map[int]fdInfo) {
	args := parseArgs(line)
	if len(args) < 2 {
		return
	}
	oldFD, err1 := strconv.Atoi(strings.TrimSpace(args[0]))
	newFD, err2 := strconv.Atoi(strings.TrimSpace(args[1]))
	if err1 != nil || err2 != nil {
		return
	}
	ret, ok := parseReturnInt(line)
	if !ok || ret < 0 {
		return
	}
	if info, exists := fdMap[oldFD]; exists {
		fdMap[newFD] = info
	}
}

func handleReadLike(line string, fdMap map[int]fdInfo, report *model.Report, read bool) {
	fd, n, ok := parseFDAndReturnBytes(line)
	if !ok || n <= 0 {
		return
	}
	info, exists := fdMap[fd]
	if !exists {
		return
	}

	switch info.Kind {
	case "file":
		if read {
			if stat := report.Files[info.Path]; stat != nil {
				stat.Bytes += n
			}
		}
	case "socket":
		addNetworkIO(report, info, n, !read)
	case "pipe", "eventfd", "signalfd", "socketpair":
		addIPCIO(report, info, n, !read)
	}
}

func handleMmap(line string, fdMap map[int]fdInfo, report *model.Report) {
	args := parseArgs(line)
	if len(args) < 6 {
		return
	}
	length, err1 := strconv.ParseInt(strings.TrimSpace(args[1]), 10, 64)
	fd, err2 := strconv.Atoi(strings.TrimSpace(args[4]))
	if err1 != nil || err2 != nil || length <= 0 {
		return
	}

	if fd >= 0 {
		if info, ok := fdMap[fd]; ok && info.Kind == "file" {
			if stat := report.Files[info.Path]; stat != nil {
				stat.Bytes += length
			}
		}
		addMemory(report, "mmap_file", 1, length)
		return
	}
	addMemory(report, "mmap_anon", 1, length)
}

func handleMunmap(line string, report *model.Report) {
	args := parseArgs(line)
	if len(args) < 2 {
		addMemory(report, "munmap", 1, 0)
		return
	}
	length, err := strconv.ParseInt(strings.TrimSpace(args[1]), 10, 64)
	if err != nil {
		addMemory(report, "munmap", 1, 0)
		return
	}
	addMemory(report, "munmap", 1, length)
}

func handleSocket(line string, fdMap map[int]fdInfo) {
	fd, ok := parseReturnInt(line)
	if !ok || fd < 0 {
		return
	}
	proto := "socket"
	if strings.Contains(line, "AF_UNIX") {
		proto = "unix"
	} else if strings.Contains(line, "AF_INET6") {
		if strings.Contains(line, "SOCK_DGRAM") {
			proto = "udp6"
		} else {
			proto = "tcp6"
		}
	} else if strings.Contains(line, "AF_INET") {
		if strings.Contains(line, "SOCK_DGRAM") {
			proto = "udp"
		} else {
			proto = "tcp"
		}
	}
	fdMap[fd] = fdInfo{Kind: "socket", Proto: proto}
}

func handleConnect(line string, fdMap map[int]fdInfo, report *model.Report) {
	fd, ok := parseFirstIntArg(line)
	if !ok {
		return
	}
	info, exists := fdMap[fd]
	if !exists || info.Kind != "socket" {
		return
	}

	peer := parseSockAddr(line)
	if peer == "" {
		peer = "unknown"
	}
	info.Peer = peer
	fdMap[fd] = info

	stat := ensureNetwork(report, info.Proto, peer)
	stat.Connects++
	if isErrReturn(line) {
		stat.Errors++
	}
}

func handleAccept(line string, fdMap map[int]fdInfo, report *model.Report) {
	listenFD, ok := parseFirstIntArg(line)
	if !ok {
		return
	}
	newFD, ok := parseReturnInt(line)
	if !ok || newFD < 0 {
		return
	}

	proto := "socket"
	if info, exists := fdMap[listenFD]; exists && info.Proto != "" {
		proto = info.Proto
	}
	peer := parseSockAddr(line)
	if peer == "" {
		peer = "unknown"
	}
	fdMap[newFD] = fdInfo{Kind: "socket", Proto: proto, Peer: peer}

	stat := ensureNetwork(report, proto, peer)
	stat.Accepts++
}

func handleNetIO(line string, fdMap map[int]fdInfo, report *model.Report, send bool) {
	fd, n, ok := parseFDAndReturnBytes(line)
	if !ok || n <= 0 {
		return
	}
	info, exists := fdMap[fd]
	if !exists || info.Kind != "socket" {
		return
	}
	addNetworkIO(report, info, n, send)
}

func handleFutex(line string, report *model.Report) {
	args := parseArgs(line)
	op := "UNKNOWN"
	if len(args) >= 2 {
		op = strings.TrimSpace(args[1])
		if idx := strings.IndexByte(op, '|'); idx >= 0 {
			op = op[:idx]
		}
	}
	if op == "" {
		op = "UNKNOWN"
	}

	stat := report.Locks[op]
	if stat == nil {
		stat = &model.LockStat{Op: op}
		report.Locks[op] = stat
	}
	stat.Count++
	if isErrReturn(line) {
		stat.Errors++
	}
	if strings.Contains(line, "ETIMEDOUT") {
		stat.Timeouts++
	}
	if d, ok := parseElapsed(line); ok {
		stat.TimeNS += d.Nanoseconds()
	}
}

func handleSpawn(line string, pid int, report *model.Report) {
	report.Process.Spawns[callName(line)]++
	report.Process.ParentSpawn[pid]++
}

func handleExec(line string, report *model.Report) {
	q := strings.IndexByte(line, '"')
	if q == -1 {
		return
	}
	path, _, ok := parseQuoted(line, q)
	if !ok {
		return
	}
	report.Process.Execs[path]++
}

func handlePoll(line, syscall string, report *model.Report) {
	stat := report.Poll[syscall]
	if stat == nil {
		stat = &model.PollStat{Syscall: syscall}
		report.Poll[syscall] = stat
	}
	stat.Count++
	ret, ok := parseReturnInt64(line)
	if ok {
		switch {
		case ret > 0:
			stat.Ready++
		case ret == 0:
			stat.Timeout++
		case ret < 0:
			stat.Errors++
		}
	}
	if d, ok := parseElapsed(line); ok {
		stat.TimeNS += d.Nanoseconds()
	}
}

func handleIPCSetup(line, syscall string, fdMap map[int]fdInfo, report *model.Report) {
	switch syscall {
	case "pipe", "pipe2":
		if f1, f2, ok := parseFDPair(line); ok && !isErrReturn(line) {
			fdMap[f1] = fdInfo{Kind: "pipe", Endpoint: "pipe"}
			fdMap[f2] = fdInfo{Kind: "pipe", Endpoint: "pipe"}
			addIPCEvent(report, "pipe", "pipe")
		}
	case "socketpair":
		if f1, f2, ok := parseFDPair(line); ok && !isErrReturn(line) {
			endpoint := "socketpair"
			if strings.Contains(line, "AF_UNIX") {
				endpoint = "unix-socketpair"
			}
			fdMap[f1] = fdInfo{Kind: "socketpair", Endpoint: endpoint}
			fdMap[f2] = fdInfo{Kind: "socketpair", Endpoint: endpoint}
			addIPCEvent(report, "socketpair", endpoint)
		}
	case "eventfd", "eventfd2":
		if fd, ok := parseReturnInt(line); ok && fd >= 0 {
			fdMap[fd] = fdInfo{Kind: "eventfd", Endpoint: "eventfd"}
			addIPCEvent(report, "eventfd", "eventfd")
		}
	case "signalfd", "signalfd4":
		if fd, ok := parseReturnInt(line); ok && fd >= 0 {
			fdMap[fd] = fdInfo{Kind: "signalfd", Endpoint: "signalfd"}
			addIPCEvent(report, "signalfd", "signalfd")
		}
	}
}

func handleMetadata(line, syscall string, fdMap map[int]fdInfo, report *model.Report) {
	group := "unknown"
	if q := strings.IndexByte(line, '"'); q >= 0 {
		if path, _, ok := parseQuoted(line, q); ok && path != "" {
			group = GroupPath(path)
		}
	} else if fd, ok := parseFirstIntArg(line); ok {
		if info, exists := fdMap[fd]; exists && info.Path != "" {
			group = GroupPath(info.Path)
		}
	}

	key := syscall + "|" + group
	stat := report.Metadata[key]
	if stat == nil {
		stat = &model.MetadataStat{Syscall: syscall, Group: group}
		report.Metadata[key] = stat
	}
	stat.Count++
	if isErrReturn(line) {
		stat.Fail++
	}
}

func addError(report *model.Report, syscall, errno, target string) {
	key := syscall + "|" + errno + "|" + target
	stat := report.Errors[key]
	if stat == nil {
		stat = &model.ErrorStat{Syscall: syscall, Errno: errno, Target: target}
		report.Errors[key] = stat
	}
	stat.Count++
}

func addMemory(report *model.Report, op string, count, bytes int64) {
	stat := report.Memory[op]
	if stat == nil {
		stat = &model.MemoryStat{Op: op}
		report.Memory[op] = stat
	}
	stat.Count += count
	stat.Bytes += bytes
}

func addNetworkIO(report *model.Report, info fdInfo, n int64, send bool) {
	peer := info.Peer
	if peer == "" {
		peer = "unknown"
	}
	proto := info.Proto
	if proto == "" {
		proto = "socket"
	}
	stat := ensureNetwork(report, proto, peer)
	if send {
		stat.SendCalls++
		stat.SendBytes += n
	} else {
		stat.RecvCalls++
		stat.RecvBytes += n
	}
}

func ensureNetwork(report *model.Report, proto, peer string) *model.NetworkStat {
	key := proto + "|" + peer
	stat := report.Network[key]
	if stat == nil {
		stat = &model.NetworkStat{Proto: proto, Peer: peer}
		report.Network[key] = stat
	}
	return stat
}

func addIPCEvent(report *model.Report, kind, endpoint string) {
	key := kind + "|" + endpoint
	stat := report.IPC[key]
	if stat == nil {
		stat = &model.IPCStat{Kind: kind, Endpoint: endpoint}
		report.IPC[key] = stat
	}
	stat.Events++
}

func addIPCIO(report *model.Report, info fdInfo, n int64, write bool) {
	endpoint := info.Endpoint
	if endpoint == "" {
		endpoint = "unknown"
	}
	key := info.Kind + "|" + endpoint
	stat := report.IPC[key]
	if stat == nil {
		stat = &model.IPCStat{Kind: info.Kind, Endpoint: endpoint}
		report.IPC[key] = stat
	}
	if write {
		stat.WriteBytes += n
	} else {
		stat.ReadBytes += n
	}
}

func extractTarget(line, syscall string) string {
	if syscall == "connect" || syscall == "accept" || syscall == "accept4" || syscall == "sendto" || syscall == "recvfrom" {
		if peer := parseSockAddr(line); peer != "" {
			return peer
		}
	}
	if q := strings.IndexByte(line, '"'); q >= 0 {
		if value, _, ok := parseQuoted(line, q); ok && value != "" {
			return value
		}
	}
	if syscall == "futex" {
		args := parseArgs(line)
		if len(args) >= 2 {
			return strings.TrimSpace(args[1])
		}
	}
	return "-"
}

func parseFDAndReturnBytes(line string) (int, int64, bool) {
	fd, ok := parseFirstIntArg(line)
	if !ok {
		return 0, 0, false
	}
	n, ok := parseReturnInt64(line)
	if !ok {
		return 0, 0, false
	}
	return fd, n, true
}

func parseOpenLine(line string) (int, string, bool) {
	q := strings.IndexByte(line, '"')
	if q == -1 {
		return 0, "", false
	}
	path, _, ok := parseQuoted(line, q)
	if !ok || path == "" {
		return 0, "", false
	}
	fd, ok := parseReturnInt(line)
	if !ok {
		return 0, "", false
	}
	return fd, path, true
}

func parseFirstIntArg(line string) (int, bool) {
	args := parseArgs(line)
	if len(args) == 0 {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(args[0]))
	if err != nil {
		return 0, false
	}
	return v, true
}

func parseArgs(line string) []string {
	l := strings.IndexByte(line, '(')
	if l == -1 {
		return nil
	}
	r := strings.LastIndex(line, ")")
	if r == -1 || r <= l {
		return nil
	}
	return strings.Split(line[l+1:r], ",")
}

func parseQuoted(s string, start int) (string, int, bool) {
	if start < 0 || start >= len(s) || s[start] != '"' {
		return "", 0, false
	}
	b := strings.Builder{}
	for i := start + 1; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			if i+1 < len(s) {
				i++
				b.WriteByte(s[i])
				continue
			}
			break
		}
		if c == '"' {
			return b.String(), i + 1, true
		}
		b.WriteByte(c)
	}
	return "", 0, false
}

func parseReturnInt(line string) (int, bool) {
	v, ok := parseReturnInt64(line)
	if !ok {
		return 0, false
	}
	if v < -2147483648 || v > 2147483647 {
		return 0, false
	}
	return int(v), true
}

func parseReturnInt64(line string) (int64, bool) {
	eq := strings.LastIndex(line, "=")
	if eq == -1 {
		return 0, false
	}
	rhs := strings.TrimSpace(line[eq+1:])
	if rhs == "" {
		return 0, false
	}
	first := firstToken(rhs)
	v, err := strconv.ParseInt(first, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func parseErrno(line string) (string, bool) {
	m := reErrno.FindStringSubmatch(line)
	if len(m) == 2 {
		return m[1], true
	}
	return "", false
}

func parseSockAddr(line string) string {
	if strings.Contains(line, "AF_UNIX") {
		if m := reSun.FindStringSubmatch(line); len(m) == 2 {
			return "unix:" + m[1]
		}
		return "unix"
	}
	if strings.Contains(line, "AF_INET6") {
		addr := ""
		port := ""
		if m := reAddr6.FindStringSubmatch(line); len(m) == 2 {
			addr = m[1]
		}
		if m := rePort6.FindStringSubmatch(line); len(m) == 2 {
			port = m[1]
		}
		if addr != "" && port != "" {
			return "[" + addr + "]:" + port
		}
		if addr != "" {
			return addr
		}
		return "inet6"
	}
	if strings.Contains(line, "AF_INET") {
		addr := ""
		port := ""
		if m := reAddr4.FindStringSubmatch(line); len(m) == 2 {
			addr = m[1]
		}
		if m := rePort4.FindStringSubmatch(line); len(m) == 2 {
			port = m[1]
		}
		if addr != "" && port != "" {
			return addr + ":" + port
		}
		if addr != "" {
			return addr
		}
		return "inet"
	}
	return ""
}

func parseElapsed(line string) (time.Duration, bool) {
	m := reTime.FindStringSubmatch(line)
	if len(m) != 2 {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	return time.Duration(v * float64(time.Second)), true
}

func parseFDPair(line string) (int, int, bool) {
	m := reFDPair.FindStringSubmatch(line)
	if len(m) != 3 {
		return 0, 0, false
	}
	a, err1 := strconv.Atoi(m[1])
	b, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return a, b, true
}

func isMetadataSyscall(name string) bool {
	switch name {
	case "stat", "lstat", "fstat", "newfstatat", "statx", "access", "faccessat", "getdents", "getdents64", "readlink", "readlinkat":
		return true
	default:
		return false
	}
}

func isErrReturn(line string) bool {
	v, ok := parseReturnInt64(line)
	return ok && v < 0
}

func firstToken(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			return s[:i]
		}
	}
	return s
}

func callName(line string) string {
	i := strings.IndexByte(line, '(')
	if i <= 0 {
		return ""
	}
	j := i - 1
	for j >= 0 && line[j] == ' ' {
		j--
	}
	if j < 0 {
		return ""
	}
	start := j
	for start >= 0 {
		c := line[start]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			start--
			continue
		}
		break
	}
	return line[start+1 : j+1]
}

func parsePIDFromName(name string) int {
	m := rePIDTail.FindStringSubmatch(name)
	if len(m) != 2 {
		return 0
	}
	v, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}
	return v
}

func GroupPath(path string) string {
	clean := filepath.Clean(path)

	if i := strings.Index(clean, "/node_modules/"); i >= 0 {
		base := clean[:i+len("/node_modules/")]
		rest := clean[i+len("/node_modules/"):]
		parts := strings.Split(rest, "/")
		if len(parts) > 0 {
			if strings.HasPrefix(parts[0], "@") && len(parts) > 1 {
				return base + parts[0] + "/" + parts[1]
			}
			return base + parts[0]
		}
	}

	dir := filepath.Dir(clean)
	base := filepath.Base(dir)
	switch base {
	case "dist", "build", "out", "target":
		parent := filepath.Dir(dir)
		if parent != "." && parent != "/" {
			return parent
		}
	}
	return dir
}
