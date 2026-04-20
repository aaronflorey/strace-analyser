package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzeDirParsesAndFiltersFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	writeTestFile(t, filepath.Join(dir, "cmd.strace.123"), `openat(AT_FDCWD, "/tmp/app.log", O_RDONLY) = 3
read(3, "abc", 3) = 3
close(3) = 0
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, child_tidptr=0x0) = 456
`)

	writeTestFile(t, filepath.Join(dir, "worker.trace"), `clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, child_tidptr=0x0) = 789
`)

	writeTestFile(t, filepath.Join(dir, ".hidden.strace.999"), `clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, child_tidptr=0x0) = 111
`)

	writeTestFile(t, filepath.Join(dir, "notes.txt"), `openat(AT_FDCWD, "/tmp/ignored", O_RDONLY) = 3
`)

	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	writeTestFile(t, filepath.Join(dir, "nested", "inside.strace.444"), `clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, child_tidptr=0x0) = 222
`)

	rep, err := AnalyzeDir(dir)
	if err != nil {
		t.Fatalf("AnalyzeDir returned error: %v", err)
	}

	if rep.ParsedFiles != 2 {
		t.Fatalf("parsed files = %d, want 2", rep.ParsedFiles)
	}

	if rep.Process.Spawns["clone"] != 2 {
		t.Fatalf("clone spawns = %d, want 2", rep.Process.Spawns["clone"])
	}

	if rep.Process.ParentSpawn[123] != 1 {
		t.Fatalf("parent spawn count for pid 123 = %d, want 1", rep.Process.ParentSpawn[123])
	}

	if rep.Process.ParentSpawn[0] != 1 {
		t.Fatalf("parent spawn count for pid 0 = %d, want 1", rep.Process.ParentSpawn[0])
	}

	stat := rep.Files["/tmp/app.log"]
	if stat == nil {
		t.Fatal("missing file stats for /tmp/app.log")
	}
	if stat.Opens != 1 {
		t.Fatalf("opens = %d, want 1", stat.Opens)
	}
	if stat.Bytes != 3 {
		t.Fatalf("bytes = %d, want 3", stat.Bytes)
	}
}

func TestGroupPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "groups scoped node_modules package",
			path: "/repo/node_modules/@scope/pkg/dist/index.js",
			want: "/repo/node_modules/@scope/pkg",
		},
		{
			name: "groups plain node_modules package",
			path: "/repo/node_modules/lodash/lodash.js",
			want: "/repo/node_modules/lodash",
		},
		{
			name: "collapses dist directory to parent",
			path: "/repo/app/dist/main.js",
			want: "/repo/app",
		},
		{
			name: "keeps regular directory",
			path: "/repo/app/src/main.go",
			want: "/repo/app/src",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := GroupPath(tc.path); got != tc.want {
				t.Fatalf("GroupPath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestAnalyzeDirAcceptsSingleTraceFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tracePath := filepath.Join(dir, "trace.out")
	writeTestFile(t, tracePath, `openat(AT_FDCWD, "/tmp/single.log", O_RDONLY) = 3
read(3, "abcd", 4) = 4
close(3) = 0
`)

	rep, err := AnalyzeDir(tracePath)
	if err != nil {
		t.Fatalf("AnalyzeDir returned error for single file: %v", err)
	}

	if rep.ParsedFiles != 1 {
		t.Fatalf("parsed files = %d, want 1", rep.ParsedFiles)
	}

	stat := rep.Files["/tmp/single.log"]
	if stat == nil {
		t.Fatal("missing file stats for /tmp/single.log")
	}
	if stat.Opens != 1 {
		t.Fatalf("opens = %d, want 1", stat.Opens)
	}
	if stat.Bytes != 4 {
		t.Fatalf("bytes = %d, want 4", stat.Bytes)
	}
}

func TestAnalyzeDirRejectsNonTraceSingleFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	notTrace := filepath.Join(dir, "output.log")
	writeTestFile(t, notTrace, `openat(AT_FDCWD, "/tmp/ignored", O_RDONLY) = 3`)

	_, err := AnalyzeDir(notTrace)
	if err == nil {
		t.Fatal("expected error for non-trace single file input")
	}
	if !strings.Contains(err.Error(), "does not look like a strace output file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAnalyzeDirMatchesTraceOutAndCaseInsensitiveNames(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "TRACE.OUT"), `clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, child_tidptr=0x0) = 401`)
	writeTestFile(t, filepath.Join(dir, "worker.STRACE.LOG"), `clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, child_tidptr=0x0) = 402`)
	writeTestFile(t, filepath.Join(dir, "notes.txt"), `clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, child_tidptr=0x0) = 403`)

	rep, err := AnalyzeDir(dir)
	if err != nil {
		t.Fatalf("AnalyzeDir returned error: %v", err)
	}

	if rep.ParsedFiles != 2 {
		t.Fatalf("parsed files = %d, want 2", rep.ParsedFiles)
	}

	if rep.Process.Spawns["clone"] != 2 {
		t.Fatalf("clone spawns = %d, want 2", rep.Process.Spawns["clone"])
	}
}

func TestAnalyzeDirNoTraceFilesErrorMentionsPatterns(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "notes.txt"), "hello")

	_, err := AnalyzeDir(dir)
	if err == nil {
		t.Fatal("expected no trace files error")
	}
	if !strings.Contains(err.Error(), "expected names like strace.*, *.trace, or trace.*") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIsTraceFileName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		file string
		want bool
	}{
		{name: "strace substring", file: "cmd.strace.123", want: true},
		{name: "trace suffix", file: "worker.trace", want: true},
		{name: "trace prefix", file: "trace.out", want: true},
		{name: "case insensitive", file: "TRACE.OUT", want: true},
		{name: "dotfile ignored", file: ".trace.out", want: false},
		{name: "plain text", file: "notes.txt", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTraceFileName(tc.file); got != tc.want {
				t.Fatalf("isTraceFileName(%q) = %v, want %v", tc.file, got, tc.want)
			}
		})
	}
}

func TestParseSockAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "ipv4 with port",
			line: `connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = 0`,
			want: "1.2.3.4:443",
		},
		{
			name: "ipv6 with port",
			line: `connect(3, {sa_family=AF_INET6, sin6_port=htons(53), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr)}, 28) = 0`,
			want: "[2001:db8::1]:53",
		},
		{
			name: "unix with path",
			line: `connect(3, {sa_family=AF_UNIX, sun_path="/tmp/sock"}, 16) = 0`,
			want: "unix:/tmp/sock",
		},
		{
			name: "unix no path",
			line: `connect(3, {sa_family=AF_UNIX}, 16) = 0`,
			want: "unix",
		},
		{
			name: "no sockaddr",
			line: `read(3, "a", 1) = 1`,
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseSockAddr(tc.line); got != tc.want {
				t.Fatalf("parseSockAddr(%q) = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}

func TestExtractTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		syscall string
		line    string
		want    string
	}{
		{
			name:    "network peer for connect",
			syscall: "connect",
			line:    `connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("10.0.0.9")}, 16) = -1 ECONNREFUSED (Connection refused)`,
			want:    "10.0.0.9:80",
		},
		{
			name:    "quoted path",
			syscall: "openat",
			line:    `openat(AT_FDCWD, "/tmp/app.log", O_RDONLY) = -1 ENOENT (No such file or directory)`,
			want:    "/tmp/app.log",
		},
		{
			name:    "futex operation",
			syscall: "futex",
			line:    `futex(0x7f00, FUTEX_WAIT_PRIVATE, 2, NULL) = -1 EAGAIN (Resource temporarily unavailable)`,
			want:    "FUTEX_WAIT_PRIVATE",
		},
		{
			name:    "fallback dash",
			syscall: "close",
			line:    `close(3) = -1 EBADF (Bad file descriptor)`,
			want:    "-",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractTarget(tc.line, tc.syscall); got != tc.want {
				t.Fatalf("extractTarget(%q, %q) = %q, want %q", tc.line, tc.syscall, got, tc.want)
			}
		})
	}
}

func TestAnalyzeDirParsesNetworkIPCPollMemoryAndErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "trace.out"), `
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = 0
sendto(3, "GET", 3, 0, NULL, 0) = 3
recvfrom(3, "OK", 2, 0, NULL, NULL) = 2
pipe2([4, 5], O_CLOEXEC) = 0
write(5, "x", 1) = 1
read(4, "x", 1) = 1
eventfd2(0, EFD_CLOEXEC) = 6
write(6, "\001\000\000\000\000\000\000\000", 8) = 8
poll([{fd=3, events=POLLIN}], 1, 1000) = 0 <0.001000>
mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, -1, 0) = 0x7f000000
munmap(0x7f000000, 4096) = 0
access("/missing", R_OK) = -1 ENOENT (No such file or directory)
`)

	rep, err := AnalyzeDir(dir)
	if err != nil {
		t.Fatalf("AnalyzeDir returned error: %v", err)
	}

	net := rep.Network["tcp|1.2.3.4:443"]
	if net == nil {
		t.Fatal("missing network stat for tcp peer 1.2.3.4:443")
	}
	if net.Connects != 1 || net.SendBytes != 3 || net.RecvBytes != 2 {
		t.Fatalf("unexpected network stat: %+v", *net)
	}

	pipe := rep.IPC["pipe|pipe"]
	if pipe == nil {
		t.Fatal("missing ipc stat for pipe")
	}
	if pipe.Events != 1 || pipe.ReadBytes != 1 || pipe.WriteBytes != 1 {
		t.Fatalf("unexpected pipe stat: %+v", *pipe)
	}

	efd := rep.IPC["eventfd|eventfd"]
	if efd == nil {
		t.Fatal("missing ipc stat for eventfd")
	}
	if efd.Events != 1 || efd.WriteBytes != 8 {
		t.Fatalf("unexpected eventfd stat: %+v", *efd)
	}

	pollStat := rep.Poll["poll"]
	if pollStat == nil {
		t.Fatal("missing poll stat")
	}
	if pollStat.Count != 1 || pollStat.Timeout != 1 || pollStat.TimeNS == 0 {
		t.Fatalf("unexpected poll stat: %+v", *pollStat)
	}

	if rep.Memory["mmap_anon"] == nil || rep.Memory["mmap_anon"].Bytes != 4096 {
		t.Fatalf("unexpected mmap_anon stat: %+v", rep.Memory["mmap_anon"])
	}
	if rep.Memory["munmap"] == nil || rep.Memory["munmap"].Bytes != 4096 {
		t.Fatalf("unexpected munmap stat: %+v", rep.Memory["munmap"])
	}

	errStat := rep.Errors["access|ENOENT|/missing"]
	if errStat == nil || errStat.Count != 1 {
		t.Fatalf("unexpected access error stat: %+v", errStat)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
