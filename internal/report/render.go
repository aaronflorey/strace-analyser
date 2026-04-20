package report

import (
	"fmt"
	"sort"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/aaronflorey/strace-analyser/internal/model"
	"github.com/aaronflorey/strace-analyser/internal/parser"
)

func PrintFiles(rep *model.Report, top int, minBytes int64) {
	totalOpens := int64(0)
	totalBytes := int64(0)
	groups := map[string]struct {
		files map[string]struct{}
		opens int64
		bytes int64
	}{}

	rows := make([]model.FileStat, 0, len(rep.Files))
	for _, s := range rep.Files {
		rows = append(rows, *s)
		totalOpens += s.Opens
		totalBytes += s.Bytes
		group := parser.GroupPath(s.Path)
		g := groups[group]
		if g.files == nil {
			g.files = map[string]struct{}{}
		}
		g.files[s.Path] = struct{}{}
		g.opens += s.Opens
		g.bytes += s.Bytes
		groups[group] = g
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Bytes == rows[j].Bytes {
			return rows[i].Opens > rows[j].Opens
		}
		return rows[i].Bytes > rows[j].Bytes
	})

	type groupRow struct {
		group string
		files int
		opens int64
		bytes int64
	}
	groupRows := make([]groupRow, 0, len(groups))
	for group, g := range groups {
		groupRows = append(groupRows, groupRow{group: group, files: len(g.files), opens: g.opens, bytes: g.bytes})
	}
	sort.Slice(groupRows, func(i, j int) bool {
		if groupRows[i].bytes == groupRows[j].bytes {
			return groupRows[i].opens > groupRows[j].opens
		}
		return groupRows[i].bytes > groupRows[j].bytes
	})

	fmt.Printf("\n[files] opens=%d bytes=%s\n", totalOpens, humanBytes(totalBytes))

	tg := table.NewWriter()
	tg.AppendHeader(table.Row{"files", "opens", "bytes", "group"})
	count := 0
	for _, g := range groupRows {
		if g.bytes < minBytes {
			continue
		}
		tg.AppendRow(table.Row{g.files, g.opens, humanBytes(g.bytes), g.group})
		count++
		if count >= top {
			break
		}
	}
	fmt.Println(tg.Render())

	tf := table.NewWriter()
	tf.AppendHeader(table.Row{"opens", "bytes", "avg", "file"})
	count = 0
	for _, s := range rows {
		if s.Bytes < minBytes {
			continue
		}
		avg := int64(0)
		if s.Opens > 0 {
			avg = s.Bytes / s.Opens
		}
		tf.AppendRow(table.Row{s.Opens, humanBytes(s.Bytes), humanBytes(avg), s.Path})
		count++
		if count >= top {
			break
		}
	}
	fmt.Println(tf.Render())
}

func PrintNetwork(rep *model.Report, top int, minBytes int64) {
	rows := make([]model.NetworkStat, 0, len(rep.Network))
	totalSend := int64(0)
	totalRecv := int64(0)
	totalConn := int64(0)
	for _, s := range rep.Network {
		rows = append(rows, *s)
		totalSend += s.SendBytes
		totalRecv += s.RecvBytes
		totalConn += s.Connects + s.Accepts
	}
	sort.Slice(rows, func(i, j int) bool {
		bi := rows[i].SendBytes + rows[i].RecvBytes
		bj := rows[j].SendBytes + rows[j].RecvBytes
		if bi == bj {
			ei := rows[i].Connects + rows[i].Accepts + rows[i].SendCalls + rows[i].RecvCalls
			ej := rows[j].Connects + rows[j].Accepts + rows[j].SendCalls + rows[j].RecvCalls
			return ei > ej
		}
		return bi > bj
	})

	fmt.Printf("\n[network] sent=%s recv=%s conn=%d\n", humanBytes(totalSend), humanBytes(totalRecv), totalConn)
	t := table.NewWriter()
	t.AppendHeader(table.Row{"proto", "connect", "accept", "sent", "recv", "errors", "peer"})
	count := 0
	for _, s := range rows {
		if (s.SendBytes+s.RecvBytes) < minBytes && (s.Connects+s.Accepts) == 0 {
			continue
		}
		t.AppendRow(table.Row{s.Proto, s.Connects, s.Accepts, humanBytes(s.SendBytes), humanBytes(s.RecvBytes), s.Errors, s.Peer})
		count++
		if count >= top {
			break
		}
	}
	fmt.Println(t.Render())
}

func PrintLocks(rep *model.Report, top int) {
	rows := make([]model.LockStat, 0, len(rep.Locks))
	total := int64(0)
	totalNs := int64(0)
	for _, s := range rep.Locks {
		rows = append(rows, *s)
		total += s.Count
		totalNs += s.TimeNS
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].TimeNS == rows[j].TimeNS {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].TimeNS > rows[j].TimeNS
	})

	fmt.Printf("\n[locks] futex_calls=%d", total)
	if totalNs > 0 {
		fmt.Printf(" time=%s\n", humanDuration(totalNs))
	} else {
		fmt.Printf(" time=n/a (use strace -T)\n")
	}
	t := table.NewWriter()
	t.AppendHeader(table.Row{"op", "count", "errors", "timeouts", "time"})
	count := 0
	for _, s := range rows {
		timeText := "n/a"
		if s.TimeNS > 0 {
			timeText = humanDuration(s.TimeNS)
		}
		t.AppendRow(table.Row{s.Op, s.Count, s.Errors, s.Timeouts, timeText})
		count++
		if count >= top {
			break
		}
	}
	fmt.Println(t.Render())
}

func PrintErrors(rep *model.Report, top int) {
	rows := make([]model.ErrorStat, 0, len(rep.Errors))
	for _, s := range rep.Errors {
		rows = append(rows, *s)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count == rows[j].Count {
			if rows[i].Errno == rows[j].Errno {
				return rows[i].Syscall < rows[j].Syscall
			}
			return rows[i].Errno < rows[j].Errno
		}
		return rows[i].Count > rows[j].Count
	})

	fmt.Printf("\n[errors] unique=%d\n", len(rows))
	t := table.NewWriter()
	t.AppendHeader(table.Row{"count", "syscall", "errno", "target"})
	count := 0
	for _, s := range rows {
		t.AppendRow(table.Row{s.Count, s.Syscall, s.Errno, s.Target})
		count++
		if count >= top {
			break
		}
	}
	fmt.Println(t.Render())
}

func PrintProcess(rep *model.Report, top int) {
	totalExec := int64(0)
	for _, n := range rep.Process.Execs {
		totalExec += n
	}
	fmt.Printf("\n[process] exec=%d wait=%d exit=%d\n", totalExec, rep.Process.WaitCalls, rep.Process.ExitCalls)

	tExec := table.NewWriter()
	tExec.AppendHeader(table.Row{"count", "exec target"})
	type execRow struct {
		path  string
		count int64
	}
	execs := make([]execRow, 0, len(rep.Process.Execs))
	for path, count := range rep.Process.Execs {
		execs = append(execs, execRow{path: path, count: count})
	}
	sort.Slice(execs, func(i, j int) bool { return execs[i].count > execs[j].count })
	for i, row := range execs {
		if i >= top {
			break
		}
		tExec.AppendRow(table.Row{row.count, row.path})
	}
	fmt.Println(tExec.Render())

	tSpawn := table.NewWriter()
	tSpawn.AppendHeader(table.Row{"count", "spawn syscall"})
	type spawnRow struct {
		sys   string
		count int64
	}
	spawns := make([]spawnRow, 0, len(rep.Process.Spawns))
	for sys, count := range rep.Process.Spawns {
		spawns = append(spawns, spawnRow{sys: sys, count: count})
	}
	sort.Slice(spawns, func(i, j int) bool { return spawns[i].count > spawns[j].count })
	for _, row := range spawns {
		tSpawn.AppendRow(table.Row{row.count, row.sys})
	}
	fmt.Println(tSpawn.Render())
}

func PrintMetadata(rep *model.Report, top int) {
	rows := make([]model.MetadataStat, 0, len(rep.Metadata))
	for _, s := range rep.Metadata {
		rows = append(rows, *s)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count == rows[j].Count {
			return rows[i].Fail > rows[j].Fail
		}
		return rows[i].Count > rows[j].Count
	})

	fmt.Printf("\n[metadata] unique=%d\n", len(rows))
	t := table.NewWriter()
	t.AppendHeader(table.Row{"count", "fail", "syscall", "group"})
	for i, row := range rows {
		if i >= top {
			break
		}
		t.AppendRow(table.Row{row.Count, row.Fail, row.Syscall, row.Group})
	}
	fmt.Println(t.Render())
}

func PrintPoll(rep *model.Report, top int) {
	rows := make([]model.PollStat, 0, len(rep.Poll))
	for _, s := range rep.Poll {
		rows = append(rows, *s)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].TimeNS == rows[j].TimeNS {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].TimeNS > rows[j].TimeNS
	})

	fmt.Printf("\n[poll] syscalls=%d\n", len(rows))
	t := table.NewWriter()
	t.AppendHeader(table.Row{"syscall", "count", "ready", "timeout", "errors", "time"})
	for i, row := range rows {
		if i >= top {
			break
		}
		timeText := "n/a"
		if row.TimeNS > 0 {
			timeText = humanDuration(row.TimeNS)
		}
		t.AppendRow(table.Row{row.Syscall, row.Count, row.Ready, row.Timeout, row.Errors, timeText})
	}
	fmt.Println(t.Render())
}

func PrintMemory(rep *model.Report, top int) {
	rows := make([]model.MemoryStat, 0, len(rep.Memory))
	for _, s := range rep.Memory {
		rows = append(rows, *s)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Bytes == rows[j].Bytes {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Bytes > rows[j].Bytes
	})

	fmt.Printf("\n[memory] ops=%d\n", len(rows))
	t := table.NewWriter()
	t.AppendHeader(table.Row{"op", "count", "bytes"})
	for i, row := range rows {
		if i >= top {
			break
		}
		bytes := "-"
		if row.Bytes > 0 {
			bytes = humanBytes(row.Bytes)
		}
		t.AppendRow(table.Row{row.Op, row.Count, bytes})
	}
	fmt.Println(t.Render())
}

func PrintIPC(rep *model.Report, top int) {
	rows := make([]model.IPCStat, 0, len(rep.IPC))
	for _, s := range rep.IPC {
		rows = append(rows, *s)
	}
	sort.Slice(rows, func(i, j int) bool {
		bi := rows[i].ReadBytes + rows[i].WriteBytes
		bj := rows[j].ReadBytes + rows[j].WriteBytes
		if bi == bj {
			return rows[i].Events > rows[j].Events
		}
		return bi > bj
	})

	fmt.Printf("\n[ipc] endpoints=%d\n", len(rows))
	t := table.NewWriter()
	t.AppendHeader(table.Row{"kind", "endpoint", "events", "read", "write"})
	for i, row := range rows {
		if i >= top {
			break
		}
		t.AppendRow(table.Row{row.Kind, row.Endpoint, row.Events, humanBytes(row.ReadBytes), humanBytes(row.WriteBytes)})
	}
	fmt.Println(t.Render())
}

func humanBytes(n int64) string {
	return humanize.IBytes(uint64(max(n, 0)))
}

func humanDuration(ns int64) string {
	d := time.Duration(ns)
	if d >= time.Second {
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	if d >= time.Millisecond {
		return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
	}
	if d >= time.Microsecond {
		return fmt.Sprintf("%.1fus", float64(d)/float64(time.Microsecond))
	}
	return d.String()
}

func max(v, floor int64) int64 {
	if v < floor {
		return floor
	}
	return v
}
