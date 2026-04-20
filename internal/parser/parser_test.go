package parser

import (
	"os"
	"path/filepath"
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

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
