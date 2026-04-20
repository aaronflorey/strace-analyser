package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRootCommandsUseTracePathArgName(t *testing.T) {
	resetFlagsForTest()

	root := newRootCommand()

	all, _, err := root.Find([]string{"all"})
	if err != nil {
		t.Fatalf("find all command: %v", err)
	}
	if !strings.Contains(all.Use, "<trace-path>") {
		t.Fatalf("all command use = %q, want to include <trace-path>", all.Use)
	}

	for _, name := range []string{"files", "network", "locks", "errors", "process", "metadata", "poll", "memory", "ipc"} {
		sub, _, err := root.Find([]string{name})
		if err != nil {
			t.Fatalf("find %q command: %v", name, err)
		}
		if !strings.Contains(sub.Use, "<trace-path>") {
			t.Fatalf("%s command use = %q, want to include <trace-path>", name, sub.Use)
		}
	}

	runCmd, _, err := root.Find([]string{"run"})
	if err != nil {
		t.Fatalf("find run command: %v", err)
	}
	if !strings.Contains(runCmd.Use, "<command>") {
		t.Fatalf("run command use = %q, want to include <command>", runCmd.Use)
	}
}

func TestAllCommandRequiresExactlyOneArg(t *testing.T) {
	resetFlagsForTest()

	root := newRootCommand()
	root.SetArgs([]string{"all"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected missing arg error")
	}
	if !strings.Contains(err.Error(), "accepts 1 arg") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFilesCommandAcceptsSingleTraceFilePath(t *testing.T) {
	resetFlagsForTest()

	dir := t.TempDir()
	tracePath := filepath.Join(dir, "trace.out")
	if err := os.WriteFile(tracePath, []byte(`openat(AT_FDCWD, "/tmp/cmd-test.log", O_RDONLY) = 3
read(3, "abc", 3) = 3
close(3) = 0
`), 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	out := captureStdout(t, func() {
		root := newRootCommand()
		root.SetArgs([]string{"files", tracePath, "--json"})
		if err := root.Execute(); err != nil {
			t.Fatalf("files command failed: %v", err)
		}
	})

	var payload struct {
		ParsedFiles int `json:"parsed_files"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("decode json output: %v\noutput=%q", err, out)
	}
	if payload.ParsedFiles != 1 {
		t.Fatalf("parsed_files = %d, want 1", payload.ParsedFiles)
	}
}

func TestRunCommandPassesArbitraryArgs(t *testing.T) {
	resetFlagsForTest()

	var got []string
	runTrace = func(tracePath string, command []string) error {
		got = append([]string(nil), command...)
		return os.WriteFile(tracePath, []byte("openat(AT_FDCWD, \"/tmp/run-test.log\", O_RDONLY) = 3\nclose(3) = 0\n"), 0o644)
	}

	root := newRootCommand()
	root.SetArgs([]string{"run", "echo", "--example-flag", "-n", "hello"})
	if err := root.Execute(); err != nil {
		t.Fatalf("run command failed: %v", err)
	}

	want := []string{"echo", "--example-flag", "-n", "hello"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("run command args = %#v, want %#v", got, want)
	}
}

func TestRunCommandBubblesTraceErrors(t *testing.T) {
	resetFlagsForTest()

	runTrace = func(_ string, _ []string) error {
		return errors.New("boom")
	}

	root := newRootCommand()
	root.SetArgs([]string{"run", "echo", "hello"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error = %v, want to contain boom", err)
	}
}

func TestRunCommandStripsLeadingDoubleDash(t *testing.T) {
	resetFlagsForTest()

	var got []string
	runTrace = func(tracePath string, command []string) error {
		got = append([]string(nil), command...)
		return os.WriteFile(tracePath, []byte("openat(AT_FDCWD, \"/tmp/run-test.log\", O_RDONLY) = 3\nclose(3) = 0\n"), 0o644)
	}

	root := newRootCommand()
	root.SetArgs([]string{"run", "--", "echo", "hello"})
	if err := root.Execute(); err != nil {
		t.Fatalf("run command failed: %v", err)
	}

	want := []string{"echo", "hello"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("run command args = %#v, want %#v", got, want)
	}
}

func TestRunCommandRequiresCommandAfterDoubleDash(t *testing.T) {
	resetFlagsForTest()

	root := newRootCommand()
	root.SetArgs([]string{"run", "--"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "requires a command") {
		t.Fatalf("error = %v, want to mention missing command", err)
	}
}

func resetFlagsForTest() {
	top = 30
	minBytes = 1
	jsonOut = false
	runTrace = runTraceCommand
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = w

	defer func() {
		os.Stdout = orig
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close write pipe: %v", err)
	}

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close read pipe: %v", err)
	}
	return string(out)
}
