package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/aaronflorey/strace-analyser/internal/model"
	"github.com/aaronflorey/strace-analyser/internal/parser"
	"github.com/aaronflorey/strace-analyser/internal/report"
)

var (
	top      int
	minBytes int64
	jsonOut  bool
	runTrace = runTraceCommand
)

func Execute() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "strace-analyser",
		Short: "Analyze a directory of strace outputs",
		Long:  "Parse strace files and summarize file, network, lock, error, process, metadata, poll, memory, and IPC activity.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	root.PersistentFlags().IntVarP(&top, "top", "n", 30, "number of rows per table")
	root.PersistentFlags().Int64Var(&minBytes, "min-bytes", 1, "minimum bytes threshold for byte-oriented tables")
	root.PersistentFlags().BoolVar(&jsonOut, "json", false, "print full parsed report as JSON")

	root.AddCommand(&cobra.Command{
		Use:   "all <trace-path>",
		Short: "Show all report sections",
		Args:  cobra.ExactArgs(1),
		RunE:  runAll,
	})
	root.AddCommand(&cobra.Command{
		Use:                "run <command> [args...]",
		Short:              "Run a command under strace and analyze it",
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: true,
		RunE:               runAndAnalyze,
	})
	root.AddCommand(newSectionCommand("files", "Show file and directory hot spots", report.PrintFiles))
	root.AddCommand(newSectionCommand("network", "Show network peer and byte activity", report.PrintNetwork))
	root.AddCommand(newSectionCommand("locks", "Show futex/lock contention signals", func(rep *model.Report, top int, _ int64) {
		report.PrintLocks(rep, top)
	}))
	root.AddCommand(newSectionCommand("errors", "Show syscall error hotspots", func(rep *model.Report, top int, _ int64) {
		report.PrintErrors(rep, top)
	}))
	root.AddCommand(newSectionCommand("process", "Show process spawn/exec summary", func(rep *model.Report, top int, _ int64) {
		report.PrintProcess(rep, top)
	}))
	root.AddCommand(newSectionCommand("metadata", "Show filesystem metadata churn", func(rep *model.Report, top int, _ int64) {
		report.PrintMetadata(rep, top)
	}))
	root.AddCommand(newSectionCommand("poll", "Show poll/epoll wait behavior", func(rep *model.Report, top int, _ int64) {
		report.PrintPoll(rep, top)
	}))
	root.AddCommand(newSectionCommand("memory", "Show mmap/munmap and memory ops", func(rep *model.Report, top int, _ int64) {
		report.PrintMemory(rep, top)
	}))
	root.AddCommand(newSectionCommand("ipc", "Show pipe/eventfd/signalfd activity", func(rep *model.Report, top int, _ int64) {
		report.PrintIPC(rep, top)
	}))

	return root
}

type sectionPrinter func(rep *model.Report, top int, minBytes int64)

func newSectionCommand(name, short string, print sectionPrinter) *cobra.Command {
	return &cobra.Command{
		Use:   name + " <trace-path>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rep, err := parser.AnalyzeDir(args[0])
			if err != nil {
				return err
			}
			if jsonOut {
				return writeJSON(rep)
			}
			fmt.Printf("Parsed %d strace files from %s\n", rep.ParsedFiles, args[0])
			print(rep, top, minBytes)
			return nil
		},
	}
}

func runAll(_ *cobra.Command, args []string) error {
	rep, err := parser.AnalyzeDir(args[0])
	if err != nil {
		return err
	}
	if jsonOut {
		return writeJSON(rep)
	}

	fmt.Printf("Parsed %d strace files from %s\n", rep.ParsedFiles, args[0])
	report.PrintFiles(rep, top, minBytes)
	report.PrintNetwork(rep, top, minBytes)
	report.PrintLocks(rep, top)
	report.PrintErrors(rep, top)
	report.PrintProcess(rep, top)
	report.PrintMetadata(rep, top)
	report.PrintPoll(rep, top)
	report.PrintMemory(rep, top)
	report.PrintIPC(rep, top)
	return nil
}

func runAndAnalyze(_ *cobra.Command, args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return fmt.Errorf("run requires a command to execute")
	}

	traceFile, err := os.CreateTemp("", "strace-analyser-*.trace")
	if err != nil {
		return fmt.Errorf("create temp trace file: %w", err)
	}
	tracePath := traceFile.Name()
	if err := traceFile.Close(); err != nil {
		return fmt.Errorf("close temp trace file: %w", err)
	}
	defer os.Remove(tracePath)

	if err := runTrace(tracePath, args); err != nil {
		return err
	}

	rep, err := parser.AnalyzeDir(tracePath)
	if err != nil {
		return err
	}
	if jsonOut {
		return writeJSON(rep)
	}

	fmt.Printf("Parsed %d strace files from %s\n", rep.ParsedFiles, tracePath)
	report.PrintFiles(rep, top, minBytes)
	report.PrintNetwork(rep, top, minBytes)
	report.PrintLocks(rep, top)
	report.PrintErrors(rep, top)
	report.PrintProcess(rep, top)
	report.PrintMetadata(rep, top)
	report.PrintPoll(rep, top)
	report.PrintMemory(rep, top)
	report.PrintIPC(rep, top)
	return nil
}

func runTraceCommand(tracePath string, command []string) error {
	straceArgs := []string{"-f", "-T", "-ttt", "-o", tracePath, "--"}
	straceArgs = append(straceArgs, command...)

	cmd := exec.Command("strace", straceArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run under strace: %w", err)
	}
	return nil
}

func writeJSON(rep *model.Report) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
