# strace-analyser

[![License](https://img.shields.io/github/license/aaronflorey/strace-analyser?style=flat-square)](https://github.com/aaronflorey/strace-analyser/blob/main/LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/aaronflorey/strace-analyser/ci.yaml?style=flat-square&label=ci)](https://github.com/aaronflorey/strace-analyser/actions/workflows/ci.yaml)
[![Release](https://img.shields.io/github/v/release/aaronflorey/strace-analyser?style=flat-square&display_name=tag&sort=semver)](https://github.com/aaronflorey/strace-analyser/releases)

A modular CLI for summarizing `strace` output directories.

## Features

- File I/O hot spots with smart grouping (`node_modules/<package>` rollups)
- Network activity by peer/protocol (connect, accept, send/recv bytes)
- Futex lock contention overview
- Syscall error hot spots (`errno` + syscall + target)
- Process lifecycle summary (`exec`, spawn, wait, exit)
- Filesystem metadata churn (`statx`, `access`, `getdents`, etc.)
- Poll/event-loop behavior (`poll`, `ppoll`, `epoll_*`, `select`)
- Memory syscall summary (`mmap`, `munmap`, `mprotect`, `madvise`, `brk`)
- IPC setup and I/O (`pipe`, `socketpair`, `eventfd`, `signalfd`)

## Installation

Install with [`bin`](https://github.com/aaronflorey/bin):

```bash
bin install github.com/aaronflorey/strace-analyser
```

If you do not have `bin` yet:

```bash
curl -fsSL https://raw.githubusercontent.com/aaronflorey/bin/master/install.sh | sh
bin install github.com/aaronflorey/strace-analyser
```

Install with Go:

```bash
go install github.com/aaronflorey/strace-analyser@latest
```

## Local setup

```bash
go mod download
go test ./...
go run . --help
```

## Usage

Capture traces with the recommended flags first:

```bash
strace -f -T -ttt -o trace.out <command>
```

Run all report sections:

```bash
strace-analyser all /path/to/trace-dir
```

Run a single section:

```bash
strace-analyser files /path/to/trace-dir
```

### Commands

- `all <trace-dir>`
- `files <trace-dir>`
- `network <trace-dir>`
- `locks <trace-dir>`
- `errors <trace-dir>`
- `process <trace-dir>`
- `metadata <trace-dir>`
- `poll <trace-dir>`
- `memory <trace-dir>`
- `ipc <trace-dir>`

### Global flags

- `-n, --top` row limit per table (default: `30`)
- `--min-bytes` filter for byte-based tables (default: `1`)
- `--json` print full parsed report as JSON
