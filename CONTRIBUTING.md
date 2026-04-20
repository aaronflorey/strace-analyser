# Contributing

Thanks for contributing to `strace-analyser`.

## Development setup

1. Install Go 1.24 or newer.
2. Clone the repository.
3. Install dependencies:

```bash
go mod download
```

## Run locally

```bash
go run . --help
go run . all ./testdata/ci-smoke.trace -n 5 --min-bytes 1024
```

## Quality checks

Run these before opening a pull request:

```bash
go vet ./...
go test ./...
```

## Commit and pull request guidelines

- Use conventional commits where possible (`feat:`, `fix:`, `chore:`, `docs:`).
- Keep pull requests focused and small.
- Include usage examples or fixture updates when behavior changes.
- Update README or other docs when flags, commands, or release behavior change.

## Trace fixture notes

- Fixture traces live in `./testdata`.
- For best parser coverage, capture traces with:

```bash
strace -f -T -ttt -o trace.out <command>
```
