# safesh — Claude Code Instructions

## Project overview

`safesh` is a Go CLI tool that acts as a drop-in replacement for `bash` in the `curl | bash` pattern. See `docs/` for full context: problem statement, position, features, and design.

## Build and test

```sh
# Requires tools in ~/devel/gopath/bin — ensure PATH includes it:
export PATH="$PATH:$(go env GOPATH)/bin"

task build       # build ./dist/safesh
task test        # go test -race ./...
task lint        # golangci-lint
task ci          # lint + test + build
```

## Key design decisions

- **No direct execution via mvdan.cc/sh** — we use `mvdan.cc/sh/v3/syntax` for AST parsing only; actual execution is always delegated to the system shell
- **Full buffering before any execution** — non-negotiable; never pipe a partial script to the shell
- **Strict mode injected as text preamble** — `set -euo pipefail` prepended after shebang (if any)
- **Temp file execution** — script written to `0600` temp file, passed as argument to shell; not piped to shell stdin
- **History always written** — including aborted runs and dry runs
- **Environment stripped to safe baseline** — only PATH, HOME, USER, LOGNAME, SHELL, TERM, LANG, LC_ALL pass through by default

## Module path

`github.com/adeshmukh/safesh` — update when GitHub org is created.

## Package structure

```
cmd/safesh/          CLI entry point (cobra)
internal/config/     Config loading (TOML)
internal/analyzer/   AST analysis + findings engine
internal/fetcher/    Stdin reader + HTTPS fetcher
internal/history/    History persistence
internal/integrity/  Checksum verification
internal/executor/   Shell delegation
internal/ui/         Output formatting + confirmation prompt
testdata/scripts/    Shell script fixtures for tests
```

## Testing conventions

- Unit tests live alongside source files (`foo_test.go`)
- Integration tests are in `internal/integration/` and use `//go:build integration`
- Use `testify/assert` for non-fatal assertions, `testify/require` for fatal
- Table-driven tests preferred
- Run with `-short` to skip slow tests in unit mode

## Finding categories (canonical names)

`execution-integrity`, `destructive`, `privilege`, `persistence`, `network`, `obfuscation`, `execution-chain`
