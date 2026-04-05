# Design

This document describes the technical design of `safesh`. See [features.md](features.md) for the feature set and [position.md](position.md) for philosophy and scope.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Invocation Modes](#2-invocation-modes)
3. [Execution Flow](#3-execution-flow)
4. [AST Analysis Pipeline](#4-ast-analysis-pipeline)
5. [Execution Model](#5-execution-model)
6. [History Storage](#6-history-storage)
7. [Configuration](#7-configuration)
8. [CLI Interface](#8-cli-interface)
9. [Project Structure](#9-project-structure)
10. [Key Dependencies](#10-key-dependencies)

---

## 1. Architecture Overview

`safesh` is composed of seven discrete components with a linear, pipeline-shaped flow:

```
┌─────────┐    ┌────────┐    ┌──────────┐    ┌─────────────┐
│ Fetcher │───▶│ Buffer │───▶│ Analyzer │───▶│  Integrity  │
└─────────┘    └────────┘    └──────────┘    │  Checker    │
                                              └──────┬──────┘
                                                     │
                             ┌───────────────────────▼──────┐
                             │         Confirmer             │
                             │  (display findings + prompt)  │
                             └───────────────┬───────────────┘
                                             │
                        ┌────────────────────▼──────────────┐
                        │              Executor              │
                        │  (inject preamble → delegate shell)│
                        └──────────────────┬─────────────────┘
                                           │
                               ┌───────────▼──────────┐
                               │    History Writer     │
                               └──────────────────────┘
```

Each component has a single responsibility. They communicate through a shared `RunContext` struct that carries the script content, findings, metadata, and configuration for the duration of a single execution.

---

## 2. Invocation Modes

### Pipe Mode (primary)

```sh
curl -fsSL https://example.com/install.sh | safesh [shell]
```

- Script is read from stdin
- Source URL is not known; recorded as `"stdin"` in history
- Shell is determined from shebang or defaults to `bash`
- Integrity checking is not available (no URL to probe for a checksum sibling)

### URL Mode

```sh
safesh [flags] <url>
```

- `safesh` fetches the script itself via HTTPS
- Source URL is known; recorded in history and used for integrity checking
- Same analysis and execution pipeline as pipe mode

### History Subcommands

```sh
safesh history
safesh history show <id>
safesh history show --last
```

Read-only. Does not invoke the analysis or execution pipeline.

---

## 3. Execution Flow

Both pipe and URL modes follow the same sequence:

```
1. Parse arguments and load configuration
2. Fetch / read script into buffer (complete, before any execution)
3. [URL mode only] Attempt integrity check
4. Parse script AST with mvdan.cc/sh
5. Run findings engine over AST → produce findings list
6. Display findings to stderr
7. If findings exist AND running interactively → prompt for confirmation
8. If confirmed (or no findings, or --no-confirm) → proceed
9. Execute: write temp file, build clean env, delegate to shell
10. Write history entry (always, including dry-run and aborted runs)
11. Clean up temp file
```

Step 10 happens regardless of outcome. An aborted run (user declined) and a failed run both produce history entries — they are useful for forensics.

### Dry-Run Deviation

With `--dry-run`, the flow stops after step 7. The script is not executed. The history entry is written and marked `dry_run: true`.

---

## 4. AST Analysis Pipeline

### Parser

`safesh` uses `mvdan.cc/sh/v3/syntax` to parse the script into an AST. This is the same library that powers `shfmt`. It supports POSIX sh, bash, and mksh dialects.

The parser is run before any execution. If parsing fails (invalid syntax), `safesh` reports the parse error and aborts. This also catches scripts that are not valid shell — including binaries accidentally served as scripts.

### Findings Engine

The findings engine walks the AST using the visitor pattern. Each finding category is an independent analysis module implementing a common interface:

```go
type Module interface {
    Analyze(ast *syntax.File, src []byte) []Finding
}
```

Each module returns zero or more `Finding` values:

```go
type Finding struct {
    Category    Category
    Line        int
    Col         int
    Description string
    Snippet     string
}
```

Modules are stateless and run in parallel. Results are merged and sorted by line number before display.

### Finding Modules

| Module | What it looks for in the AST |
|---|---|
| `execution-integrity` | Absence of `set -e`, `set -u`, `set -o pipefail` in top-level statements |
| `destructive` | `CallExpr` where command is `rm`, `dd`, `mkfs`, `shred`, `truncate` with flags that indicate irreversibility |
| `privilege` | `CallExpr` where command is `sudo`, `su`, `pkexec`, `doas`, `runuser` |
| `persistence` | Redirects or `CallExpr` targeting `~/.bashrc`, `~/.zshrc`, `~/.profile`, `/etc/profile.d/`, `crontab`, `systemctl enable` |
| `network` | `CallExpr` where command is `curl`, `wget`, `fetch`, `http`; extracts literal URL arguments |
| `obfuscation` | `CallExpr` for `eval`; pipe expressions where left side is `base64` with decode flags and right side is a shell |
| `execution-chain` | Pipe expressions where the right-hand command is `bash`, `sh`, `zsh`, `dash`, `fish`, or `ksh` |

#### A note on static analysis limits

Modules analyze literal values in the AST. Dynamically constructed values (e.g., `curl "$BASE_URL/file"`) cannot be resolved statically. When a module encounters a dynamic value where a literal is expected (e.g., a URL argument that is a variable reference), it records a finding noting the unresolvable expression rather than silently skipping it.

---

## 5. Execution Model

### Strict Mode Injection

`safesh` prepends a preamble to the script before execution. The preamble is injected as source text, not as a shell flag, so it applies to the script's own execution context:

```sh
set -euo pipefail
```

If the script has a shebang line, the preamble is inserted immediately after it. If not, it is prepended at the top.

This can be disabled via `--no-strict` or the config file (per URL pattern or globally).

### Shell Selection

Precedence, highest to lowest:

1. Positional argument: `safesh bash`, `safesh zsh`
2. Shebang line in the script: `#!/bin/bash`, `#!/usr/bin/env zsh`
3. Config default (`defaults.shell`)
4. Fallback: `bash`

When resolving a shell name, `safesh` looks it up in `PATH` and records the resolved absolute path in the history entry. If the specified shell is not found, `safesh` aborts with a clear error rather than silently falling back.

Recognised shell names: `bash`, `sh`, `zsh`, `dash`, `fish`, `ksh`, `mksh`.

### Environment Isolation

The script is executed with a minimal environment. Only the following variables are passed through by default:

```
PATH, HOME, USER, LOGNAME, SHELL, TERM, LANG, LC_ALL
```

All other environment variables (including any secrets or tokens in the parent session) are stripped. Additional variables can be passed through explicitly:

```sh
curl ... | safesh --env GITHUB_TOKEN --env MY_VAR
```

### Temp File Execution

The modified script (with preamble injected) is written to a temp file under a directory with `0700` permissions. The shell is invoked with the temp file as its argument. The temp file is removed after the shell exits, whether or not execution succeeded.

`safesh` does not use `bash -c <script>` or pipe the script to the shell's stdin — this avoids re-introducing the partial execution problem and ensures the shell reads from a complete, seekable file.

---

## 6. History Storage

### Location

```
~/.local/share/safesh/history/
```

### Entry Structure

Each execution produces a directory named by a collision-resistant ID:

```
~/.local/share/safesh/history/
  20260405T143022Z-a3f9b2/
    script.sh       # original script as received, unmodified
    meta.json       # execution metadata
    findings.json   # structured findings report
    exit.json       # exit code and duration (absent for dry runs and aborted runs)
```

The ID format is `<ISO8601-compact-UTC>-<6-hex-chars>`. Example: `20260405T143022Z-a3f9b2`.

### `meta.json`

```json
{
  "id": "20260405T143022Z-a3f9b2",
  "timestamp": "2026-04-05T14:30:22Z",
  "source": "https://example.com/install.sh",
  "mode": "url",
  "shell": "/usr/bin/bash",
  "shell_requested": "bash",
  "safesh_version": "0.1.0",
  "hostname": "devbox",
  "user": "alice",
  "dry_run": false,
  "aborted": false,
  "strict_mode": true,
  "checksum": {
    "algorithm": "sha256",
    "value": "e3b0c44298fc1c149afb...",
    "verified": true,
    "checksum_source": "https://example.com/install.sh.sha256"
  }
}
```

`checksum` is omitted if integrity checking was not performed or not applicable (pipe mode).

### `findings.json`

```json
{
  "findings": [
    {
      "category": "privilege",
      "line": 18,
      "col": 1,
      "description": "invokes sudo",
      "snippet": "sudo apt-get install -y curl"
    },
    {
      "category": "persistence",
      "line": 42,
      "col": 1,
      "description": "appends to ~/.bashrc",
      "snippet": "echo 'export PATH=...' >> ~/.bashrc"
    }
  ]
}
```

An empty `findings` array means the script produced no findings — not that it is safe.

### `exit.json`

```json
{
  "exit_code": 0,
  "duration_ms": 4821
}
```

Absent for dry-run entries and runs aborted at the confirmation prompt.

### History Retention

`safesh` does not automatically delete history entries. Retention cleanup is a separate, explicit operation:

```sh
safesh history clean --older-than 90d
safesh history clean --keep-last 100
```

---

## 7. Configuration

### Location

```
~/.config/safesh/config.toml
```

Created on first run with defaults if it does not exist. `safesh` always works without a config file present.

### Schema

```toml
[defaults]
# Default shell if not specified by argument or shebang
shell = "bash"

# Inject set -euo pipefail before execution
strict_mode = true

# Prompt for confirmation when findings exist
confirm_on_findings = true

# Strip environment to safe baseline before execution
environment_isolation = true

[findings]
# Categories that require explicit confirmation to proceed
# (user is shown findings and must type 'yes')
blocking = ["obfuscation", "execution-chain"]

# Categories that display a warning but do not prompt
warn_only = ["network", "persistence"]

# Categories to suppress entirely (use with care)
ignore = []

[history]
enabled = true

# Housekeeping thresholds (not auto-applied; used by 'safesh history clean')
max_entries = 1000
max_age_days = 90

[strict_mode]
# Disable strict mode for scripts from these URL prefixes
# Applies to URL mode only
disabled_for = []
# Example:
# disabled_for = ["https://trusted-internal.example.com/"]

[environment]
# Environment variable names to pass through in addition to the safe baseline
passthrough = []
# Example:
# passthrough = ["GITHUB_TOKEN", "NPM_TOKEN"]
```

---

## 8. CLI Interface

### Synopsis

```
safesh [<shell>] [flags]          # pipe mode: read script from stdin
safesh [flags] <url>              # URL mode: fetch script from URL
safesh history                    # list recent history entries
safesh history show <id>          # show a specific history entry
safesh history show --last        # show the most recent entry
safesh history clean [flags]      # remove history entries matching criteria
```

### Flags

| Flag | Description |
|---|---|
| `--dry-run` | Analyze and report findings without executing |
| `--sha256 <hash>` | Expected SHA-256 hash; abort if script does not match (URL mode only) |
| `--explain <category>` | Print a detailed explanation of a finding category and exit |
| `--env <VAR>` | Pass through a named environment variable (repeatable) |
| `--no-strict` | Do not inject `set -euo pipefail` |
| `--no-confirm` | Display findings but do not prompt; always proceed |
| `--config <path>` | Use an alternate config file |
| `--version` | Print version and exit |
| `--help` | Print help and exit |

### `history show` Output

```
Entry: 20260405T143022Z-a3f9b2
Date:  2026-04-05 14:30:22 UTC
Source: https://example.com/install.sh
Shell: /usr/bin/bash
Exit:  0 (4.8s)

Findings:
  [privilege]    line 18  invokes sudo
  [persistence]  line 42  appends to ~/.bashrc

Script:
─────────────────────────────────────────
#!/usr/bin/env bash
... (script content) ...
─────────────────────────────────────────
```

---

## 9. Project Structure

```
safesh/
├── cmd/
│   └── safesh/
│       └── main.go               # entry point, wires components
├── internal/
│   ├── analyzer/
│   │   ├── analyzer.go           # orchestrates module execution
│   │   ├── finding.go            # Finding type and Category constants
│   │   └── modules/
│   │       ├── destructive.go
│   │       ├── execution_chain.go
│   │       ├── execution_integrity.go
│   │       ├── network.go
│   │       ├── obfuscation.go
│   │       ├── persistence.go
│   │       └── privilege.go
│   ├── config/
│   │   └── config.go             # load, parse, and validate config.toml
│   ├── executor/
│   │   └── executor.go           # preamble injection, env setup, shell delegation
│   ├── fetcher/
│   │   └── fetcher.go            # stdin reader and HTTPS fetcher
│   ├── history/
│   │   └── history.go            # write and read history entries
│   ├── integrity/
│   │   └── integrity.go          # checksum discovery and verification
│   └── ui/
│       ├── confirm.go            # TTY detection and confirmation prompt
│       └── output.go             # findings display, formatting
├── docs/
│   ├── design.md
│   ├── features.md
│   ├── position.md
│   ├── problem-statement.md
│   └── survey.md
├── go.mod
└── go.sum
```

---

## 10. Key Dependencies

| Package | Purpose |
|---|---|
| `mvdan.cc/sh/v3` | Shell parser (AST) and syntax utilities. Powers all static analysis. |
| `github.com/spf13/cobra` | CLI framework. Flag parsing, subcommands, help generation. |
| `github.com/BurntSushi/toml` | Configuration file parsing. |
| `golang.org/x/term` | TTY detection (determines whether to show interactive confirmation prompt). |

All dependencies are chosen for stability and minimal transitive footprint. `mvdan.cc/sh/v3` is the only domain-specific dependency; the rest are standard CLI infrastructure.
