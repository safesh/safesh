# safesh

A drop-in replacement for `bash` in the `curl | bash` pattern that makes script execution meaningfully safer with minimal friction.

```sh
# Before
curl -fsSL https://example.com/install.sh | bash

# After
curl -fsSL https://example.com/install.sh | safesh
```

`safesh` buffers the full script before executing, enforces strict mode, performs static analysis, and reports findings — all before a single line runs.

## What it does

- **Buffers completely** — reads the entire script before executing any of it, preventing partial execution from dropped connections
- **Enforces strict mode** — prepends `set -euo pipefail` to catch unset variables and command failures
- **Analyses statically** — walks the AST to find destructive operations, privilege escalation, persistence mechanisms, obfuscation, and more
- **Reports findings** — groups them by category with line numbers before asking for confirmation
- **Keeps history** — every execution is logged to `~/.local/share/safesh/history/`
- **Isolates environment** — strips sensitive env vars before delegating to the shell

## Installation

```sh
# Via go install
go install github.com/safesh/safesh/cmd/safesh@latest
```

## Usage

```sh
# Pipe mode (primary)
curl -fsSL https://example.com/install.sh | safesh

# Specify execution shell
curl -fsSL https://example.com/install.sh | safesh bash
curl -fsSL https://example.com/install.sh | safesh zsh

# URL mode (enables integrity checking)
safesh https://example.com/install.sh

# URL mode with expected hash
safesh --sha256 <hash> https://example.com/install.sh

# Dry run (analyse without executing)
curl -fsSL https://example.com/install.sh | safesh --dry-run

# Inspect history
safesh history
safesh history show --last
safesh history show <id>
```

## Finding categories

| Category | What it flags |
|---|---|
| `execution-integrity` | Missing `set -e`, `set -u`, `set -o pipefail` |
| `destructive` | `rm -rf`, `dd`, `mkfs`, truncation |
| `privilege` | `sudo`, `su`, `pkexec` |
| `persistence` | Cron jobs, shell profile modifications, systemd units |
| `network` | Outbound `curl`/`wget` calls and their domains |
| `obfuscation` | `eval`, `base64 -d \| bash` chains |
| `execution-chain` | Nested `curl \| bash` inside the script |

## Philosophy

`safesh` is honest about what it can and cannot do. A script that passes all checks is *unsuspicious*, not *safe*. It is one layer of defense, not a security guarantee. See [docs/position.md](docs/position.md).

## Configuration

Optional config at `~/.config/safesh/config.toml`. Runs without any config by default.

See [docs/features.md](docs/features.md) for the full feature set and [docs/design.md](docs/design.md) for architecture.

## License

MIT
