# safesh examples

Each subdirectory is a self-contained end-to-end scenario. Every example runs
a real HTTP server (via `python3 -m http.server`) alongside a test container
that invokes safesh against it — the same `curl | safesh` code path used in
production.

## Examples

| Directory | Scenario |
|-----------|----------|
| `1-clean-script` | No findings → safesh runs the script, exits 0 |
| `2-findings-allowed` | Privilege + network findings → `--ci` mode proceeds with warnings |
| `3-aborted-run` | Obfuscation finding (blocking) → non-interactive mode blocks execution |
| `4-checksum-verify` | `--sha256` matches → integrity verified, script runs |
| `5-dry-run` | `--dry-run` → findings reported, script never executed |

## Running

Run a single example:

```sh
make -C examples/1-clean-script test
```

Run all examples:

```sh
task test-e2e
```

## Requirements

- Docker with `docker compose` (v2)
- `task` (Taskfile runner)

## How each example works

Each example contains:

- `docker-compose.yml` — `server` service (python HTTP) + `test` service (safesh runner)
- `scripts/` — shell scripts served by the HTTP server
- `test.sh` — assertions run inside the test container
- `Makefile` — `make test` is the entry point
