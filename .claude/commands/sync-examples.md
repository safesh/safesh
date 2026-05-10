---
description: Audit examples/ against current safesh capabilities and add or update examples to close gaps, then open a PR.
---

Keep `examples/` a faithful, runnable demonstration of what `safesh` does today. Add missing examples for shipped features; update stale examples whose assertions no longer match safesh's output. Do not invent examples for capabilities that don't exist yet.

## Where things live

- **Example suite root**: `examples/`
- **Per-example layout** (mirror this exactly for any new example):
  - `examples/N-<slug>/Makefile` — `make test` is the entry point
  - `examples/N-<slug>/docker-compose.yml` — `server` (python http) + `test` (safesh runner) services
  - `examples/N-<slug>/scripts/install.sh` — the script served over HTTP
  - `examples/N-<slug>/test.sh` — assertions run inside the test container
  - `examples/N-<slug>/README.md` — short scenario description with expected terminal output
- **Shared image**: `examples/Dockerfile` (builds safesh from source into an alpine runner with `bash` + `curl`).
- **Suite index**: `examples/README.md` — has a table that must list every example.
- **Suite runner**: `task test-e2e` (defined in `Taskfile.yml`) — iterates `examples/*/` and runs `make -C "$dir" test`.

Existing examples (read these first to absorb conventions):

- `1-clean-script` — no findings, runs and exits 0.
- `2-findings-allowed` — `--ci` mode proceeds with warnings on privilege+network findings.
- `3-aborted-run` — non-interactive blocking on obfuscation finding (also covers homograph).
- `4-checksum-verify` — `--sha256` happy path + wrong-hash failure path.
- `5-dry-run` — `--dry-run` reports findings without executing.

## Sources of truth

- **CLI surface** (flags / subcommands worth demonstrating): `cmd/safesh/main.go`. Note flags that have user-visible behaviour but currently no example: candidates include `--observe`, `--sandbox` / `--sandbox-allow-net`, `--explain <category>`, `--no-strict`, `--config`, `--env`, `safesh history` / `safesh history show`, `safesh version` / `--version`.
- **Finding categories**: `internal/finding/finding.go` (`AllCategories`) and `internal/analyzer/modules/`. Every category should be exercised by at least one example's `install.sh` somewhere in the suite — not necessarily a dedicated example each.
- **UI output strings** that test scripts grep for: `internal/ui/`. If a test greps for text that no longer appears, the test is stale.

## How to detect gaps

1. **Feature-without-example.** For each user-visible flag/subcommand in `cmd/safesh/main.go`, check whether any `examples/*/test.sh` invokes it. Missing? Candidate for a new example. Skip features that are platform-restricted in a way the Docker harness can't satisfy (e.g. `--observe` requires Linux + strace; `--sandbox` requires Linux + bwrap — these can still work in the alpine container but need `apk add strace` / `bubblewrap` in `examples/Dockerfile`; only add such examples if the harness can actually run them — otherwise skip and note in the PR body).
2. **Category-without-coverage.** For each category in `finding.AllCategories`, grep `examples/*/scripts/*.sh` for a triggering pattern. Any uncovered category is a gap — usually fixable by extending an existing `install.sh` rather than adding a new example.
3. **Stale assertion.** For each `examples/*/test.sh`, check every `grep -q` pattern against current `internal/ui/` output. If `safesh` no longer prints that string, update the grep (do NOT delete the assertion — find the new string).
4. **Stale README.** Each `examples/N-*/README.md` quotes terminal output. If safesh's output has changed, refresh the quoted block.
5. **Suite index drift.** `examples/README.md`'s table must list every directory under `examples/`.

## Authoring rules for new examples

- Number the directory sequentially (next free `N-`).
- `install.sh` must be a realistic-looking install script — not a contrived test fixture. Aim for something that resembles what a real vendor might serve.
- `test.sh` follows the existing pattern: `FAIL=0`, `fail()` helper, server-readiness wait loop, run safesh, grep stderr/stdout, `[ "$FAIL" -eq 0 ] && echo "PASS" && exit 0`.
- Do NOT use `set -e` in `test.sh` — alpine's `ash` exits on failing `var=$(cmd)` and breaks the suite. (See `9d8322c` for context.)
- Make assertions specific: grep for category names, exit codes, and at least one banner/output string.
- `Makefile` and `docker-compose.yml` should be byte-for-byte clones of `examples/1-clean-script/`'s versions, except for any extra service config the scenario needs.
- Add the new example to the table in `examples/README.md`.

## Scope rules

- Do not add an example for a capability you cannot point to in `cmd/safesh/main.go` or the `internal/` packages.
- Prefer extending an existing example over adding a new directory when the gap is "category not covered."
- Do not modify `examples/Dockerfile` unless a new example genuinely needs additional packages — and if you do, verify all existing examples still pass.
- Do not add emojis.

## Verify

- `task build` — make sure safesh still compiles.
- For any example you touched or added: `make -C examples/N-<slug> test`. This requires Docker; if Docker isn't available in the session, say so explicitly in the PR body and do not claim the example was verified.
- After all per-example runs pass, optionally run `task test-e2e` to run the full suite.

## Ship

Open a pull request — do NOT commit to `main`. Suggested branch name: `examples/<short-topic>`. Commit style follows the repo: `test(e2e): …` or `feat(examples): …`. Include the standard `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>` trailer.

PR body: list each gap found, what you did about it (added example N, extended example M, updated stale grep in test K), and which examples you actually ran locally vs. which rely on CI.

If you find no gaps and no stale assertions, say so plainly and do not open a PR.
