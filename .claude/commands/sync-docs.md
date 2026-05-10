---
description: Reconcile README.md and the docs/ site with the current code state, then open a PR.
---

Reconcile user-facing documentation with the current code state of `safesh`. The two doc surfaces are:

1. `README.md` at the repo root.
2. The GitHub Pages site under `docs/` — primarily `docs/index.html`, plus `docs/features.md`, `docs/design.md`, `docs/position.md`, `docs/problem-statement.md`, `docs/survey.md`.

Treat the code as the source of truth. Do not invent capabilities; do not delete text just because it isn't covered by code. Make the smallest set of edits that removes drift.

## Sources of truth (compare docs against these)

- **CLI surface** (flags, subcommands, args, version line): `cmd/safesh/main.go`. Look at `newRootCmd`, `newVersionCmd`, `newHistoryCmd`, the `flags` struct, and `printExplanation`.
- **Finding categories** (canonical set, names, order): `internal/finding/finding.go` (`AllCategories`). The current full set is `execution-integrity`, `destructive`, `privilege`, `persistence`, `network`, `obfuscation`, `execution-chain`, `homograph`. If the code has changed, trust the code.
- **Per-category descriptions**: the `printExplanation` map in `cmd/safesh/main.go` and the analyzer modules under `internal/analyzer/modules/`.
- **History layout / paths**: `internal/history/`.
- **Config schema**: `internal/config/`.
- **Sandbox / observe behaviour**: `internal/sandbox/` and `internal/observer/` — both have OS constraints (Linux-only, require `bwrap` / `strace`) that the docs must state correctly.
- **Build / install commands**: `Taskfile.yml` and `.goreleaser.yml` (Homebrew tap publish lives there).
- **Recent intent**: `git log --oneline -30` — recent commits often hint at what changed.

## How to detect drift

Walk each doc surface end-to-end and ask:

1. **Flag drift.** Does every persistent flag in `cmd/safesh/main.go` appear in the doc's flag table or usage examples (where one exists)? Does any flag in the docs no longer exist? Common gaps to check: `--ci`, `--observe`, `--sandbox`, `--sandbox-allow-net`, `--no-strict`, `--no-confirm`, `--config`, `--explain`, `--env`, `--sha256`, `--dry-run`, `--version`.
2. **Subcommand drift.** Does every cobra subcommand (`version`, `history`, `history show --last`) appear correctly?
3. **Finding-category drift.** Does each surface that lists categories (`README.md` "Finding categories" table, `docs/index.html` "Finding categories" section, `docs/features.md` section 4) include every entry from `finding.AllCategories` with a sensible one-line description? `homograph` is a frequent miss.
4. **Future-vs-shipped drift.** `docs/features.md` has a "Future Considerations" section. Anything there that has actually shipped (e.g. `--ci`, `--sandbox`, Homebrew install) must be promoted out of "future" into the appropriate shipped section.
5. **Install instructions drift.** Cross-check `README.md` and `docs/index.html` install blocks against `.goreleaser.yml` (Homebrew tap, binary names, supported OS/arch).
6. **Example output drift.** If the docs quote `safesh` output (e.g. `no findings`, `sha256 verified`, banner text), make sure those strings still appear in `internal/ui/` output. If not, update the quoted output.
7. **Link rot.** Verify every relative link in `README.md` and `docs/*.md` points to a file that exists.

## Scope rules

- Edit only what is drifted. Do not rewrite voice, restructure sections, or add new content beyond what the code requires.
- Do not change `docs/design.md` architecture prose unless the architecture itself has changed in code.
- Do not touch `docs/position.md`, `docs/survey.md`, or `docs/problem-statement.md` unless something in them is factually contradicted by the code.
- Do not add emojis.
- Do not modify `docs/index.html` styling or layout — content edits only (inside existing `<table>`, `<section>`, `<p>` elements).

## Verify

- Run `task lint` and `task test` if you modified anything in `internal/` or `cmd/` (you shouldn't, but check).
- For `docs/index.html`, eyeball the diff for unbalanced tags.
- For markdown changes, confirm tables still parse (consistent column counts).

## Ship

Open a pull request — do NOT commit to `main`. Suggested branch name: `docs/sync-<short-topic>`. Commit message follows the repo's conventional-commit style; recent examples: `docs(readme): …`, `docs(site): …`. Use a single commit per logical change when possible. Include the standard `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>` trailer.

PR title: `docs: sync README and site with current code surface` (or narrower if the diff is small). PR body: bullet list of each drift found and fixed, with the source-of-truth file referenced for each item.

If you find no drift, say so plainly and do not open a PR.
