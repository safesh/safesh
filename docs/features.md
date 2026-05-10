# Features

This document defines the feature set for `safesh`. See [position.md](position.md) for philosophy and limitations.

---

## MVP Features

### 1. Drop-in Invocation

`safesh` is usable as a direct replacement for `bash` in the pipe pattern:

```sh
curl -fsSL https://example.com/install.sh | safesh
```

It also supports direct URL invocation, which unlocks integrity checking (see feature 7):

```sh
safesh https://example.com/install.sh
```

Both modes produce the same analysis and execution behavior. The pipe form is the primary use case; the URL form is for users who want integrity checking or a cleaner audit record.

---

### 2. Full Buffering Before Execution

`safesh` always reads the complete script before executing any of it. Execution never begins on a partial download.

This prevents a class of bugs and attacks where a truncated script (from a dropped connection or a malicious server that closes mid-stream) executes partial logic — for example, a cleanup step that runs without the subsequent install step.

This is non-negotiable behavior and cannot be disabled.

---

### 3. Strict Mode Enforcement

`safesh` prepends the following to every script before execution, regardless of what the script author included:

```sh
set -euo pipefail
```

This ensures:
- `set -e` — exit immediately on any command failure
- `set -u` — treat unset variables as errors (prevents the `rm -rf $PREFIX/` → `rm -rf /` class of bug)
- `set -o pipefail` — propagate failures through pipes

If a script is known to be incompatible with strict mode (rare but possible), the user can disable this via configuration.

---

### 4. Semantic Findings Report

Before executing, `safesh` analyzes the script and reports findings grouped by category. Findings include the line number and a plain-language description.

Categories:

| Category | What it covers |
|---|---|
| **execution-integrity** | Missing `set -e`, `set -u`, `set -o pipefail`; ignored exit codes (`cmd \|\| true` patterns) |
| **destructive** | `rm -rf`, `dd`, `mkfs`, truncation of existing files, disk-level operations |
| **privilege** | `sudo`, `su`, `pkexec`, `chmod 777`, `chown` to root |
| **persistence** | Cron jobs, systemd units, shell profile modifications (`~/.bashrc`, `~/.zshrc`, `/etc/profile.d/`), login hooks |
| **network** | `curl`/`wget`/`fetch` calls within the script and the domains they contact |
| **obfuscation** | `eval`, `base64 -d | bash`, dynamic variable construction used in command execution |
| **execution-chain** | Nested `curl \| bash` or `wget \| sh` patterns inside the script |
| **homograph** | Bidi/isolate control characters, zero-width characters, and IDN-homograph URL hosts (mixed-script or non-ASCII labels) |

Example output:

```
safesh findings:
  [persistence]        modifies ~/.bashrc (line 42)
  [privilege]          invokes sudo (lines 18, 67)
  [network]            fetches from: releases.example.com, raw.githubusercontent.com
  [obfuscation]        uses eval (line 91)
  [execution-chain]    pipes to bash internally (line 103)

Run with --explain <category> for more detail.
```

If no findings are present, `safesh` reports that and proceeds. If findings are present, the default behavior is to display them and prompt for confirmation before executing (see feature 5).

The findings report alone has value even if the user proceeds — it leaves a record of what was suspicious about a script that later causes a problem.

---

### 5. Zero-Config Defaults with Configurable Behavior

Out of the box, `safesh` requires no configuration. The defaults are:

- Full buffering: always on
- Strict mode: always on
- Findings report: always shown
- Confirmation prompt: shown when any findings exist
- History logging: always on

Users who want to customize behavior can place a config file at `~/.config/safesh/config.toml`. Configurable options include:

- Which finding categories trigger a confirmation prompt (vs. warn-only)
- Which finding categories block execution entirely
- Whether to disable strict mode for specific scripts (by URL pattern or hash)
- History retention policy (count or age)
- Custom finding rules (pattern + category + description)

---

### 6. History and Audit Log

Every script execution is recorded at `~/.local/share/safesh/history/`. Each entry is a directory named by timestamp and contains:

- `script.sh` — the full script as received (before any `safesh` modifications)
- `meta.json` — source URL (if known), timestamp, invocation mode, user, hostname, `safesh` version
- `findings.json` — the structured findings report
- `exit.json` — exit code and execution duration

The history directory is append-only by design. `safesh` never modifies or deletes history entries automatically (retention cleanup is a separate, configurable housekeeping operation).

---

### 7. Integrity Checking (URL Invocation Mode)

When invoked as `safesh https://example.com/install.sh`, `safesh` fetches the script itself and attempts to locate a checksum file using common conventions:

- `<url>.sha256`
- `<url>.sha256sum`
- Sibling `checksums.txt` or `SHA256SUMS` in the same directory

If a checksum file is found, `safesh` verifies the script against it and reports the result before proceeding. If no checksum file is found, `safesh` notes the absence but does not block execution.

Users can also provide an expected hash explicitly:

```sh
safesh --sha256 <expected-hash> https://example.com/install.sh
```

This is useful when a project documents the expected hash in release notes but does not publish a checksum file at a discoverable URL.

**Note:** Integrity checking confirms the script has not been tampered with in transit. It does not verify the script is safe to run, nor does it authenticate the script's author.

---

### 8. Dry Run (Static)

`safesh --dry-run` performs full analysis and displays the findings report but does not execute the script. The script is saved to history as a dry-run entry.

The dry run is explicitly static: it shows what the script *contains*, not what it *would do* on your system. Scripts with conditional branches, runtime environment detection, or dynamic downloads may behave differently at execution time than the static analysis suggests.

`safesh` makes this limitation clear in dry-run output.

---

### 9. Inspect History

```sh
safesh history              # list recent entries
safesh history show <id>    # show script and findings for an entry
safesh history show --last  # show the most recent entry
```

Output includes the script source, findings, metadata, and exit code. No external tooling or report format required — plain terminal output.

---

### 10. Network Activity Inventory

As part of the findings report (category: `network`), `safesh` lists every domain the script intends to contact. This gives the user a concrete answer to "what does this script phone home to?" before deciding to run it.

This is static analysis — it identifies `curl`/`wget` calls with literal URLs. Dynamically constructed URLs (e.g., `curl "$BASE_URL/file"`) are flagged as unresolvable and noted separately.

---

### 11. Environment Isolation

`safesh` runs the script with a clean, minimal environment rather than inheriting the full shell environment. The inherited environment is stripped to a safe baseline (`PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `TERM`, `LANG`, `LC_ALL`) before execution.

This prevents scripts from accidentally or intentionally reading sensitive values from environment variables (API keys, tokens, credentials) that happen to be set in the user's session.

Users can pass specific environment variables through explicitly:

```sh
safesh --env MY_VAR https://example.com/install.sh
```

---

### 12. Sandboxed Execution (Linux)

`safesh --sandbox` runs the script inside a [bubblewrap](https://github.com/containers/bubblewrap) sandbox with a restricted filesystem view. Network access is blocked by default; pass `--sandbox-allow-net` to allow it. Linux only; requires `bwrap` to be installed.

This is opt-in and intended for high-risk scripts where the user wants stronger isolation than environment stripping alone provides. macOS support and a Landlock-only fallback on Linux kernels where bubblewrap is unavailable are still future work (see Future Considerations).

---

### 13. CI / Non-Interactive Mode

`safesh --ci` skips the confirmation prompt, prints findings as warnings, and exits non-zero only on actual execution failure (not on findings alone). Intended for automated environments — CI pipelines, provisioning scripts, agent toolchains — where there is no human at a TTY to respond to prompts.

The findings report is still produced and still written to history. `--ci` does not suppress findings; it only changes how they gate execution.

---

### 14. Runtime Observation (Linux)

`safesh --observe` runs the script under [`strace`](https://strace.io/) and reports the observed behavior afterward — files opened, network calls made, processes spawned. Linux only; requires `strace` to be installed.

This is a sandboxed run by default (no confirmation prompt), intended as a complement to static analysis rather than a replacement. It catches dynamically constructed behavior that the static `network` finding cannot resolve, but it does not block: the script runs and the observation is reported alongside the findings. Use `--dry-run` if you want analysis without execution.

---

## Future Considerations

The following are intentionally out of scope for MVP. They are worth revisiting once core features are stable.

### Plugin / Hook Architecture
A defined extension API allowing custom analysis modules, custom blocking rules, and custom audit backends. Valuable for power users and teams, but expensive to design well. A poorly designed plugin API becomes a maintenance burden and a new attack surface. Should emerge from real use cases rather than speculative design.

### macOS Sandbox + Landlock Fallback
`--sandbox` is shipped on Linux via bubblewrap (see feature 12). Still future: a `sandbox-exec` profile for macOS, and a Landlock-only fallback on Linux kernels where bubblewrap is unavailable.

### Team / Organizational Policy
Centrally managed `safesh` policy (allowed domains, required findings categories that block execution, mandatory audit log forwarding) for organizations that want consistent enforcement across developers. Out of scope until the single-user experience is solid.

### GPG / Sigstore Integration
Verifying scripts against a GPG signature or Sigstore transparency log entry. Addresses the authentication gap that integrity checking (feature 7) does not. Requires bootstrapping trust in the verification tooling — a hard problem that deserves its own design treatment.
