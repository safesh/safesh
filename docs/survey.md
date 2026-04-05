# Survey of Existing Solutions

This document surveys tools, approaches, and conventions that address the risks described in the [problem statement](problem-statement.md).

---

## Categories

1. [Static Analysis](#1-static-analysis)
2. [Sandboxed Execution](#2-sandboxed-execution)
3. [Preview and Intercept Tools](#3-preview-and-intercept-tools)
4. [Alternative Package Managers](#4-alternative-package-managers)
5. [Code Signing Infrastructure](#5-code-signing-infrastructure)
6. [Runtime Detection and Enforcement](#6-runtime-detection-and-enforcement)
7. [Community Conventions](#7-community-conventions)
8. [Academic and Security Research](#8-academic-and-security-research)

---

## 1. Static Analysis

These tools analyze a script's source before execution to find bugs or dangerous patterns.

### ShellCheck
Mature, widely-used linter for bash/sh/dash/ksh. Catches unquoted variables, unset variable bugs, bad substitutions, and many error-prone idioms. Integrated into most CI systems and editors.

**Gap:** A quality and correctness tool, not a security scanner. Will not detect a well-written malicious script.

### Shellharden
Focused specifically on quoting correctness — the class of bugs where unquoted variables allow word-splitting and glob injection. Can auto-apply fixes.

**Gap:** Narrow scope; quoting only. Does not address intent or logic-level threats.

### Semgrep (with custom rules)
General-purpose pattern-matching static analysis. Custom rules can flag `eval $(...)`, `base64 -d | bash`, hardcoded IPs, or any pattern you define.

**Gap:** Only as good as the rules written. Cannot detect novel evasion or obfuscated malice.

---

## 2. Sandboxed Execution

These tools run scripts in an isolated environment to limit blast radius.

### Firejail
SUID sandbox using Linux namespaces, seccomp-bpf, and optional AppArmor/SELinux. Ready-made profiles exist for many applications.

**Gap:** SUID binary is itself a risk. Kernel bugs can escape namespaces. Manual profile creation required for arbitrary install scripts. Does not prevent damage within allowed scope.

### Bubblewrap (bwrap)
Low-level unprivileged namespace sandbox — the primitive that Flatpak uses internally. More secure than Firejail (no SUID), but requires manual sandbox definitions per use-case.

**Gap:** No user-facing wrapper for ad-hoc installer use. Requires understanding of mount namespaces.

### Docker / Podman
Run a script in an ephemeral container (`--rm --network none --read-only`). Podman runs rootless.

**Gap:** Containers share the host kernel — a kernel exploit escapes. Getting the installed result out of the container onto the host is awkward. Significant overhead for one-off installs.

### Linux Kernel Primitives: Landlock, Seccomp-BPF, Namespaces
Kernel-level mechanisms (available since Linux 5.13 for Landlock) that can in principle restrict a process to write only to the target install directory, read only from system libraries, and block dangerous syscalls.

**Gap:** No ready-made user-facing tool composes these for installer script use. Building such a tool is an open opportunity.

---

## 3. Preview and Intercept Tools

These tools sit between the download and execution steps.

### vet
The most direct response to the curl|bash problem. Replaces the pipe with a four-step workflow: fetch → diff against previous run → ShellCheck → explicit user confirmation. Available on Homebrew and AUR.

**Gap:** Relies on human ability to interpret diffs and ShellCheck output. A well-written malicious script passes all checks. `--force` bypasses the human gate entirely for CI use.

### Tirith
Shell-hook-based terminal security. Detects and blocks pipe-to-shell patterns, homograph URLs, decode-then-execute chains (`base64 -d | sh`), ANSI injection, and credential exfiltration attempts across 80+ rules. Very recently emerged but growing quickly (~2,100 stars).

**Gap:** Shell-hook only — non-interactive script execution is not covered. No runtime monitoring after the command starts.

### lgtmit
Experimental Node.js filter that routes the downloaded script through Claude for AI semantic review before allowing execution.

**Gap:** Very early stage (2 stars, Jan 2026). Requires Claude CLI and API access. AI models can be deceived by adversarially crafted scripts.

### checkinstall
Wraps any install command using `installwatch` to intercept all filesystem writes and builds a proper `.deb`/`.rpm` package from the result, making the install reversible via the package manager.

**Gap:** Does not prevent execution or block network calls. No longer actively maintained upstream. Focused on `make install`, not arbitrary shell scripts.

---

## 4. Alternative Package Managers

These replace the curl|bash pattern entirely with a managed, auditable install path.

### Nix / NixOS
Hermetic, reproducible package manager. Each package is built in a sandbox with cryptographically-addressed outputs. Supports reproducible builds and atomic rollbacks. `nix-shell` enables scripts with pinned, declared dependencies.

**Gap:** Steep learning curve. The bootstrap installer itself uses curl|sh. Review is community-based and fallible.

### GNU Guix
Stricter than Nix: all packages built from source, starting from a tiny binary seed (fully bootstrappable). Updates delivered via authenticated Git checkout, preventing downgrade attacks. Reproducibility independently verifiable.

**Gap:** Smallest ecosystem of the mainstream options. The installer uses curl|sh.

### Homebrew
Human- and CI-reviewed formulae. As of 2025–2026, casks must be Apple-signed and notarized to remain in the official tap.

**Gap:** A 2024 Trail of Bits audit found 20 casks downloading over HTTP with no integrity verification. Third-party taps are unaudited. The installer is a curl|sh.

### Snap / Flatpak
AppArmor/namespace sandboxed application packages. No shell script execution during install — declarative package format.

**Gap:** Sandbox escapes are known (notably via the X11 socket). Store review is imperfect.

### mise / asdf
Version managers for development toolchains. Download official release binaries without executing install shell scripts. No shell script execution during the managed install phase.

**Gap:** Signature verification is inconsistent per tool. Initial bootstrapper uses curl|sh.

### webinstall.dev (webi)
Curated installer scripts for developer tools, authored (not delegated to tool maintainers) with structural safety: strict mode, `{ }` wrapping to prevent partial execution, no sudo, install to `~/.local/`.

**Gap:** Trust shifts entirely to webi maintainers. No signature verification on downloaded binaries (HTTPS only).

---

## 5. Code Signing Infrastructure

### Sigstore / Cosign
Keyless signing using short-lived OIDC certificates logged in an immutable transparency log (Rekor). Supports signing arbitrary blobs including shell scripts.

**Gap:** Very low adoption for shell script installers — primarily used for container images and language packages. Bootstrapping problem: verifying the installer requires having cosign installed first.

### GPG / SHA-256 Checksums
The traditional approach: publish a detached signature or hash alongside the installer and document verification steps.

**Gap:** Requires a trustworthy channel to obtain the key separately from the script. Most users skip this step. Key management overhead is high.

---

## 6. Runtime Detection and Enforcement

### Falco (CNCF Graduated)
eBPF/kernel-module rule engine. Can alert on unexpected shell spawns, curl invocations, writes to sensitive files, and outbound connections from unexpected processes.

**Gap:** Alert-only by default. Primarily designed for cloud/container workloads, not developer laptops.

### Tetragon (Cilium / CNCF)
eBPF-based with enforcement capability — can block execution at the syscall level rather than just alerting. Kubernetes-aware.

**Gap:** Primarily Kubernetes-focused. Complex policy authoring. Not suited for developer workstation use.

---

## 7. Community Conventions

### Download, Inspect, Run
The standard recommendation: `curl -O install.sh && less install.sh && bash install.sh`. Eliminates partial execution and splits the connection (making server-side timing attacks harder).

**Gap:** Does not defeat a server that serves different content to different requests. Requires user competence to review arbitrary shell code.

### Function Wrapping
If a script's entire logic is enclosed in functions called only at the end, a partial download defines functions but does not execute them. Addresses the truncation/partial-execution risk specifically.

**Gap:** A discipline for script authors, not a tool for script consumers. Not widely enforced.

### Prefer Package Managers
Community consensus: use curl|bash only as a last-resort bootstrapper. Once a package manager is installed, use it exclusively.

---

## 8. Academic and Security Research

### Server-Side Detection of curl|bash (2018–2022)
Demonstrated that a server can reliably detect whether its output is being piped to bash versus just downloaded. Bash's line-buffered execution introduces measurable TCP timing delays that the server can observe. Proof-of-concept published at [m4tx/curl-bash-attack](https://github.com/m4tx/curl-bash-attack). **Critical implication:** a malicious server can serve a clean script to inspectors and a malicious one to runners, defeating the Download-Inspect-Run convention.

### SCORE: Static Script Malware Detection (arXiv 2411.08182, Nov 2024)
ML system using AST features and syntax highlighting for static detection of malicious shell/Python/Perl scripts. Achieves 81% higher true-positive rate than signature-based AV at 0.17% false-positive rate. Not yet a packaged tool.

### Building a Secure Software Supply Chain with GNU Guix (arXiv 2206.14606, 2022)
Documents how authenticated Git checkout + reproducible + bootstrappable builds together eliminate the implicit trust in binary seeds that package managers traditionally require. Deployed in production Guix.

### Evasive Techniques in Malicious Linux Shell Scripts (Uptycs, 2021)
Documents real-world attacker techniques: disabling monitoring agents, flushing firewall rules, base64 obfuscation, structuring scripts to evade static analysis. Context for why static analysis alone is insufficient.

---

## Key Observations

1. **No single tool solves the full problem.** The threat has multiple independent attack vectors — supply chain, MitM, truncation, server-side targeting, privilege escalation — and each existing tool addresses only a subset.

2. **The "inspect before running" convention is weaker than it appears.** A malicious server can detect the pipe and serve different content to the download versus the run, making inspection insufficient by itself (though still worth doing).

3. **The most complete mitigations require changing the install paradigm entirely.** Hermetic package managers (Nix, Guix) eliminate the attack surface, but at significant ecosystem and learning-curve cost.

4. **Purpose-built tooling is emerging (vet, Tirith) but has not reached mainstream adoption.** There is a clear gap for a tool that is both ergonomic and provides multi-layered defense.

5. **Kernel primitives (Landlock, seccomp-bpf, namespaces) are available for strong sandboxing but have no ready-made user-facing tool** for the specific use-case of running an untrusted installer script safely.

6. **Code signing infrastructure exists but is not widely adopted for shell scripts.** Sigstore/Cosign is the most promising technology but faces a bootstrapping problem and very low uptake in this domain.
