# Position

## What We Believe

The `curl | bash` pattern is not going away. It is convenient, universally understood, and deeply embedded in the software ecosystem. Security tools that require users to change their mental model or workflow substantially will not be adopted. A safer world requires meeting users where they are.

We believe that most harm from `curl | bash` is not caused by sophisticated, targeted attacks — it is caused by bugs, oversights, and opportunistic malware that a small amount of scrutiny would have caught. A tool that raises the floor for the common case is worth building, even if it cannot raise the ceiling for the adversarial case.

We also believe that security tools have an obligation to be honest. A script that passes all of `safesh`'s checks is not *safe* — it is *unsuspicious*. The difference matters, and we will not obscure it.

## What safesh Is

`safesh` is a drop-in replacement for `bash` in the `curl | bash` pattern:

```sh
curl -fsSL https://example.com/install.sh | safesh
```

It is a low-friction safety layer that interposes between a remote script and your shell. Its job is to:

- Prevent a class of common, avoidable harms before they happen
- Make the script's intent visible enough for an informed decision
- Leave a record of what ran

It is one layer of defense, not the only one.

## What safesh Is Not

**Not a sandbox.** `safesh` does not run scripts in an isolated environment by default. A script that passes through `safesh` executes with the same privileges and filesystem access it would have with plain `bash`. (Opt-in sandboxing may be offered as a flag for users who want stronger isolation.)

**Not a security guarantee.** A determined author can write a malicious script that passes every check `safesh` performs. A compromised server can detect that it is being scrutinized and behave differently. `safesh` does not and cannot prevent these scenarios.

**Not a replacement for judgment.** `safesh` can surface information and require acknowledgment. It cannot make the decision for you. Running scripts from untrusted sources carries inherent risk regardless of what tooling wraps them.

**Not a verifier of intent.** `safesh` can detect dangerous patterns. It cannot determine whether a pattern is malicious or legitimate. A script that runs `rm -rf ~/.config/myapp` before reinstalling is behaving reasonably. `safesh` may flag it; the user decides.

## Limitations We Accept

**Server-side evasion.** A malicious server can detect that its output is being piped to a shell process (via TCP timing) and serve a clean script to a downloader while serving a malicious one to a runner. `safesh` cannot prevent this. The Download-Inspect-Run convention partially mitigates it; we may support it but cannot make it foolproof.

**Obfuscation.** A script that encodes its payload in base64, fetches a second stage at runtime, or uses indirect evaluation can defeat static pattern detection. `safesh` will flag known obfuscation idioms but cannot guarantee detection of novel ones.

**Scope of analysis.** `safesh` analyzes the script it receives. It does not analyze binaries that the script downloads and executes, or the behavior of packages the script installs.

**No cryptographic verification.** `safesh` does not verify that a script comes from its claimed author. It does not integrate with Sigstore, GPG, or any signing infrastructure. Authenticating the origin of a script is a separate, unsolved problem in this space.

## Our Approach

**Friction as a design constraint.** Every check, warning, and prompt `safesh` adds has a cost. We will not add a check unless it catches a real class of harm and its false-positive rate is low enough to stay out of the user's way. Noise erodes trust and leads to prompt fatigue.

**Fail informatively, not silently.** When `safesh` detects something concerning, it should say clearly what it found, why it matters, and what the user's options are. It should not just block and refuse.

**Raise the floor for everyone.** The behaviors `safesh` enforces by default — buffering the full script, enforcing strict mode, flagging high-risk patterns — should benefit all users regardless of threat model. Stronger protections (sandboxing, mandatory confirmation, audit logging) are opt-in.

**Be honest about the model.** "Unsuspicious" is not "safe." `safesh` will communicate the difference in its output. We will not market this tool as a security solution to problems it does not solve.

**Complement, don't compete.** `safesh` is designed to work alongside existing tools: ShellCheck for linting, package managers for managed installs, sandboxing tools for high-risk scripts. We will integrate with them where it makes sense rather than reinventing them.

## Who This Is For

`safesh` targets developers on interactive workstations — macOS, Linux desktops, and WSL2. This is the environment where `curl | bash` is a daily habit: bootstrapping a new machine, installing a language version manager, pulling in a dev tool. A human is present, a TTY is available, and the question "should I run this?" can actually be answered interactively.

Server environments are explicitly out of scope. Production systems, CI/CD pipelines, and cloud provisioning scripts have different requirements — versioned, audited, repeatable installs — that are better served by package managers, configuration management tools, or container images. `safesh` is not designed for those contexts and makes no claims about them.

`safesh` is primarily for developers and engineers who:

- Regularly install developer tooling via scripts from the internet
- Are not security specialists but have a reasonable concern about what they are running
- Want protection against mistakes and opportunistic threats without significant workflow changes

It is not primarily designed for:
- Server provisioning or automated infrastructure management
- CI/CD pipelines (though a non-interactive mode may be supported in the future)
- High-security environments that require hermetic, verified, reproducible installs
- Users who need strong isolation guarantees (firejail, bubblewrap, or containers are better fits)

## Summary

`safesh` makes the common case meaningfully safer with minimal friction. It is honest about what it can and cannot do. It is one tool in a larger defense-in-depth posture, not a complete solution. We think that is enough to be worth building.
