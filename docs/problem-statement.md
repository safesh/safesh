# Problem Statement

## The `curl | bash` Problem

Installing software by piping a remote script directly into a shell has become a widespread convention:

```sh
curl -fsSL https://example.com/install.sh | bash
```

This pattern is convenient but inherently unsafe. The user surrenders control at the moment of execution, with no opportunity to inspect, verify, or constrain what runs on their machine.

## Risks

### 1. Malicious Content
A script served from a remote URL can contain intentionally harmful commands. The server can serve different content to different users — targeting by IP, user-agent, or timing — so reviewing the script URL offers no real guarantee about what will execute.

### 2. Destructive Bugs
Unintentional mistakes in install scripts can cause irreversible damage. A mistyped path in a cleanup step, for example, can silently wipe important directories.

### 3. Unset Variable Expansion
Shell scripts that do not enforce `set -u` are vulnerable to silent variable expansion bugs. A common pattern:

```sh
rm -rf "$PREFIX/"
```

...becomes `rm -rf /` if `PREFIX` is unset. These bugs are easy to introduce, hard to spot in review, and catastrophic in effect.

### 4. Privilege Escalation Without Oversight
Scripts are frequently piped to `sudo bash`, granting root access to code that was never audited. All of the above risks are amplified accordingly.

### 5. Scope Creep Beyond Installation
Install scripts routinely do more than install software. They may modify shell profiles, add cron jobs, register services, or phone home — often without disclosure.

### 6. No Audit Trail
Piped execution leaves no record of what ran. Post-incident forensics is difficult or impossible.

### 7. No Dry Run
There is no standard way to preview the effects of a script without executing it. The only option is to read the source carefully — which most users do not do.

### 8. Supply Chain and MITM Exposure
Even HTTPS-served scripts can be compromised at the origin, through a hijacked CDN, or via a dependency the script itself fetches at runtime.

## Summary

The `curl | bash` pattern trades safety for convenience in a way that is rarely made explicit to users. Each execution is a blind trust exercise: trust in the author, the server, the network, and the script's own correctness — all at once, with no fallback if any of those fail.

A safer alternative should make intent visible, execution auditable, and destructive actions preventable — without requiring users to abandon the convenience of scriptable installs entirely.
