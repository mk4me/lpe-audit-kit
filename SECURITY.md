# Security Policy

## Reporting a vulnerability in this auditor

If you discover a security issue in `lpe-audit-kit` itself — for example,
the script behaves dangerously on certain inputs, leaks sensitive data, or
could be exploited to compromise the host running it — please report it
privately rather than opening a public issue.

**Contact:** Open a private security advisory via GitHub:
https://github.com/mk4me/lpe-audit-kit/security/advisories/new

Please include:
- Description of the issue
- Steps to reproduce
- Affected versions
- Suggested mitigation if you have one

I will acknowledge within a week and aim to release a fix within 30 days
for confirmed issues, depending on complexity.

## Reporting Linux kernel vulnerabilities

This is *not* the right place to report Linux kernel vulnerabilities.
For kernel issues, follow upstream coordinated disclosure:

- General kernel security: `security@kernel.org`
- Distribution coordination: `linux-distros@vs.openwall.org`
- See [Linux kernel security process](https://www.kernel.org/doc/html/latest/process/security-bugs.html)

## Scope

In scope:
- The audit scripts (`lpe-audit.sh`, `fleet-audit.sh`, `verify.sh`)
- Build/release artifacts on this repo
- CI configuration if it could leak secrets

Out of scope:
- Vulnerabilities in Linux kernel, sudo, AppArmor, etc. (report to those
  projects directly)
- Vulnerabilities in dependencies (`ssh`, `awk`, `bash`) — report upstream
- Issues in user environments not caused by this tool

## Supported versions

| Version | Supported |
|---|---|
| 1.x | Yes (current) |
| < 1.0 | No |

## Security model

This tool is designed to be:

1. **Read-only.** It does not modify system state. Mitigation commands are
   printed as text, never executed.
2. **No exploit code.** It detects exposure but does not attempt to verify
   exposure by triggering the bugs.
3. **Minimal privilege.** Works without root; sudo is optional and only
   improves visibility into kernel module status.
4. **Self-contained.** No network calls in the core audit (the `--check-patch`
   flag adds tracker URL printing but does not perform queries by default).
5. **Reviewable.** ~700 lines of POSIX shell, no minified or obfuscated code.
