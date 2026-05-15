# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-05-15

### Added
- **KeySign-Pwn** detection — `ptrace_may_access` mm=NULL bypass + `pidfd_getfd`
  primitive, fixed in mainline commit `31e62c2ebbfd` (Torvalds, 2026-05-14).
  Steals root-owned file descriptors from exiting setuid binaries before
  `exit_files()` runs. Real-world impact: leak `/etc/shadow` (via `chage`)
  and SSH host private keys (via `ssh-keysign`).
  - Status grading by `yama.ptrace_scope`: EXPOSED (0/1), PARTIAL (2),
    HARDENED (3), PATCHED (if distro changelog confirms backport),
    NOT_AFFECTED (kernel < 5.6, no `pidfd_getfd`)
  - Distro changelog check via `rpm -q --changelog` and dpkg
    `/usr/share/doc/linux-image-*/changelog.Debian.gz`
  - Setuid vector inventory (`ssh-keysign`, `chage`) reported as informational
    only; does NOT influence severity — the bug is in the kernel, not the
    binaries
- JSON schema bumped to `lpe-audit/1.2`
- Summary table row + recommended action with `ptrace_scope=2` interim
  mitigation
- 3 new test assertions (default-run mention, JSON key presence, schema bump)

### Changed
- Section counters in audit output: `[N/4]` → `[N/5]`
- Header documentation updated to describe info-disclosure nature of
  KeySign-Pwn vs. execution-LPE of the existing four bugs
- **CVE backfill** — Dirty Frag #1 and #2 now have official numbers:
  - Dirty Frag #1: `CVE-2026-43284` (patched 2026-05-08, mainline)
  - Dirty Frag #2: `CVE-2026-43500` (CVE reserved, NVD pending, no upstream patch)
- Dirty Frag recommended-action split into two blocks: #1 (apply update,
  IPsec mitigation as interim) vs #2 (still requires module blacklist
  while CVE-2026-43500 patch pending)

### Credit
- Disclosure: Qualys
- Public PoC: <https://github.com/0xdeadbeefnetwork/ssh-keysign-pwn>
- Pre-existing flag of FD-theft shape: Jann Horn (Project Zero), 2020-10-16

## [1.1.0] - 2026-05-08

### Added
- **No-install execution paths**: stream the audit script through `sh` or `ssh`
  without writing anything to disk
- `remote-audit.sh` — wrapper for SSH-based remote audit of a single host
  - Supports `--sudo`, `--json`, `--quiet`, custom port and key
  - `--remote-source` flag fetches script from GitHub on the fly
- `install.sh` — verified install with SHA256 check against published checksum
  - `--run` flag downloads, verifies, runs, and deletes
  - Falls back gracefully between `curl`/`wget` and `sha256sum`/`shasum`
- `docs/index.html` — landing page for GitHub Pages with all execution paths
- README: new "Run without installing anything" section with three patterns

### Changed
- Release tarball now includes `remote-audit.sh` and `install.sh`
- CI lints all five scripts (was three)

## [1.0.0] - 2026-05-07

### Added
- Initial public release
- `lpe-audit.sh` — POSIX-compatible single-host auditor
  - Copy Fail (CVE-2026-31431) detection via `algif_aead` module status
  - Dirty Frag #1 (xfrm-ESP) detection via `esp4`/`esp6` modules + userns posture
  - Dirty Frag #2 (RxRPC) detection via `rxrpc` module status
  - CrackArmor (CVE-2026-23268..23411) detection via AppArmor/sudo state
  - Container context detection (Docker, Podman, Kubernetes, LXC)
  - Userns posture reporting
  - Three output modes: human-readable, JSON, quiet
  - Standard exit codes (0=clean, 2=exposed, 3=error)
- `fleet-audit.sh` — parallel SSH wrapper for multi-host audits
  - Configurable concurrency and SSH options
  - Aggregated CSV matrix and pretty-printed report
  - Per-host JSON for downstream processing
- `verify.sh` — SHA256 integrity verification
- POSIX sh compatibility — tested on bash, dash, ash
- Tested on Ubuntu 18.04+, Debian 10+, RHEL 7+, AlmaLinux 8+, Fedora 36+,
  openSUSE 15+, Alpine 3.15+, Amazon Linux 2/2023
- Bilingual README (English + Polish)
- Apache 2.0 license

[Unreleased]: https://github.com/mk4me/lpe-audit-kit/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/mk4me/lpe-audit-kit/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/mk4me/lpe-audit-kit/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/mk4me/lpe-audit-kit/releases/tag/v1.0.0
