# lpe-audit-kit

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Shell](https://img.shields.io/badge/shell-POSIX%20sh-green.svg)](#requirements)
[![CI](https://github.com/mk4me/lpe-audit-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/mk4me/lpe-audit-kit/actions)

> **Portable read-only audit toolkit for the Q1–Q2 2026 Linux page-cache write LPE vulnerability cluster.**

Detects exposure to four related kernel logic bugs that allow unprivileged
local users to escalate to root on most Linux systems released since 2017.
Read-only — does not modify system state. Mitigation commands are printed
as suggestions, never executed.

## Vulnerabilities covered

| Name | CVE | Component | Patch status |
|---|---|---|---|
| **Copy Fail** | [CVE-2026-31431](https://www.cve.org/CVERecord?id=CVE-2026-31431) | `algif_aead` / `authencesn` | Patched late April 2026 |
| **Dirty Frag #1** | [CVE-2026-43284](https://www.cve.org/CVERecord?id=CVE-2026-43284) | `xfrm-ESP` page-cache write | Patched 2026-05-08 |
| **Dirty Frag #2** | [CVE-2026-43500](https://www.cve.org/CVERecord?id=CVE-2026-43500) | `RxRPC` page-cache write | CVE reserved, **NVD pending, no upstream patch** |
| **CrackArmor** | [CVE-2026-23268..23411](https://ubuntu.com/security/vulnerabilities/crackarmor) | AppArmor confused deputy | Patched March 2026 |
| **KeySign-Pwn** | pending | `ptrace_may_access` mm=NULL + `pidfd_getfd` | Mainline `31e62c2ebbfd` (2026-05-14); distro backports pending |

The first four share a common bug class: a 4-byte controlled write into the
kernel page cache of any readable file, used to modify the in-memory copy of
setuid binaries (`/usr/bin/su`, `/usr/bin/sudo`) at execution time.
Deterministic,
no race condition, same exploit works across distributions.

**KeySign-Pwn is a different class** — info-disclosure, not execution. It
abuses a window in `do_exit()` where `task->mm` is already NULL but file
descriptors are still alive, letting a same-uid attacker steal fds via
`pidfd_getfd(2)`. When the victim is a setuid binary that opened a root-owned
file before dropping privileges (`ssh-keysign` → SSH host keys; `chage` →
`/etc/shadow`), the result is credential leakage that trivially escalates
to root via offline cracking or host-key impersonation. The setuid binaries
are *vectors*, not the bug; the bug is in the kernel and removing the
binaries does not fix it.

## Run without installing anything

Three ways to audit a host without leaving any files behind.

### Local host (current machine)

Stream the script through a shell — script runs from memory, nothing on disk:

```bash
curl -fsSL https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main/lpe-audit.sh | sh
```

With options (note the `-s --` to forward flags to the script, not to `sh`):

```bash
curl -fsSL https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main/lpe-audit.sh | sh -s -- --json
curl -fsSL https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main/lpe-audit.sh | sh -s -- --quiet
```

### Remote host (over SSH, no copy)

The same script streamed through SSH stdin — nothing is written to the remote
filesystem either:

```bash
curl -fsSL https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main/lpe-audit.sh \
    | ssh user@host 'bash -s'

# With sudo for full kernel module visibility:
curl -fsSL https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main/lpe-audit.sh \
    | ssh user@host 'sudo bash -s'

# JSON output for downstream processing:
curl -fsSL https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main/lpe-audit.sh \
    | ssh user@host 'bash -s -- --json' > host.json
```

### Verified install (recommended for production)

`curl | sh` is convenient but skips integrity verification. For a verified
download that checks SHA256 against the published checksum before running:

```bash
# Download, verify, and run (no file left behind)
curl -fsSL https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main/install.sh | sh -s -- --run

# Download, verify, and save for later
curl -fsSL https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main/install.sh | sh
./lpe-audit.sh
```

The `install.sh` wrapper fetches `SHA256SUMS` from the same repo, verifies the
script matches the published checksum, and only then runs it. Use this when
you need defense-in-depth against compromised mirrors or MITM.

## Quick start (with local clone)

### Single host

```bash
curl -fsSL https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main/lpe-audit.sh -o lpe-audit.sh
chmod +x lpe-audit.sh
./lpe-audit.sh
```

Or clone the repo:

```bash
git clone https://github.com/mk4me/lpe-audit-kit.git
cd lpe-audit-kit
./lpe-audit.sh
```

### Remote host (single)

```bash
git clone https://github.com/mk4me/lpe-audit-kit.git
cd lpe-audit-kit
./remote-audit.sh --sudo --json admin@host > audit.json
```

Or in one line without cloning anything (see *Run without installing anything*
above).

### Multiple hosts (fleet)

```bash
git clone https://github.com/mk4me/lpe-audit-kit.git
cd lpe-audit-kit
cp hosts.txt.example hosts.txt
$EDITOR hosts.txt
./fleet-audit.sh -i hosts.txt -c 16 --sudo
```

Output appears in `fleet-results-<timestamp>/`:
- `fleet-matrix.csv` — host × CVE status table
- `fleet-report.txt` — pretty summary
- `<host>.json` — per-host detailed output

## Output modes

```bash
./lpe-audit.sh                  # Human-readable colored report (default)
./lpe-audit.sh --json           # Machine-readable JSON
./lpe-audit.sh --quiet          # Summary line only
./lpe-audit.sh --check-patch    # Print distro CVE tracker URLs
./lpe-audit.sh --version
./lpe-audit.sh --help
```

## Status values

| Status | Meaning |
|---|---|
| `EXPOSED` | Exploitable now, immediate action required |
| `LATENT` | Module not loaded but autoloadable |
| `PARTIAL` | Mitigation present but bypassable |
| `HARDENED` | Module loaded, userns gate closed |
| `MITIGATED` | Blacklisted + not loaded |
| `LIKELY_OK` | No module evidence; verify kernel patch |
| `NOT_PRESENT` | Module not in kernel build |
| `NOT_AFFECTED` | Kernel/distro out of scope |

Exit codes: `0` = no exposure, `2` = at least one `EXPOSED`, `3` = script error.

## What it checks

| Check | Method |
|---|---|
| Copy Fail | kernel ≥4.14 + `algif_aead` module status + blacklist files |
| Dirty Frag #1 | kernel ≥4.10 + `esp4`/`esp6` modules + userns gating + AppArmor restrict |
| Dirty Frag #2 | kernel ≥6.5 + `rxrpc` module |
| CrackArmor | AppArmor enabled vs SELinux + sudo/sudo-rs detection |
| KeySign-Pwn | kernel ≥5.6 (`pidfd_getfd`) + distro changelog grep for `31e62c2ebbfd` + `yama.ptrace_scope` posture |
| Container context | `/proc/1/cgroup`, `/.dockerenv`, runtimes installed |
| Userns posture | `/proc/sys/kernel/unprivileged_userns_clone`, `max_user_namespaces`, AppArmor restrict |

## Requirements

**Local machine** (running the scripts):
- POSIX-compatible shell (`sh`, `bash`, `dash`, `ash`)
- Standard userland: `awk`, `grep`, `sed`, `cat`, `uname`
- Fleet runner additionally needs: `ssh`, `scp`, `xargs`
- Optional: `jq` for JSON aggregation, `column` for table formatting

**Remote hosts** (audited):
- Same as local machine
- No additional packages required
- Root not required (but `sudo` improves accuracy)

## Tested distributions

Ubuntu 18.04+, Debian 10+, RHEL/CentOS 7+, AlmaLinux 8+, Rocky Linux 8+,
Fedora 36+, openSUSE Leap 15+, Alpine 3.15+, Amazon Linux 2/2023.

## Fleet runner options

```text
Usage: ./fleet-audit.sh -i hosts.txt [options]

Required:
  -i FILE          Hosts file (one host per line)

Options:
  -c N             Parallel SSH connections (default: 8)
  -u USER          Default SSH user (default: $USER)
  -k KEYFILE       SSH private key file
  -o DIR           Output directory (default: ./fleet-results-<timestamp>)
  -t SECONDS       SSH connect timeout (default: 15)
  --sudo           Run remote audit with sudo -n (passwordless required)
  --check-patch    Pass --check-patch to remote audit
  -h, --help       This help
```

Hosts file accepts: `host`, `user@host`, `host:port`, `user@host:port`. Lines
starting with `#` and blank lines are ignored.

## Caveats

1. **Patch detection is heuristic.** The script checks module presence,
   blacklists, and userns posture, but cannot directly verify if your kernel
   includes a specific patch commit. Authoritative source is your distro's
   CVE tracker — links are printed at the end of the report.

2. **`sudo` improves accuracy.** Without sudo, `modinfo` may not see modules
   in `/lib/modules/.../kernel/` if directories have restrictive permissions.

3. **Dirty Frag has no patch.** Mitigation requires module blacklisting,
   which **disables IPsec (esp4/esp6) and AFS/RxRPC**. Verify your VPN/AFS
   needs before applying.

## Mitigation reference

```bash
# Copy Fail (interim, until kernel update applied)
echo 'install algif_aead /bin/false' | sudo tee /etc/modprobe.d/disable-algif.conf
sudo rmmod algif_aead 2>/dev/null || true

# Dirty Frag (NO PATCH - this is your only option)
sudo tee /etc/modprobe.d/dirtyfrag.conf <<'EOF'
install esp4 /bin/false
install esp6 /bin/false
install rxrpc /bin/false
EOF
sudo rmmod esp4 esp6 rxrpc 2>/dev/null || true

# CrackArmor - apply distro kernel + sudo + util-linux updates
```

## Verifying integrity

The repo includes `SHA256SUMS` for the script files:

```bash
./verify.sh
# or manually:
sha256sum -c SHA256SUMS
```

For releases, signed tarballs are attached to GitHub Releases.

## How the scripts decide

For each vulnerability the audit follows the same logic tree:

```
   ┌─ Kernel out of scope?         → NOT_AFFECTED
   ├─ Module blacklisted+unloaded? → MITIGATED
   ├─ Module loaded?
   │   ├─ Userns/gate closed?      → HARDENED
   │   ├─ AppArmor restrict?       → PARTIAL  (CrackArmor bypass possible)
   │   └─ otherwise                → EXPOSED
   ├─ Module on disk only?         → LATENT  (autoloadable)
   └─ Module absent?               → NOT_PRESENT
```

This is heuristic by design. A `LIKELY_OK` or `NOT_PRESENT` does not prove
your kernel is patched against Copy Fail or CrackArmor — that requires
checking your distro's CVE tracker. The audit narrows the search; it does
not replace it.

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports and feature
requests via [GitHub Issues](https://github.com/mk4me/lpe-audit-kit/issues).

For security issues with the auditor itself (not with Linux kernel):
see [SECURITY.md](SECURITY.md).

## References

- Dirty Frag origin: https://github.com/V4bel/dirtyfrag
- Copy Fail technical writeup (Theori): https://xint.io/blog/copy-fail-linux-distributions
- CrackArmor advisory (Qualys): https://blog.qualys.com/vulnerabilities-threat-research/2026/03/12/crackarmor-critical-apparmor-flaws-enable-local-privilege-escalation-to-root
- CISA KEV (Copy Fail): https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Ubuntu CrackArmor advisory: https://ubuntu.com/security/vulnerabilities/crackarmor

## License

[Apache License 2.0](LICENSE) — Copyright © 2026 Marek Kulbacki

Vulnerability research credits — see [NOTICE](NOTICE).

---

## Polski

Przenośny zestaw narzędzi do audytu (read-only) ekspozycji na klaster
podatności Linux page-cache write z Q1–Q2 2026.

### Szybki start

**Bez instalacji** — tylko wykonanie:

```bash
# Lokalny host
curl -fsSL https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main/lpe-audit.sh | sh

# Zdalny host przez SSH (nic nie zostaje)
curl -fsSL https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main/lpe-audit.sh \
    | ssh user@host 'sudo bash -s'

# Z weryfikacją SHA256 (zalecane dla produkcji)
curl -fsSL https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main/install.sh | sh -s -- --run
```

**Z lokalnym klonem** (gdy masz dużo hostów):

```bash
git clone https://github.com/mk4me/lpe-audit-kit.git
cd lpe-audit-kit
./lpe-audit.sh                        # pojedynczy host
./remote-audit.sh --sudo admin@host   # zdalny host przez SSH
./fleet-audit.sh -i hosts.txt         # cała flota
```

### Co sprawdza

Cztery podatności umożliwiające lokalnemu użytkownikowi bez uprawnień
zdobycie roota na większości systemów Linux od 2017:
- **Copy Fail** (CVE-2026-31431) — załatane
- **Dirty Frag #1** (CVE-2026-43284, xfrm-ESP) — załatane 2026-05-08
- **Dirty Frag #2** (CVE-2026-43500, RxRPC) — **CVE reserved, brak łatki upstream**
- **CrackArmor** (CVE-2026-23268..23411) — załatane
- **KeySign-Pwn** (info-disclosure, pending CVE) — łatka w mainline od 2026-05-14, dystrybucje **bez backportu**

Audyt jest heurystyczny: sprawdza obecność modułów kernela, blacklisty,
posture userns, kontekst kontenera. Autorytatywne źródło wciąż to tracker
CVE Twojej dystrybucji (linki w raporcie).

### Tryby

```bash
./lpe-audit.sh                # raport czytelny z kolorami
./lpe-audit.sh --json         # JSON dla automatyzacji
./lpe-audit.sh --quiet        # tylko podsumowanie
```

Pełna dokumentacja powyżej w sekcji English.
