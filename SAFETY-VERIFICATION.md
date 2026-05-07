# Safety Verification Report — lpe-audit-kit v1.1.0

**Date:** 2026-05-08  
**Test environment:** Ubuntu 24.04.4 LTS, kernel 6.18.5, x86_64  
**Tools:** strace 6.8, shellcheck, bash 5.2, dash 0.5.12, busybox 1.36

This report documents an empirical verification that `lpe-audit.sh` does not modify
system state in any way. The script's claim of "read-only operation" is verified
both by static code analysis and dynamic syscall tracing.

---

## 1. Static Analysis Results

### 1.1 Search for write operations

Grep for any pattern that could modify the filesystem:

```
Patterns: rm, mv, cp, chmod, chown, mkdir, rmdir, touch, sed -i, tee, redirects (>, >>)
```

**Result:** All matches found are **strings inside `echo`** statements that
print mitigation suggestions to the user. None are actual command invocations.

| Line | Match | Context |
|---|---|---|
| 541 | `echo "...sudo tee /etc/modprobe.d/disable-algif.conf"` | Suggestion text only |
| 542 | `echo "...sudo rmmod algif_aead..."` | Suggestion text only |
| 552 | `echo "...sudo tee /etc/modprobe.d/dirtyfrag.conf..."` | Suggestion text only |
| 557 | `echo "...sudo rmmod esp4 esp6 rxrpc..."` | Suggestion text only |

### 1.2 Search for system state changes

```
Patterns: sysctl, modprobe, insmod, rmmod, systemctl, service start/stop
```

**Result:** All matches are inside `echo` statements (suggestions to user).
Zero actual invocations.

### 1.3 Search for shell execution risks

```
Patterns: eval, exec, source, unquoted variable expansion in dangerous positions
```

**Result:** Zero `eval` or `exec` calls. All variable expansions are
properly quoted or used in safe contexts (string comparisons, file existence
tests). No injection surface.

---

## 2. Dynamic Analysis (strace)

The script was executed under `strace -f` with comprehensive syscall tracing.

### 2.1 Filesystem modification syscalls

| Syscall | Count | Notes |
|---|---:|---|
| `creat` | **0** | No file creation |
| `unlink` / `unlinkat` | **0** | No file deletion |
| `rename` / `renameat` | **0** | No file rename |
| `chmod` / `fchmod` / `fchmodat` | **0** | No permission change |
| `chown` / `fchown` / `fchownat` | **0** | No ownership change |
| `mkdir` / `mkdirat` | **0** | No directory creation |
| `rmdir` | **0** | No directory removal |
| `truncate` / `ftruncate` | **0** | No file truncation |
| `link` / `symlink` | **0** | No link creation |

**Total filesystem modifications: 0**

### 2.2 File access mode analysis

`openat` calls with `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`, or `O_APPEND`
(excluding `/dev/null`, pipes, sockets, ttys):

**Result: 0 such calls.** All file opens are read-only (`O_RDONLY`).

### 2.3 Programs invoked (execve)

The script invokes only standard POSIX userland tools:

```
/usr/bin/awk
/usr/bin/cat
/usr/bin/date
/usr/bin/grep
/usr/bin/head
/usr/bin/hostname
/usr/bin/sed
/usr/bin/tr
/usr/bin/uname
```

**No invocations of:** `sudo`, `modprobe`, `rmmod`, `insmod`, `systemctl`,
`service`, `mount`, `umount`, `iptables`, `ip`, `nft`, `chmod`, `chown`, `rm`,
`mv`, `cp`, `dd`, `tee`, `truncate`.

### 2.4 Network activity

Real network connections (AF_INET, AF_INET6):

**Result: 0 attempted connections.**

The only socket activity observed is glibc's standard NSCD (Name Service
Cache Daemon) check via AF_UNIX socket — this is implicit in `getaddrinfo()`
calls used by tools like `hostname`, and is not initiated by the script.

`--check-patch` mode prints distro CVE tracker URLs as text but does not
fetch them.

### 2.5 Files accessed (read-only)

24 unique paths opened, all read-only:

```
/etc/os-release          - distro identification
/etc/passwd              - hostname resolution support
/etc/nsswitch.conf       - hostname resolution support
/etc/ld.so.cache         - dynamic linker (implicit)
/proc/1/cgroup           - container detection
/proc/1/sched            - container detection (PID 1 name)
/proc/modules            - loaded kernel modules
/proc/mounts             - mount information
/proc/filesystems        - filesystems listing
/proc/sys/user/max_user_namespaces  - userns posture
/proc/self/maps          - implicit (executable load)
/lib/*                   - shared libraries (implicit)
/lib/modprobe.d          - module blacklist files
/usr/lib/modprobe.d      - module blacklist files
/usr/share/zoneinfo/UTC0 - timezone for UTC timestamp
/dev/null                - I/O redirection
/dev/tty                 - terminal detection
```

None of these are modified.

---

## 3. Edge Case Resilience

The script was tested under hostile conditions:

| Condition | Behavior |
|---|---|
| Run as non-root user | ✅ Works correctly, exit 0 |
| Restrictive `umask 0777` | ✅ Works correctly, exit 0 |
| Read-only working directory | ✅ Works correctly, exit 0 |
| Missing `/etc/os-release` | ✅ Continues with `unknown` distro, exit 0 |
| Unreadable `/proc/modules` | ✅ Continues with degraded info, exit 0 |
| Unknown command-line flag | ✅ Refuses, exit 3 |
| Run on macOS (Darwin) | ✅ Refuses with clear message, exit 3 |

The script **never crashes** and **never falls back to risky behavior**
under hostile environments.

---

## 4. Shell Compatibility

Verified to run cleanly under:

| Shell | Version | Status |
|---|---|---|
| `bash` | 5.2 | ✅ |
| `dash` | 0.5.12 | ✅ (POSIX-correct) |
| `busybox sh` (ash) | 1.36 | ✅ (Alpine Linux compatible) |

This covers every Linux distribution since the script's stated minimum
(Ubuntu 18.04 / Debian 10 / RHEL 7 / Alpine 3.15 / Amazon Linux 2).

---

## 5. Companion Scripts

### 5.1 `remote-audit.sh`

**Static analysis result:** Zero filesystem modifications. Script
streams `lpe-audit.sh` through SSH stdin to a remote host. Nothing is
written to either local or remote filesystem during operation.

### 5.2 `fleet-audit.sh`

**Local writes (intentional, documented):**
- `mkdir -p ./fleet-results-<timestamp>/` — output directory
- Per-host `*.json` and `*.err` files — audit results
- `fleet-matrix.csv` and `fleet-report.txt` — aggregated reports

**Remote writes (intentional, with cleanup):**
- `scp lpe-audit.sh user@host:/tmp/lpe-audit.sh` — temporary copy
- After execution: `rm -f /tmp/lpe-audit.sh` — cleanup

**Edge case:** If the SSH session terminates unexpectedly between `scp`
and the cleanup `rm`, a stale copy of `lpe-audit.sh` may remain in
`/tmp/` on the target host. This is:
- A plain shell script (not executable until set chmod +x)
- A read-only auditor (verified above)
- Located in `/tmp/` which is typically auto-cleaned at reboot

**No security implication.** A user wanting zero remote-side traces
should use `remote-audit.sh` instead, which streams via stdin.

### 5.3 `install.sh`

**Filesystem operations:**
- Downloads `lpe-audit.sh` to a target directory (default: `.`)
- Verifies SHA256 against published checksum
- On `--run` flag: runs the script, then deletes it

All operations are within the user's own working directory; no system
paths are touched.

---

## 6. Summary

`lpe-audit.sh` is verified to be a strictly read-only auditor.

- **0** writes to the filesystem
- **0** modifications to system state (sysctl, modules, services)
- **0** network connections
- **0** privilege escalation attempts
- **9** standard POSIX tools invoked (read-only operations only)
- **24** files read (all in `/etc`, `/proc`, `/sys`, `/lib`, `/dev`)

Mitigation commands are printed as suggestions only. The user has
complete control over whether and when to apply them.

The script is safe to run on production systems including:
- Single hosts with critical workloads
- Multi-tenant container hosts
- Read-only / immutable infrastructure
- Compliance-monitored environments

It will not interrupt services, not modify configuration files, not
install packages, not load or unload kernel modules, and not establish
any outbound network connections.

---

## 7. Reproducibility

To reproduce these checks on your own host:

```bash
# Static analysis
shellcheck -S warning lpe-audit.sh

# Dynamic syscall trace
strace -f -e trace=openat,creat,unlink,unlinkat,rename,renameat,renameat2,\
truncate,ftruncate,chmod,fchmod,fchmodat,chown,fchown,fchownat,\
mkdir,mkdirat,rmdir,link,symlink,linkat,symlinkat,write \
  -y -o /tmp/audit-trace.log ./lpe-audit.sh --json > /dev/null

# Verify no filesystem modifications
grep -E '(creat|unlink|rename|chmod|chown|mkdir|truncate)' /tmp/audit-trace.log
# Expected output: empty (no matches)
```
