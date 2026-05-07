#!/usr/bin/env bash
#
# lpe-audit.sh - Portable Linux LPE vulnerability audit
# =====================================================
# Audits exposure to the Q1-Q2 2026 page-cache write LPE cluster:
#
#   Copy Fail        CVE-2026-31431            (algif_aead, patched)
#   Dirty Frag #1    no-CVE - embargo broken   (xfrm-ESP, NO PATCH)
#   Dirty Frag #2    no-CVE - embargo broken   (RxRPC, NO PATCH)
#   CrackArmor       CVE-2026-23268..23411     (AppArmor, patched)
#
# Read-only. Does not modify system state. Mitigation commands are
# printed as suggestions, never executed.
#
# Tested on: Ubuntu 18.04+, Debian 10+, RHEL 7+, AlmaLinux 8+,
#            Fedora 36+, openSUSE 15+, Alpine 3.15+, Amazon Linux 2/2023
#
# Usage:
#   ./lpe-audit.sh                  # human-readable report
#   ./lpe-audit.sh --json           # machine-readable JSON
#   ./lpe-audit.sh --quiet          # only summary + non-zero exit if exposed
#   ./lpe-audit.sh --check-patch    # additionally query distro CVE tracker (needs curl)
#
# Exit codes:
#   0  - no exposure detected
#   2  - one or more components EXPOSED
#   3  - script error / unsupported environment
#
# License: public domain. No warranty. Use at your own risk.
# Source:  https://github.com/V4bel/dirtyfrag (Dirty Frag origin)
#          https://xint.io/blog/copy-fail-linux-distributions (Copy Fail)
#          https://blog.qualys.com (CrackArmor)

set -u

VERSION="1.0"
LANG=C
LC_ALL=C
export LANG LC_ALL

# ---------- argument parsing ----------
JSON_MODE=0
QUIET_MODE=0
CHECK_PATCH=0

for arg in "$@"; do
    case "$arg" in
        --json)         JSON_MODE=1 ;;
        --quiet)        QUIET_MODE=1 ;;
        --check-patch)  CHECK_PATCH=1 ;;
        -h|--help)
            sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        --version)
            echo "lpe-audit.sh v$VERSION"
            exit 0 ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 3 ;;
    esac
done

# ---------- terminal colors (only if interactive + not JSON) ----------
if [ -t 1 ] && [ $JSON_MODE -eq 0 ]; then
    RED=$'\033[0;31m'; YEL=$'\033[0;33m'; GRN=$'\033[0;32m'
    BLU=$'\033[0;34m'; DIM=$'\033[2m';   BLD=$'\033[1m';   RST=$'\033[0m'
else
    RED=""; YEL=""; GRN=""; BLU=""; DIM=""; BLD=""; RST=""
fi

# ---------- portable findings store (no associative arrays for /bin/sh compat) ----------
FINDINGS=""    # newline-separated "key|status|detail"

record() {
    # $1=key $2=status $3=detail (may contain spaces, no newlines)
    local d
    d=$(echo "$3" | tr '\n' ' ')
    FINDINGS="${FINDINGS}${1}|${2}|${d}
"
}

get_finding_status() {
    echo "$FINDINGS" | awk -F'|' -v k="$1" '$1==k {print $2; exit}'
}
get_finding_detail() {
    echo "$FINDINGS" | awk -F'|' -v k="$1" '$1==k {for(i=3;i<=NF;i++) printf "%s%s",$i,(i<NF?"|":""); print ""; exit}'
}

# ---------- output helpers ----------
say()    { [ $JSON_MODE -eq 0 ] && [ $QUIET_MODE -eq 0 ] && printf '%s\n' "$*"; }
header() { [ $JSON_MODE -eq 0 ] && [ $QUIET_MODE -eq 0 ] && printf '\n%s%s=== %s ===%s\n' "$BLD" "$BLU" "$*" "$RST"; }
ok()     { [ $JSON_MODE -eq 0 ] && [ $QUIET_MODE -eq 0 ] && printf '  %s[OK]%s    %s\n'   "$GRN" "$RST" "$*"; }
warn()   { [ $JSON_MODE -eq 0 ] && [ $QUIET_MODE -eq 0 ] && printf '  %s[WARN]%s  %s\n'   "$YEL" "$RST" "$*"; }
vuln()   { [ $JSON_MODE -eq 0 ] && [ $QUIET_MODE -eq 0 ] && printf '  %s[VULN]%s  %s\n'   "$RED" "$RST" "$*"; }
info()   { [ $JSON_MODE -eq 0 ] && [ $QUIET_MODE -eq 0 ] && printf '  %s[info]%s  %s\n'   "$DIM" "$RST" "$*"; }

# ---------- portable kernel version comparison ----------
# Return 0 if $1 >= $2, else 1. Strips non-numeric suffixes per component.
ver_ge() {
    # shellcheck disable=SC2034
    local a_arr b_arr
    a=$(echo "$1" | tr '.' ' ')
    b=$(echo "$2" | tr '.' ' ')
    set -- $a
    a_arr="$*"
    # shellcheck disable=SC2086
    set -- $b
    b_arr="$*"

    # Use awk for robust component comparison
    awk -v A="$a_arr" -v B="$b_arr" 'BEGIN {
        na = split(A, aa, " "); nb = split(B, bb, " ")
        n = (na > nb) ? na : nb
        for (i = 1; i <= n; i++) {
            av = aa[i]; bv = bb[i]
            gsub(/[^0-9].*/, "", av); gsub(/[^0-9].*/, "", bv)
            if (av == "") av = 0; if (bv == "") bv = 0
            av += 0; bv += 0
            if (av > bv) exit 0
            if (av < bv) exit 1
        }
        exit 0
    }'
}

# ---------- check we have minimal tools ----------
for tool in awk grep sed cat uname; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required tool missing: $tool" >&2
        exit 3
    fi
done

# We're not Linux?
case "$(uname -s)" in
    Linux) ;;
    *) echo "This script only runs on Linux (uname=$(uname -s))" >&2; exit 3 ;;
esac

# ---------- 0. system identification ----------
header "System identification"

KERNEL=$(uname -r)
KERNEL_BASE=$(echo "$KERNEL" | sed 's/-.*//' | sed 's/+.*//')
ARCH=$(uname -m)
HOSTNAME=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "unknown")

DISTRO_ID="unknown"; DISTRO_VER="unknown"; DISTRO_NAME="unknown"; DISTRO_FAMILY="unknown"
if [ -r /etc/os-release ]; then
    # Source-style read but POSIX-safe
    DISTRO_ID=$(awk -F= '/^ID=/{gsub(/"/,"",$2); print $2; exit}' /etc/os-release)
    DISTRO_VER=$(awk -F= '/^VERSION_ID=/{gsub(/"/,"",$2); print $2; exit}' /etc/os-release)
    DISTRO_NAME=$(awk -F= '/^PRETTY_NAME=/{gsub(/"/,"",$2); print $2; exit}' /etc/os-release)
    ID_LIKE=$(awk -F= '/^ID_LIKE=/{gsub(/"/,"",$2); print $2; exit}' /etc/os-release)
fi

# Determine distro family (for CVE tracker queries)
case "${DISTRO_ID:-}${ID_LIKE:-}" in
    *ubuntu*|*debian*) DISTRO_FAMILY="debian" ;;
    *rhel*|*centos*|*almalinux*|*rocky*|*fedora*|*ol*|*amzn*) DISTRO_FAMILY="rhel" ;;
    *suse*) DISTRO_FAMILY="suse" ;;
    *alpine*) DISTRO_FAMILY="alpine" ;;
    *arch*) DISTRO_FAMILY="arch" ;;
esac

info "Host:        $HOSTNAME"
info "Kernel:      $KERNEL  (base $KERNEL_BASE, arch $ARCH)"
info "Distro:      ${DISTRO_NAME:-unknown}  (family: $DISTRO_FAMILY)"

record "system.kernel"      "INFO" "$KERNEL"
record "system.kernel_base" "INFO" "$KERNEL_BASE"
record "system.distro"      "INFO" "${DISTRO_NAME:-unknown}"
record "system.distro_id"   "INFO" "${DISTRO_ID:-unknown}"
record "system.distro_ver"  "INFO" "${DISTRO_VER:-unknown}"
record "system.family"      "INFO" "$DISTRO_FAMILY"
record "system.arch"        "INFO" "$ARCH"
record "system.hostname"    "INFO" "$HOSTNAME"

# ---------- helper: module status ----------
# Sets MOD_LOADED, MOD_AVAILABLE, MOD_BLACKLISTED globals
check_module() {
    local mod="$1"
    MOD_LOADED=0
    MOD_AVAILABLE=0
    MOD_BLACKLISTED=0

    [ -d "/sys/module/$mod" ] && MOD_LOADED=1
    if ! grep -q "^${mod} " /proc/modules 2>/dev/null; then
        :
    else
        MOD_LOADED=1
    fi

    if command -v modinfo >/dev/null 2>&1; then
        modinfo "$mod" >/dev/null 2>&1 && MOD_AVAILABLE=1
    else
        # Fallback: search /lib/modules for .ko file
        if [ -d "/lib/modules/$KERNEL" ]; then
            find "/lib/modules/$KERNEL" -name "${mod}.ko*" 2>/dev/null | grep -q . && MOD_AVAILABLE=1
        fi
    fi

    # Check blacklists in standard locations
    for dir in /etc/modprobe.d /usr/lib/modprobe.d /run/modprobe.d /lib/modprobe.d; do
        [ -d "$dir" ] || continue
        if grep -rqsE "^[[:space:]]*(install|blacklist)[[:space:]]+${mod}([[:space:]]|$)" "$dir" 2>/dev/null; then
            MOD_BLACKLISTED=1
            break
        fi
    done
}

# ---------- helper: userns posture ----------
USERNS_RESTRICTED=0
USERNS_DETAIL=""
if [ -r /proc/sys/kernel/unprivileged_userns_clone ]; then
    UUC=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)
    USERNS_DETAIL="${USERNS_DETAIL}unprivileged_userns_clone=$UUC "
    [ "$UUC" = "0" ] && USERNS_RESTRICTED=1
fi
if [ -r /proc/sys/user/max_user_namespaces ]; then
    MAXUNS=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null)
    USERNS_DETAIL="${USERNS_DETAIL}max_user_namespaces=$MAXUNS "
    [ "$MAXUNS" = "0" ] && USERNS_RESTRICTED=1
fi
APPARMOR_USERNS_RESTRICT=0
if [ -r /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
    AURU=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)
    USERNS_DETAIL="${USERNS_DETAIL}apparmor_restrict_unprivileged_userns=$AURU "
    [ "$AURU" = "1" ] && APPARMOR_USERNS_RESTRICT=1
fi

# ---------- 1. Copy Fail (CVE-2026-31431) ----------
header "[1/4] Copy Fail  (CVE-2026-31431, algif_aead)"

CF_STATUS="UNKNOWN"; CF_DETAIL=""

if ver_ge "$KERNEL_BASE" "4.14"; then
    info "Kernel $KERNEL_BASE >= 4.14 - was vulnerable from introduction (2017-08)"

    check_module "algif_aead"
    AEAD_LOADED=$MOD_LOADED
    AEAD_AVAILABLE=$MOD_AVAILABLE
    AEAD_BLACKLISTED=$MOD_BLACKLISTED

    if [ $AEAD_BLACKLISTED -eq 1 ] && [ $AEAD_LOADED -eq 0 ]; then
        CF_STATUS="MITIGATED"
        CF_DETAIL="algif_aead blacklisted and not loaded; verify kernel patch separately via distro CVE tracker"
        ok "Copy Fail: module blacklisted + not loaded (still verify kernel patch)"
    elif [ $AEAD_LOADED -eq 1 ]; then
        CF_STATUS="EXPOSED"
        CF_DETAIL="algif_aead loaded on kernel $KERNEL_BASE; kernel patch verification required"
        vuln "Copy Fail: algif_aead loaded, kernel patch status unverified"
    elif [ $AEAD_AVAILABLE -eq 1 ]; then
        CF_STATUS="LATENT"
        CF_DETAIL="algif_aead module on disk, autoload via socket(AF_ALG) possible"
        warn "Copy Fail: algif_aead autoloadable (any user can trigger autoload)"
    else
        CF_STATUS="LIKELY_OK"
        CF_DETAIL="algif_aead not available, but verify kernel patch via distro tracker"
        ok "Copy Fail: algif_aead not available on this kernel"
    fi
else
    CF_STATUS="NOT_AFFECTED"
    CF_DETAIL="Kernel $KERNEL_BASE predates Copy Fail introduction (4.14, 2017)"
    ok "Copy Fail: kernel pre-4.14, not affected"
fi

record "copyfail.status" "$CF_STATUS" "$CF_DETAIL"

# ---------- 2. Dirty Frag #1 - xfrm-ESP (no CVE) ----------
header "[2/4] Dirty Frag #1  (xfrm-ESP page-cache write, NO PATCH)"

DF1_STATUS="UNKNOWN"; DF1_DETAIL=""

if ver_ge "$KERNEL_BASE" "4.10"; then
    ESP_LOADED=0; ESP_AVAILABLE=0; ESP_BLACKLISTED=0
    for m in esp4 esp6; do
        check_module "$m"
        [ $MOD_LOADED -eq 1 ] && ESP_LOADED=1
        [ $MOD_AVAILABLE -eq 1 ] && ESP_AVAILABLE=1
    done
    # Both must be blacklisted to count as mitigation
    check_module "esp4"; ESP4_BL=$MOD_BLACKLISTED
    check_module "esp6"; ESP6_BL=$MOD_BLACKLISTED
    [ $ESP4_BL -eq 1 ] && [ $ESP6_BL -eq 1 ] && ESP_BLACKLISTED=1

    if [ $ESP_BLACKLISTED -eq 1 ] && [ $ESP_LOADED -eq 0 ]; then
        DF1_STATUS="MITIGATED"
        DF1_DETAIL="esp4/esp6 blacklisted and not loaded"
        ok "xfrm-ESP variant: blacklisted + not loaded"
    elif [ $ESP_LOADED -eq 1 ]; then
        if [ $USERNS_RESTRICTED -eq 1 ]; then
            DF1_STATUS="HARDENED"
            DF1_DETAIL="esp modules loaded but unprivileged userns disabled - trigger blocked"
            warn "xfrm-ESP: module loaded; userns gate closed"
        elif [ $APPARMOR_USERNS_RESTRICT -eq 1 ]; then
            DF1_STATUS="PARTIAL"
            DF1_DETAIL="AppArmor userns restriction in place but bypassable via CrackArmor"
            warn "xfrm-ESP: AppArmor userns restrict in place (CrackArmor bypass possible)"
        else
            DF1_STATUS="EXPOSED"
            DF1_DETAIL="esp modules loaded + unprivileged userns allowed"
            vuln "xfrm-ESP: module loaded + userns open = exploitable"
        fi
    elif [ $ESP_AVAILABLE -eq 1 ]; then
        DF1_STATUS="LATENT"
        DF1_DETAIL="esp4/esp6 not loaded but autoloadable"
        warn "xfrm-ESP: module autoloadable on demand"
    else
        DF1_STATUS="NOT_PRESENT"
        DF1_DETAIL="esp4/esp6 not in kernel build"
        ok "xfrm-ESP: modules not present in kernel build"
    fi
else
    DF1_STATUS="NOT_AFFECTED"
    DF1_DETAIL="Kernel pre-4.10"
    ok "xfrm-ESP variant: kernel pre-4.10, not affected"
fi

record "dirtyfrag.xfrm.status" "$DF1_STATUS" "$DF1_DETAIL"

# ---------- 3. Dirty Frag #2 - RxRPC (no CVE) ----------
header "[3/4] Dirty Frag #2  (RxRPC page-cache write, NO PATCH)"

DF2_STATUS="UNKNOWN"; DF2_DETAIL=""

if ver_ge "$KERNEL_BASE" "6.5"; then
    check_module "rxrpc"
    if [ $MOD_BLACKLISTED -eq 1 ] && [ $MOD_LOADED -eq 0 ]; then
        DF2_STATUS="MITIGATED"
        DF2_DETAIL="rxrpc blacklisted and not loaded"
        ok "RxRPC variant: blacklisted + not loaded"
    elif [ $MOD_LOADED -eq 1 ]; then
        DF2_STATUS="EXPOSED"
        DF2_DETAIL="rxrpc loaded; trigger does NOT need userns - any local user"
        vuln "RxRPC: module loaded + no userns gate = ANY local user can exploit"
    elif [ $MOD_AVAILABLE -eq 1 ]; then
        DF2_STATUS="LATENT"
        DF2_DETAIL="rxrpc autoloadable via socket(AF_RXRPC)"
        warn "RxRPC: module autoloadable via socket(AF_RXRPC,...)"
    else
        DF2_STATUS="NOT_PRESENT"
        DF2_DETAIL="rxrpc not in kernel build"
        ok "RxRPC: module not present"
    fi
else
    DF2_STATUS="NOT_AFFECTED"
    DF2_DETAIL="Kernel $KERNEL_BASE pre-6.5 - RxRPC variant not in scope"
    ok "RxRPC variant: kernel pre-6.5, not affected"
fi

record "dirtyfrag.rxrpc.status" "$DF2_STATUS" "$DF2_DETAIL"

# ---------- 4. CrackArmor ----------
header "[4/4] CrackArmor  (CVE-2026-23268..23411, AppArmor)"

CA_STATUS="UNKNOWN"; CA_DETAIL=""

if ver_ge "$KERNEL_BASE" "4.11"; then
    AA_ENABLED=0
    if [ -r /sys/module/apparmor/parameters/enabled ]; then
        AA_VAL=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)
        [ "$AA_VAL" = "Y" ] && AA_ENABLED=1
    fi

    SELINUX_ENABLED=0
    if [ -d /sys/fs/selinux ]; then
        SELINUX_ENABLED=1
    fi

    if [ $AA_ENABLED -eq 0 ]; then
        if [ $SELINUX_ENABLED -eq 1 ]; then
            CA_STATUS="NOT_AFFECTED"
            CA_DETAIL="System uses SELinux instead of AppArmor"
            ok "CrackArmor: SELinux system, not affected"
        else
            CA_STATUS="NOT_AFFECTED"
            CA_DETAIL="AppArmor not enabled"
            ok "CrackArmor: AppArmor disabled, not affected"
        fi
    else
        # Detect sudo-rs (Ubuntu 25.10+ default)
        SUDORS=0
        if command -v sudo >/dev/null 2>&1; then
            if sudo -V 2>/dev/null | grep -qiE 'sudo-rs|rust'; then
                SUDORS=1
            fi
        fi
        SUDO_VER=$(sudo -V 2>/dev/null | head -1 | awk '{print $NF}')
        SUDO_VER=${SUDO_VER:-none}

        if [ $SUDORS -eq 1 ]; then
            CA_STATUS="MITIGATED"
            CA_DETAIL="sudo-rs in use (no mail notification path); kernel patch still required"
            ok "CrackArmor: sudo-rs mitigates user-space LPE chain"
        else
            CA_STATUS="EXPOSED"
            CA_DETAIL="AppArmor enabled, classic sudo $SUDO_VER - apply kernel + util-linux + sudo updates"
            warn "CrackArmor: AppArmor active, classic sudo - patch kernel + util-linux + sudo"
        fi
    fi
else
    CA_STATUS="NOT_AFFECTED"
    CA_DETAIL="Kernel pre-4.11"
    ok "CrackArmor: kernel pre-4.11, not affected"
fi

record "crackarmor.status" "$CA_STATUS" "$CA_DETAIL"

# ---------- 5. Container/isolation context ----------
header "Container & isolation context"

IN_CONTAINER=0
CONTAINER_TYPE="none"
RUNTIMES=""

if [ -f /.dockerenv ]; then
    IN_CONTAINER=1; CONTAINER_TYPE="docker"
elif [ -f /run/.containerenv ]; then
    IN_CONTAINER=1; CONTAINER_TYPE="podman"
elif [ -r /proc/1/cgroup ] && grep -qaE '(docker|kubepods|containerd|lxc)' /proc/1/cgroup 2>/dev/null; then
    IN_CONTAINER=1
    CONTAINER_TYPE=$(grep -aE 'docker|kubepods|containerd|lxc' /proc/1/cgroup | head -1 | grep -oE 'docker|kubepods|containerd|lxc' | head -1)
elif [ -r /proc/1/sched ] && head -1 /proc/1/sched 2>/dev/null | grep -qvE '^(systemd|init)'; then
    # PID 1 is something other than systemd/init - might be containerized
    IN_CONTAINER=1; CONTAINER_TYPE="unknown"
fi

if [ $IN_CONTAINER -eq 1 ]; then
    warn "Running INSIDE a container ($CONTAINER_TYPE)"
    warn "Page cache is shared with host - all bugs above are container-escape primitives"
    record "container.status" "INSIDE" "$CONTAINER_TYPE"
else
    info "Running on host (not in container)"
    record "container.status" "HOST" "none"

    for rt in docker podman containerd kubelet lxc crio runc; do
        if command -v "$rt" >/dev/null 2>&1; then
            RUNTIMES="$RUNTIMES $rt"
        fi
    done
    RUNTIMES=$(echo "$RUNTIMES" | sed 's/^ //')
    if [ -n "$RUNTIMES" ]; then
        warn "Container runtime(s) installed:$RUNTIMES"
        warn "Multi-tenant blast radius applies"
        record "container.runtimes" "PRESENT" "$RUNTIMES"
    fi
fi

info "userns posture: $USERNS_DETAIL"
record "userns.posture" "INFO" "$USERNS_DETAIL"

# ---------- 6. Optional: distro CVE tracker check ----------
if [ $CHECK_PATCH -eq 1 ]; then
    header "Distro CVE tracker check (Copy Fail / CrackArmor)"
    if ! command -v curl >/dev/null 2>&1; then
        warn "curl not available - skipping tracker check"
    else
        case "$DISTRO_FAMILY" in
            debian)
                if [ "$DISTRO_ID" = "ubuntu" ]; then
                    URL="https://ubuntu.com/security/cves/CVE-2026-31431.json"
                else
                    URL="https://security-tracker.debian.org/tracker/data/json"
                fi
                info "Tracker URL: $URL (manual verification recommended)"
                ;;
            rhel)
                URL="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-31431.json"
                info "Tracker URL: $URL (manual verification recommended)"
                ;;
            suse)
                URL="https://www.suse.com/security/cve/CVE-2026-31431.html"
                info "Tracker URL: $URL (manual verification recommended)"
                ;;
            *)
                info "No automatic tracker integration for family '$DISTRO_FAMILY'"
                ;;
        esac
    fi
fi

# ---------- JSON output ----------
if [ $JSON_MODE -eq 1 ]; then
    printf '{\n'
    printf '  "schema": "lpe-audit/1.0",\n'
    printf '  "timestamp": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
    printf '  "host": "%s",\n' "$HOSTNAME"
    printf '  "findings": {\n'
    first=1
    echo "$FINDINGS" | while IFS='|' read -r k s d; do
        [ -z "$k" ] && continue
        [ $first -eq 0 ] && printf ',\n'
        # Escape backslashes and quotes in detail
        d_esc=$(printf '%s' "$d" | sed 's/\\/\\\\/g; s/"/\\"/g')
        printf '    "%s": {"status": "%s", "detail": "%s"}' "$k" "$s" "$d_esc"
        first=0
    done
    printf '\n  }\n}\n'
    exit 0
fi

# ---------- Summary ----------
header "SUMMARY"

print_row() {
    label="$1"; status="$2"; detail="$3"
    case "$status" in
        EXPOSED|VULN)
            color="$RED" ;;
        LATENT|PARTIAL|HARDENED)
            color="$YEL" ;;
        MITIGATED|LIKELY_OK|NOT_AFFECTED|NOT_PRESENT)
            color="$GRN" ;;
        *)
            color="$DIM" ;;
    esac
    printf "  %-32s %s%-12s%s  %s\n" "$label" "$color" "$status" "$RST" "$detail"
}

[ $QUIET_MODE -eq 0 ] && echo
print_row "Copy Fail (CVE-2026-31431)"      "$CF_STATUS"  "$CF_DETAIL"
print_row "Dirty Frag #1 (xfrm-ESP)"        "$DF1_STATUS" "$DF1_DETAIL"
print_row "Dirty Frag #2 (RxRPC)"           "$DF2_STATUS" "$DF2_DETAIL"
print_row "CrackArmor (CVE-2026-23268+)"    "$CA_STATUS"  "$CA_DETAIL"
[ $QUIET_MODE -eq 0 ] && echo

# ---------- Recommended actions ----------
if [ $QUIET_MODE -eq 0 ]; then
    header "Recommended actions"
    NEED_ACTION=0

    case "$CF_STATUS" in
        EXPOSED|LATENT|UNKNOWN)
            NEED_ACTION=1
            echo
            echo "  ${BLD}Copy Fail (CVE-2026-31431):${RST}"
            echo "    1) Apply distro kernel update (most distros patched late April 2026)"
            echo "    2) Interim mitigation:"
            echo "       echo 'install algif_aead /bin/false' | sudo tee /etc/modprobe.d/disable-algif.conf"
            echo "       sudo rmmod algif_aead 2>/dev/null || true"
            ;;
    esac

    case "$DF1_STATUS$DF2_STATUS" in
        *EXPOSED*|*LATENT*|*PARTIAL*|*HARDENED*)
            NEED_ACTION=1
            echo
            echo "  ${BLD}Dirty Frag (NO UPSTREAM PATCH - embargo broken):${RST}"
            echo "    Apply module blacklist (WARNING: disables IPsec and AFS/RxRPC):"
            echo "    sudo tee /etc/modprobe.d/dirtyfrag.conf <<'EOF'"
            echo "    install esp4 /bin/false"
            echo "    install esp6 /bin/false"
            echo "    install rxrpc /bin/false"
            echo "    EOF"
            echo "    sudo rmmod esp4 esp6 rxrpc 2>/dev/null || true"
            echo "    Track upstream patches in mainline Linux kernel stable tree"
            ;;
    esac

    if [ "$CA_STATUS" = "EXPOSED" ]; then
        NEED_ACTION=1
        echo
        echo "  ${BLD}CrackArmor (CVE-2026-23268..23411):${RST}"
        echo "    1) Apply kernel updates"
        echo "    2) Update util-linux (su mitigation) and sudo packages"
        echo "    3) Consider migration to sudo-rs (Ubuntu 25.10+ default)"
    fi

    if [ $IN_CONTAINER -eq 1 ] || [ -n "$RUNTIMES" ]; then
        echo
        echo "  ${BLD}Multi-tenant / container hardening:${RST}"
        echo "    - Page cache is shared per-host. All four bugs are escape primitives."
        echo "    - For untrusted workloads: Firecracker / Cloud Hypervisor / Kata / gVisor"
        echo "    - Disable unprivileged user namespaces if not needed:"
        echo "        sudo sysctl -w kernel.unprivileged_userns_clone=0"
        echo "        sudo sysctl -w user.max_user_namespaces=0"
    fi

    if [ $NEED_ACTION -eq 0 ]; then
        echo
        ok "No exposed components detected. Still verify kernel patches via your distro CVE tracker."
    fi
    echo
fi

# ---------- Footer ----------
if [ $QUIET_MODE -eq 0 ]; then
    info "This audit is HEURISTIC. Authoritative answer = your distro's CVE tracker:"
    info "  Ubuntu:   https://ubuntu.com/security/cve/CVE-2026-31431"
    info "  Debian:   https://security-tracker.debian.org/tracker/CVE-2026-31431"
    info "  RHEL:     https://access.redhat.com/security/cve/CVE-2026-31431"
    info "  SUSE:     https://www.suse.com/security/cve/CVE-2026-31431.html"
    info "  AlmaLinux/Rocky: same as RHEL upstream"
    echo
fi

# ---------- Exit code ----------
EXIT_CODE=0
case "$CF_STATUS$DF1_STATUS$DF2_STATUS$CA_STATUS" in
    *EXPOSED*) EXIT_CODE=2 ;;
esac
exit $EXIT_CODE
