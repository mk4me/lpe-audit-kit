#!/usr/bin/env bash
#
# fleet-audit.sh - Run lpe-audit.sh against multiple hosts via SSH
# ================================================================
# Universal wrapper - works with any SSH-accessible Linux fleet.
#
# Usage:
#   ./fleet-audit.sh -i hosts.txt [options]
#
# Hosts file format (one per line):
#   user@host           - explicit user
#   host                - uses default user (-u or current $USER)
#   host:port           - non-standard SSH port
#   user@host:port      - both
#   # comment lines and blank lines are ignored
#
# Examples:
#   ./fleet-audit.sh -i hosts.txt
#   ./fleet-audit.sh -i hosts.txt -c 16 -u admin
#   ./fleet-audit.sh -i hosts.txt --sudo --check-patch
#   ./fleet-audit.sh -i hosts.txt -k ~/.ssh/work_id_ed25519
#

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
AUDIT_SCRIPT="$SCRIPT_DIR/lpe-audit.sh"

HOSTS_FILE=""
CONCURRENCY=8
SSH_USER="${USER:-root}"
SSH_KEY=""
OUT_DIR="./fleet-results-$(date +%Y%m%d-%H%M%S)"
USE_SUDO=0
CHECK_PATCH=0
SSH_TIMEOUT=15

usage() {
    cat <<EOF
Usage: $0 -i hosts.txt [options]

Required:
  -i FILE          Hosts file (one host per line)

Options:
  -c N             Parallel SSH connections (default: 8)
  -u USER          Default SSH user (default: \$USER = $USER)
  -k KEYFILE       SSH private key file
  -o DIR           Output directory (default: ./fleet-results-<timestamp>)
  -t SECONDS       SSH connect timeout (default: 15)
  --sudo           Run remote audit with sudo -n (passwordless required)
  --check-patch    Pass --check-patch to remote audit
  -h, --help       This help

Output:
  <out>/<host>.json     Per-host JSON
  <out>/<host>.err      Per-host stderr
  <out>/fleet-matrix.csv  Aggregated CSV (host x CVE)
  <out>/fleet-report.txt  Pretty-printed summary

Exit codes:
  0   All hosts audited, none EXPOSED
  1   Some hosts unreachable / errors
  2   At least one host has EXPOSED status

EOF
    exit 1
}

# --- arg parsing ---
while [ $# -gt 0 ]; do
    case "$1" in
        -i) HOSTS_FILE="$2"; shift 2 ;;
        -c) CONCURRENCY="$2"; shift 2 ;;
        -u) SSH_USER="$2"; shift 2 ;;
        -k) SSH_KEY="$2"; shift 2 ;;
        -o) OUT_DIR="$2"; shift 2 ;;
        -t) SSH_TIMEOUT="$2"; shift 2 ;;
        --sudo) USE_SUDO=1; shift ;;
        --check-patch) CHECK_PATCH=1; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
done

[ -z "$HOSTS_FILE" ] && usage
[ ! -r "$HOSTS_FILE" ] && { echo "Cannot read hosts file: $HOSTS_FILE" >&2; exit 3; }
[ ! -r "$AUDIT_SCRIPT" ] && { echo "Cannot find lpe-audit.sh next to this script" >&2; exit 3; }

# --- dependency checks ---
for tool in ssh scp xargs awk; do
    command -v $tool >/dev/null 2>&1 || { echo "Missing tool: $tool" >&2; exit 3; }
done
# jq is optional - we don't strictly need it
command -v jq >/dev/null 2>&1 || true

# --- SSH options ---
SSH_OPTS="-o StrictHostKeyChecking=accept-new"
SSH_OPTS="$SSH_OPTS -o ConnectTimeout=$SSH_TIMEOUT"
SSH_OPTS="$SSH_OPTS -o BatchMode=yes"
SSH_OPTS="$SSH_OPTS -o ServerAliveInterval=10"
SSH_OPTS="$SSH_OPTS -o LogLevel=ERROR"
[ -n "$SSH_KEY" ] && SSH_OPTS="$SSH_OPTS -i $SSH_KEY -o IdentitiesOnly=yes"

# --- prepare ---
mkdir -p "$OUT_DIR"
echo "[+] Output:        $OUT_DIR"
echo "[+] Concurrency:   $CONCURRENCY"
echo "[+] Default user:  $SSH_USER"
echo "[+] Audit script:  $AUDIT_SCRIPT"
[ -n "$SSH_KEY" ] && echo "[+] SSH key:       $SSH_KEY"
[ $USE_SUDO -eq 1 ] && echo "[+] Sudo:          enabled (-n, passwordless required)"
[ $CHECK_PATCH -eq 1 ] && echo "[+] Patch check:   enabled"

# Read non-empty, non-comment lines
HOST_COUNT=0
HOSTS_LIST=$(grep -vE '^[[:space:]]*(#|$)' "$HOSTS_FILE")
HOST_COUNT=$(echo "$HOSTS_LIST" | wc -l)
echo "[+] Hosts to audit: $HOST_COUNT"
echo

# --- worker function (called via xargs) ---
audit_one() {
    target="$1"
    out_dir="$2"
    audit_script="$3"
    default_user="$4"
    use_sudo="$5"
    check_patch="$6"
    ssh_opts="$7"

    # Parse host[:port] and user@host[:port]
    user_part=""
    rest="$target"
    case "$target" in
        *@*)
            user_part="${target%@*}@"
            rest="${target#*@}"
            ;;
        *)
            user_part="${default_user}@"
            ;;
    esac
    host="$rest"
    port_arg=""
    case "$rest" in
        *:*)
            host="${rest%:*}"
            port="${rest##*:}"
            port_arg="-P $port"
            ssh_port_arg="-p $port"
            ;;
        *)
            ssh_port_arg=""
            ;;
    esac
    conn="${user_part}${host}"
    safe_host=$(echo "$host" | tr '/' '_' | tr ':' '_')
    out_json="$out_dir/${safe_host}.json"
    out_err="$out_dir/${safe_host}.err"

    # Step 1: copy script
    # shellcheck disable=SC2086
    if ! scp $ssh_opts $port_arg -q "$audit_script" "${conn}:/tmp/lpe-audit.sh" 2>"$out_err"; then
        printf '{"host":"%s","error":"scp failed"}\n' "$host" > "$out_json"
        echo "[FAIL]  $host  (scp failed - check network/auth)"
        return 1
    fi

    # Step 2: build remote command
    remote_cmd="bash /tmp/lpe-audit.sh --json"
    [ "$check_patch" = "1" ] && remote_cmd="$remote_cmd --check-patch"
    [ "$use_sudo" = "1" ] && remote_cmd="sudo -n $remote_cmd"

    # Step 3: execute and clean up
    # shellcheck disable=SC2086
    if ! ssh $ssh_opts $ssh_port_arg "$conn" "$remote_cmd; rm -f /tmp/lpe-audit.sh" \
            > "$out_json" 2>>"$out_err"; then
        # Even on non-zero exit (EXPOSED returns 2), JSON may be valid
        if [ -s "$out_json" ] && head -c 1 "$out_json" 2>/dev/null | grep -q '{'; then
            : # got valid-looking JSON despite non-zero exit (likely EXPOSED=2)
        else
            printf '{"host":"%s","error":"ssh exec failed"}\n' "$host" > "$out_json"
            echo "[FAIL]  $host  (ssh failed)"
            return 1
        fi
    fi

    # Step 4: validate JSON
    if head -c 1 "$out_json" 2>/dev/null | grep -q '{'; then
        # quick status extraction without jq
        cf=$(awk -F'"' '/copyfail.status/{getline; for(i=1;i<=NF;i++) if($i=="status"){print $(i+2); exit}}' "$out_json" 2>/dev/null)
        cf=${cf:-?}
        echo "[OK]    $host  copyfail=$cf"
    else
        mv "$out_json" "${out_json}.broken"
        printf '{"host":"%s","error":"invalid JSON"}\n' "$host" > "$out_json"
        echo "[FAIL]  $host  (invalid JSON returned)"
        return 1
    fi
}

export -f audit_one

# --- run in parallel ---
echo "$HOSTS_LIST" | \
    xargs -I{} -P "$CONCURRENCY" \
    bash -c 'audit_one "$@"' _ "{}" "$OUT_DIR" "$AUDIT_SCRIPT" "$SSH_USER" "$USE_SUDO" "$CHECK_PATCH" "$SSH_OPTS"

# --- aggregate ---
echo
echo "[+] Aggregating results..."

CSV="$OUT_DIR/fleet-matrix.csv"
REPORT="$OUT_DIR/fleet-report.txt"

extract() {
    # extract status of given key from JSON file (no jq needed)
    file="$1"; key="$2"
    awk -v K="$key" '
        BEGIN { found=0 }
        $0 ~ "\"" K "\"" {
            # status is in same logical line/object
            match($0, /"status"[[:space:]]*:[[:space:]]*"[^"]*"/)
            if (RSTART > 0) {
                s = substr($0, RSTART, RLENGTH)
                gsub(/.*"status"[[:space:]]*:[[:space:]]*"/, "", s)
                gsub(/".*/, "", s)
                print s
                exit
            }
        }
    ' "$file" 2>/dev/null
}

extract_detail() {
    file="$1"; key="$2"
    awk -v K="$key" '
        $0 ~ "\"" K "\"" {
            match($0, /"detail"[[:space:]]*:[[:space:]]*"[^"]*"/)
            if (RSTART > 0) {
                s = substr($0, RSTART, RLENGTH)
                gsub(/.*"detail"[[:space:]]*:[[:space:]]*"/, "", s)
                gsub(/".*/, "", s)
                print s
                exit
            }
        }
    ' "$file" 2>/dev/null
}

{
    echo "host,kernel,distro,copyfail,dirtyfrag_xfrm,dirtyfrag_rxrpc,crackarmor,container"
    for f in "$OUT_DIR"/*.json; do
        [ -r "$f" ] || continue
        host=$(basename "$f" .json)

        # error file?
        if grep -q '"error"' "$f" 2>/dev/null; then
            err=$(awk -F'"' '/"error"/ {print $4; exit}' "$f")
            echo "$host,ERROR,ERROR,ERROR,ERROR,ERROR,ERROR,$err"
            continue
        fi

        kernel=$(extract_detail "$f" "system.kernel")
        distro=$(extract_detail "$f" "system.distro")
        cf=$(extract "$f" "copyfail.status")
        df1=$(extract "$f" "dirtyfrag.xfrm.status")
        df2=$(extract "$f" "dirtyfrag.rxrpc.status")
        ca=$(extract "$f" "crackarmor.status")
        ct=$(extract "$f" "container.status")
        # CSV-escape commas
        distro=$(echo "$distro" | tr ',' ';')
        echo "$host,${kernel:-?},${distro:-?},${cf:-?},${df1:-?},${df2:-?},${ca:-?},${ct:-?}"
    done
} > "$CSV"

# --- pretty report ---
{
    echo "================================================================"
    echo " LPE FLEET AUDIT REPORT - $(date)"
    echo " Hosts: $HOST_COUNT    Output: $OUT_DIR"
    echo "================================================================"
    echo
    if command -v column >/dev/null 2>&1; then
        column -t -s, "$CSV"
    else
        cat "$CSV"
    fi
    echo
    echo "Status legend:"
    echo "  EXPOSED       - exploitable, immediate action required"
    echo "  LATENT        - module autoloadable, near-exposed"
    echo "  PARTIAL       - userns restriction in place but bypassable"
    echo "  HARDENED      - module loaded but userns gate closed"
    echo "  MITIGATED     - blacklisted + not loaded"
    echo "  LIKELY_OK     - no module evidence (verify patch separately)"
    echo "  NOT_PRESENT   - module not in kernel build"
    echo "  NOT_AFFECTED  - kernel/distro out of scope"
    echo "  ERROR         - host unreachable / audit failed"
    echo
    echo "EXPOSED hosts by vulnerability:"
    for col in copyfail dirtyfrag_xfrm dirtyfrag_rxrpc crackarmor; do
        count=$(awk -F, -v COL="$col" '
            NR==1 { for(i=1;i<=NF;i++) if($i==COL) c=i; next }
            $c=="EXPOSED" { n++ }
            END { print n+0 }
        ' "$CSV")
        printf "  %-20s %d\n" "$col" "$count"
    done

    EXPOSED_HOSTS=$(awk -F, 'NR>1 { for(i=4;i<=7;i++) if($i=="EXPOSED") {print $1; next} }' "$CSV")
    if [ -n "$EXPOSED_HOSTS" ]; then
        echo
        echo "Hosts requiring immediate action:"
        echo "$EXPOSED_HOSTS" | sed 's/^/  /'
    fi

    ERROR_HOSTS=$(awk -F, 'NR>1 && $2=="ERROR" { print $1 }' "$CSV")
    if [ -n "$ERROR_HOSTS" ]; then
        echo
        echo "Hosts with errors (re-run manually):"
        echo "$ERROR_HOSTS" | sed 's/^/  /'
    fi
    echo
} | tee "$REPORT"

echo
echo "[+] CSV:    $CSV"
echo "[+] Report: $REPORT"
echo "[+] JSONs:  $OUT_DIR/*.json"

# Exit code
if grep -q ",EXPOSED," "$CSV" 2>/dev/null || grep -q ",EXPOSED$" "$CSV" 2>/dev/null; then
    exit 2
elif grep -q ",ERROR," "$CSV" 2>/dev/null; then
    exit 1
fi
exit 0
