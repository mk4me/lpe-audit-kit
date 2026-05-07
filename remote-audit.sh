#!/usr/bin/env bash
#
# remote-audit.sh - Audit a remote host without copying files to it
# =================================================================
# Streams lpe-audit.sh through SSH stdin. Nothing is written to the
# remote filesystem - the script runs from memory and disappears.
#
# Usage:
#   ./remote-audit.sh [options] user@host
#
# Examples:
#   ./remote-audit.sh root@server.example.com
#   ./remote-audit.sh --sudo admin@web-01
#   ./remote-audit.sh --json admin@web-01 > web-01.json
#   ./remote-audit.sh --sudo --json admin@db-01 | jq
#   ./remote-audit.sh -p 2222 -k ~/.ssh/key admin@host
#
# Source script can be:
#   - Local lpe-audit.sh next to this wrapper (default)
#   - Remote URL via --url <URL>
#

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
LOCAL_SCRIPT="$SCRIPT_DIR/lpe-audit.sh"
DEFAULT_URL="https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main/lpe-audit.sh"

# --- defaults ---
USE_SUDO=0
AUDIT_FLAGS=""
SSH_PORT=""
SSH_KEY=""
SOURCE_URL=""
SHELL_BIN="bash"

usage() {
    cat <<EOF
Usage: $0 [options] user@host

Audit a remote Linux host via SSH without copying any files to it.
The audit script streams through SSH stdin and runs from memory only.

Audit options (passed to lpe-audit.sh on the remote):
  --json              JSON output (machine-readable)
  --quiet             Summary only
  --check-patch       Print distro CVE tracker URLs
  --sudo              Run with sudo -n on remote (passwordless required)

SSH options:
  -p PORT             SSH port (default: 22)
  -k KEYFILE          SSH private key
  --shell SHELL       Remote shell to use (default: bash; use sh for POSIX)

Source options:
  --url URL           Fetch script from URL instead of local file
  --remote-source     Same as --url $DEFAULT_URL
                      Useful when you don't have the kit locally

Other:
  -h, --help          This help

Examples:
  # Audit a single host (using local lpe-audit.sh)
  $0 root@server.example.com

  # With sudo for full kernel module visibility
  $0 --sudo admin@web-01

  # JSON output, save to file
  $0 --sudo --json admin@web-01 > audit-web-01.json

  # Without local copy of the kit (fetches from GitHub)
  $0 --remote-source --sudo admin@host

  # Custom port and key
  $0 -p 2222 -k ~/.ssh/audit_key admin@host

EOF
    exit 1
}

# --- argument parsing ---
TARGET=""
while [ $# -gt 0 ]; do
    case "$1" in
        --json|--quiet|--check-patch)
            AUDIT_FLAGS="$AUDIT_FLAGS $1"
            shift
            ;;
        --sudo)
            USE_SUDO=1
            shift
            ;;
        -p)
            SSH_PORT="-p $2"
            shift 2
            ;;
        -k)
            SSH_KEY="-i $2 -o IdentitiesOnly=yes"
            shift 2
            ;;
        --shell)
            SHELL_BIN="$2"
            shift 2
            ;;
        --url)
            SOURCE_URL="$2"
            shift 2
            ;;
        --remote-source)
            SOURCE_URL="$DEFAULT_URL"
            shift
            ;;
        -h|--help)
            usage
            ;;
        --)
            shift
            ;;
        -*)
            echo "Unknown option: $1" >&2
            usage
            ;;
        *)
            if [ -n "$TARGET" ]; then
                echo "Multiple targets given: '$TARGET' and '$1'" >&2
                usage
            fi
            TARGET="$1"
            shift
            ;;
    esac
done

[ -z "$TARGET" ] && usage

# --- check we have a script source ---
SCRIPT_SOURCE=""
if [ -n "$SOURCE_URL" ]; then
    if ! command -v curl >/dev/null 2>&1; then
        echo "ERROR: --url requires curl" >&2
        exit 3
    fi
    SCRIPT_SOURCE="curl"
elif [ -r "$LOCAL_SCRIPT" ]; then
    SCRIPT_SOURCE="local"
else
    echo "ERROR: lpe-audit.sh not found locally at $LOCAL_SCRIPT" >&2
    echo "Either:" >&2
    echo "  1. Run from inside the lpe-audit-kit directory" >&2
    echo "  2. Use --remote-source to fetch from GitHub" >&2
    echo "  3. Use --url <URL> for a custom location" >&2
    exit 3
fi

# --- build SSH options ---
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o LogLevel=ERROR"

# --- build remote command ---
REMOTE_CMD="$SHELL_BIN -s --"
[ -n "$AUDIT_FLAGS" ] && REMOTE_CMD="$REMOTE_CMD$AUDIT_FLAGS"
[ "$USE_SUDO" = "1" ] && REMOTE_CMD="sudo -n $REMOTE_CMD"

# --- info to stderr (so --json output stays clean) ---
echo "[+] Target: $TARGET" >&2
echo "[+] Source: ${SOURCE_URL:-$LOCAL_SCRIPT}" >&2
echo "[+] Remote: $REMOTE_CMD" >&2
echo >&2

# --- execute ---
# shellcheck disable=SC2086
if [ "$SCRIPT_SOURCE" = "curl" ]; then
    curl -fsSL "$SOURCE_URL" | ssh $SSH_OPTS $SSH_PORT $SSH_KEY "$TARGET" "$REMOTE_CMD"
else
    # shellcheck disable=SC2086
    ssh $SSH_OPTS $SSH_PORT $SSH_KEY "$TARGET" "$REMOTE_CMD" < "$LOCAL_SCRIPT"
fi

EXIT_CODE=$?

case $EXIT_CODE in
    0) ;;
    2) echo >&2; echo "[!] Host has EXPOSED components - see report above" >&2 ;;
    3) echo >&2; echo "[!] Audit script error on remote" >&2 ;;
    255) echo >&2; echo "[!] SSH connection error - check host, key, network" >&2 ;;
    *) echo >&2; echo "[!] Unexpected exit code: $EXIT_CODE" >&2 ;;
esac

exit $EXIT_CODE
