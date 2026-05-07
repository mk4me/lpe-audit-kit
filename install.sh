#!/bin/sh
#
# install.sh - Safe curl|sh alternative with SHA256 verification
# ==============================================================
# This installer downloads lpe-audit.sh, verifies its SHA256 against
# the published checksum, and only then runs it (or saves it for later).
#
# Use this instead of `curl ... | sh` when you want integrity verification.
#
# Quick install (download + verify + save):
#   curl -fsSL https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main/install.sh | sh
#
# Quick run (download + verify + run + delete):
#   curl -fsSL https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main/install.sh | sh -s -- --run
#
# The verified checksums are pulled from SHA256SUMS in the same repo.
#

set -eu

REPO_BASE="https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main"
SCRIPT_NAME="lpe-audit.sh"
SUMS_NAME="SHA256SUMS"
TARGET_DIR="${TARGET_DIR:-.}"
DO_RUN=0
RUN_ARGS=""

usage() {
    cat <<EOF
Usage: install.sh [options]

Options:
  --run            Run the script immediately after verification, then delete
  --target DIR     Where to save the script (default: current directory)
  --                Subsequent args passed to lpe-audit.sh when --run is used
  -h, --help       This help

Environment variables:
  TARGET_DIR       Same as --target

Examples:
  # Download to current directory, verify, save
  ./install.sh

  # Download, verify, run with --json, then delete
  ./install.sh --run -- --json

  # Quick run without leaving a file behind
  curl -fsSL https://raw.githubusercontent.com/mk4me/lpe-audit-kit/main/install.sh | sh -s -- --run

EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --run)
            DO_RUN=1
            shift
            ;;
        --target)
            TARGET_DIR="$2"
            shift 2
            ;;
        --)
            shift
            RUN_ARGS="$*"
            break
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

# --- Pick downloader ---
if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -qO- "$1"; }
else
    echo "ERROR: need curl or wget" >&2
    exit 3
fi

# --- Pick SHA256 tool ---
if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    echo "ERROR: need sha256sum or shasum" >&2
    exit 3
fi

mkdir -p "$TARGET_DIR"
TARGET_PATH="$TARGET_DIR/$SCRIPT_NAME"

echo "[+] Downloading $SCRIPT_NAME..." >&2
fetch "$REPO_BASE/$SCRIPT_NAME" > "$TARGET_PATH"

echo "[+] Fetching SHA256SUMS..." >&2
EXPECTED_SUM=$(fetch "$REPO_BASE/$SUMS_NAME" | awk -v f="$SCRIPT_NAME" '$2==f {print $1; exit}')

if [ -z "$EXPECTED_SUM" ]; then
    echo "ERROR: $SCRIPT_NAME not found in published SHA256SUMS" >&2
    rm -f "$TARGET_PATH"
    exit 4
fi

ACTUAL_SUM=$(sha256 "$TARGET_PATH")

if [ "$EXPECTED_SUM" != "$ACTUAL_SUM" ]; then
    echo "ERROR: SHA256 mismatch!" >&2
    echo "  expected: $EXPECTED_SUM" >&2
    echo "  actual:   $ACTUAL_SUM" >&2
    rm -f "$TARGET_PATH"
    exit 5
fi

chmod +x "$TARGET_PATH"
echo "[+] Verified: $TARGET_PATH (SHA256 OK)" >&2

if [ $DO_RUN -eq 1 ]; then
    echo "[+] Running audit..." >&2
    echo >&2
    # shellcheck disable=SC2086
    "$TARGET_PATH" $RUN_ARGS
    RC=$?
    rm -f "$TARGET_PATH"
    exit $RC
else
    echo >&2
    echo "  To run: $TARGET_PATH" >&2
fi
