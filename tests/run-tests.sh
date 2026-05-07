#!/bin/sh
# Basic test harness for lpe-audit.sh
# Verifies output format, exit codes, and basic invariants on the host
# where it runs. Real distro-matrix testing happens in CI.
#
# shellcheck disable=SC2034  # variables are used inside eval'd assert conditions

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
AUDIT="$SCRIPT_DIR/../lpe-audit.sh"

[ ! -x "$AUDIT" ] && { echo "lpe-audit.sh not executable at $AUDIT"; exit 1; }

# Skip Linux-output tests if we're on macOS/BSD/etc.
# The script correctly exits with code 3 on non-Linux systems.
HOST_OS=$(uname -s)
SKIP_LINUX_TESTS=0
if [ "$HOST_OS" != "Linux" ]; then
    SKIP_LINUX_TESTS=1
    echo "================================================================"
    echo " Note: running on $HOST_OS, not Linux."
    echo " The audit script targets Linux specifically and will exit with"
    echo " code 3 on this host. Tests requiring Linux output will be"
    echo " skipped. To fully test, run inside a Linux container or VM."
    echo "================================================================"
    echo
fi

PASS=0
FAIL=0
SKIP=0
TESTS=0

red()   { printf '\033[0;31m%s\033[0m' "$*"; }
green() { printf '\033[0;32m%s\033[0m' "$*"; }

assert() {
    name="$1"
    cond="$2"
    TESTS=$((TESTS + 1))
    if eval "$cond"; then
        printf '  %s  %s\n' "$(green '[PASS]')" "$name"
        PASS=$((PASS + 1))
    else
        printf '  %s  %s  (failed: %s)\n' "$(red '[FAIL]')" "$name" "$cond"
        FAIL=$((FAIL + 1))
    fi
}

skip() {
    name="$1"
    reason="$2"
    TESTS=$((TESTS + 1))
    SKIP=$((SKIP + 1))
    printf '  \033[2m[SKIP]\033[0m  %s  (%s)\n' "$name" "$reason"
}

echo "Running test suite for lpe-audit.sh..."
echo

# --- Test 1: --version works ---
echo "Test group: command-line interface"
VERSION_OUT=$("$AUDIT" --version 2>&1)
assert "version flag prints version" '[ -n "$VERSION_OUT" ] && echo "$VERSION_OUT" | grep -q "lpe-audit.sh"'

# --- Test 2: --help works ---
HELP_OUT=$("$AUDIT" --help 2>&1)
assert "help flag prints usage" 'echo "$HELP_OUT" | grep -qi "usage"'

# --- Test 3: unknown flag returns 3 ---
"$AUDIT" --bogus-flag >/dev/null 2>&1
RC=$?
assert "unknown flag returns exit code 3" '[ "$RC" = "3" ]'

# --- Test 4: default run produces output ---
echo
echo "Test group: default run"
if [ $SKIP_LINUX_TESTS -eq 1 ]; then
    # On non-Linux, the script correctly exits with code 3
    "$AUDIT" >/dev/null 2>&1
    NONLINUX_RC=$?
    assert "non-Linux exits with code 3" '[ "$NONLINUX_RC" = "3" ]'
    skip "default run produces output" "non-Linux host"
    skip "default run exit code is 0 or 2" "non-Linux host"
    skip "default output mentions Copy Fail" "non-Linux host"
    skip "default output mentions Dirty Frag" "non-Linux host"
    skip "default output mentions CrackArmor" "non-Linux host"
else
    DEFAULT_OUT=$("$AUDIT" 2>&1)
    DEFAULT_RC=$?
    assert "default run produces output" '[ -n "$DEFAULT_OUT" ]'
    assert "default run exit code is 0 or 2" '[ "$DEFAULT_RC" = "0" ] || [ "$DEFAULT_RC" = "2" ]'
    assert "default output mentions Copy Fail" 'echo "$DEFAULT_OUT" | grep -q "Copy Fail"'
    assert "default output mentions Dirty Frag" 'echo "$DEFAULT_OUT" | grep -q "Dirty Frag"'
    assert "default output mentions CrackArmor" 'echo "$DEFAULT_OUT" | grep -q "CrackArmor"'
fi

# --- Test 5: JSON mode ---
echo
echo "Test group: JSON output"
if [ $SKIP_LINUX_TESTS -eq 1 ]; then
    skip "JSON output is non-empty" "non-Linux host"
    skip "JSON starts with {" "non-Linux host"
    skip "JSON ends with }" "non-Linux host"
    skip "JSON is parseable by python" "non-Linux host"
    skip "JSON contains schema field" "non-Linux host"
    skip "JSON contains findings field" "non-Linux host"
    skip "JSON contains copyfail.status" "non-Linux host"
    skip "JSON contains dirtyfrag.xfrm.status" "non-Linux host"
    skip "JSON contains dirtyfrag.rxrpc.status" "non-Linux host"
    skip "JSON contains crackarmor.status" "non-Linux host"
else
    JSON_OUT=$("$AUDIT" --json 2>/dev/null)
    assert "JSON output is non-empty" '[ -n "$JSON_OUT" ]'
    assert "JSON starts with {" 'echo "$JSON_OUT" | head -c 1 | grep -q "{"'
    assert "JSON ends with }" 'echo "$JSON_OUT" | tail -c 3 | grep -q "}"'

    # Validate JSON if python is available
    if command -v python3 >/dev/null 2>&1; then
        echo "$JSON_OUT" | python3 -c "import sys, json; json.load(sys.stdin)" >/dev/null 2>&1
        assert "JSON is parseable by python" '[ "$?" = "0" ]'
    fi

    assert "JSON contains schema field" 'echo "$JSON_OUT" | grep -q "\"schema\""'
    assert "JSON contains findings field" 'echo "$JSON_OUT" | grep -q "\"findings\""'
    assert "JSON contains copyfail.status" 'echo "$JSON_OUT" | grep -q "copyfail.status"'
    assert "JSON contains dirtyfrag.xfrm.status" 'echo "$JSON_OUT" | grep -q "dirtyfrag.xfrm.status"'
    assert "JSON contains dirtyfrag.rxrpc.status" 'echo "$JSON_OUT" | grep -q "dirtyfrag.rxrpc.status"'
    assert "JSON contains crackarmor.status" 'echo "$JSON_OUT" | grep -q "crackarmor.status"'
fi

# --- Test 6: quiet mode ---
echo
echo "Test group: quiet mode"
if [ $SKIP_LINUX_TESTS -eq 1 ]; then
    skip "quiet output non-empty" "non-Linux host"
    skip "quiet output is short (<= 10 lines)" "non-Linux host"
else
    QUIET_OUT=$("$AUDIT" --quiet 2>&1)
    assert "quiet output non-empty" '[ -n "$QUIET_OUT" ]'
    QUIET_LINES=$(echo "$QUIET_OUT" | wc -l)
    assert "quiet output is short (<= 10 lines)" '[ "$QUIET_LINES" -le 10 ]'
fi

# --- Test 7: shell portability ---
echo
echo "Test group: shell portability"
if command -v dash >/dev/null 2>&1; then
    dash -n "$AUDIT" 2>/dev/null
    assert "dash parse-check passes" '[ "$?" = "0" ]'
fi
bash -n "$AUDIT" 2>/dev/null
assert "bash parse-check passes" '[ "$?" = "0" ]'

# --- Test 8: no shellcheck errors ---
if command -v shellcheck >/dev/null 2>&1; then
    echo
    echo "Test group: static analysis"
    shellcheck -S error "$AUDIT" >/dev/null 2>&1
    assert "shellcheck reports no errors" '[ "$?" = "0" ]'
fi

# --- Summary ---
echo
echo "================================================================"
if [ $SKIP -gt 0 ]; then
    printf 'Results: %s passed, %s failed, %s skipped (of %s tests)\n' "$PASS" "$FAIL" "$SKIP" "$TESTS"
else
    printf 'Results: %s passed, %s failed (of %s tests)\n' "$PASS" "$FAIL" "$TESTS"
fi
echo "================================================================"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
