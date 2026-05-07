#!/usr/bin/env bash
# Verify integrity of kit files.
# Run from inside lpe-audit-kit/ directory.

set -e

cd "$(dirname "$0")"

echo "Checking script integrity..."
if [ -r SHA256SUMS ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c SHA256SUMS && echo "[OK] All files match expected hashes"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -c SHA256SUMS && echo "[OK] All files match expected hashes"
    else
        echo "No sha256sum/shasum tool available" >&2
        exit 1
    fi
else
    echo "SHA256SUMS file not found; skipping verification" >&2
    exit 1
fi
