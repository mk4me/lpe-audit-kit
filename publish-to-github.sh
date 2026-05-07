#!/usr/bin/env bash
#
# publish-to-github.sh - Initialize git repo and push to GitHub
# =============================================================
# Run this from inside the unpacked lpe-audit-kit/ directory.
#
# Prerequisites:
#   - git installed
#   - GitHub CLI installed:  https://cli.github.com/
#       Debian/Ubuntu:  sudo apt install gh
#       Fedora/RHEL:    sudo dnf install gh
#       macOS:          brew install gh
#   - Authenticated:  gh auth login
#
# What it does:
#   1. Initialize git repo (if not already)
#   2. Create initial commit
#   3. Create GitHub repo (public by default)
#   4. Push code
#   5. Create v1.0.0 tag and push (triggers release workflow)
#

set -euo pipefail

REPO_NAME="${1:-lpe-audit-kit}"
VISIBILITY="${2:-public}"   # public | private
DESCRIPTION="Portable read-only audit toolkit for the Q1-Q2 2026 Linux page-cache write LPE vulnerability cluster"

# --- Sanity checks ---
if ! command -v git >/dev/null 2>&1; then
    echo "ERROR: git not installed" >&2; exit 1
fi
if ! command -v gh >/dev/null 2>&1; then
    echo "ERROR: GitHub CLI (gh) not installed. See https://cli.github.com/" >&2
    exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
    echo "ERROR: gh not authenticated. Run: gh auth login" >&2
    exit 1
fi

if [ ! -f "lpe-audit.sh" ] || [ ! -f "README.md" ]; then
    echo "ERROR: Run this script from inside the lpe-audit-kit/ directory" >&2
    exit 1
fi

# --- Step 1: git init ---
if [ ! -d ".git" ]; then
    echo "[1/5] Initializing git repo..."
    git init -b main
else
    echo "[1/5] Git repo already initialized, skipping init"
fi

# --- Step 2: initial commit ---
echo "[2/5] Creating initial commit..."
git add .
if git diff --cached --quiet; then
    echo "       (no changes to commit)"
else
    git commit -m "Initial release v1.0.0

Portable audit toolkit for the Q1-Q2 2026 Linux page-cache write LPE
vulnerability cluster:

  - Copy Fail (CVE-2026-31431)
  - Dirty Frag #1 (xfrm-ESP, no upstream patch)
  - Dirty Frag #2 (RxRPC, no upstream patch)
  - CrackArmor (CVE-2026-23268..23411)

Read-only. POSIX-compatible. Fleet runner included."
fi

# --- Step 3: create GitHub repo ---
echo "[3/5] Creating GitHub repo: $REPO_NAME ($VISIBILITY)..."
if gh repo view "$REPO_NAME" >/dev/null 2>&1; then
    echo "       (repo already exists)"
    REMOTE_URL=$(gh repo view "$REPO_NAME" --json sshUrl -q .sshUrl)
else
    gh repo create "$REPO_NAME" \
        --"$VISIBILITY" \
        --description "$DESCRIPTION" \
        --homepage "https://github.com/$(gh api user -q .login)/$REPO_NAME" \
        --add-readme=false
    REMOTE_URL=$(gh repo view "$REPO_NAME" --json sshUrl -q .sshUrl)
fi

# --- Step 4: push ---
echo "[4/5] Pushing to GitHub..."
if ! git remote get-url origin >/dev/null 2>&1; then
    git remote add origin "$REMOTE_URL"
fi
git push -u origin main

# --- Step 5: tag and push v1.0.0 ---
echo "[5/5] Creating v1.0.0 tag..."
if git rev-parse v1.0.0 >/dev/null 2>&1; then
    echo "       (tag already exists)"
else
    git tag -a v1.0.0 -m "Release v1.0.0

Initial public release. See CHANGELOG.md for details."
    git push origin v1.0.0
    echo "       Tag pushed - this triggers the Release workflow which"
    echo "       will build the tarball and attach it to the GitHub Release."
fi

# --- Done ---
GH_USER=$(gh api user -q .login)
URL="https://github.com/$GH_USER/$REPO_NAME"
echo
echo "================================================================"
echo " Done!"
echo "================================================================"
echo
echo " Repo:     $URL"
echo " Releases: $URL/releases"
echo " Actions:  $URL/actions"
echo
echo " Share these one-liners with your colleagues:"
echo
echo "   git clone $URL.git"
echo "   curl -fsSL https://raw.githubusercontent.com/$GH_USER/$REPO_NAME/main/lpe-audit.sh | bash"
echo
echo " (Note: piping to bash skips integrity verification. Recommend"
echo "  cloning instead, or downloading the signed release tarball.)"
echo
