#!/usr/bin/env bash
set -euo pipefail

# Ensure we're in a git repo
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  echo "Not inside a Git repository. Run this from your repo root."
  exit 1
}

# Require a .gitignore in the repo root
if [[ ! -f ".gitignore" ]]; then
  echo "No .gitignore found at repo root. Create it first, then re-run."
  exit 1
fi

# Warn if working tree is dirty (uncommitted changes)
if git rev-parse --verify HEAD >/dev/null 2>&1; then
  if ! git diff-index --quiet HEAD --; then
    echo "Your working tree has uncommitted changes."
    echo "Commit or stash them before running this script."
    exit 1
  fi
fi

echo "=== Preview: paths that WOULD be ignored per your .gitignore ==="
# Show tracked paths that .gitignore would ignore (uses --no-index to force check)
git ls-files -z | git check-ignore -z --stdin --verbose --no-index || true
echo "================================================================"

read -r -p "Proceed to untrack all files ignored by .gitignore (reindex)? [y/N] " ans
case "${ans,,}" in
  y|yes) ;;
  *) echo "Aborted."; exit 0;;
esac

echo "[1/3] Removing all files from index (keeps working tree intact)."
git rm -r --cached -- . >/dev/null

echo "[2/3] Re-adding files (now .gitignore rules are enforced)."
git add .

echo "[3/3] Committing reindex."
git commit -m "Reindex: stop tracking files ignored by .gitignore"

echo "Done. Review and push:"
echo "  git push"
