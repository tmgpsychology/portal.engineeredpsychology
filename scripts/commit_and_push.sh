#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: bash scripts/commit_and_push.sh \"Commit message\""
  exit 1
fi

COMMIT_MESSAGE="$1"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

echo "Checking repo status..."
git status --short

echo "Staging changes..."
git add -A

if git diff --cached --quiet; then
  echo "No staged changes to commit."
  exit 0
fi

echo "Staged changes:"
git diff --cached --stat

echo "Creating commit..."
git commit -m "${COMMIT_MESSAGE}"

echo "Pushing to GitHub..."
git push

echo "Done."
