#!/usr/bin/env bash
# Push this tool to GitHub (macOS / Linux). Idempotent - safe to re-run.
#
# Prereqs:  macOS: brew install git gh   |   Linux: sudo apt install git gh
#
# Usage, from inside this 'tool' folder:
#   ./push_to_github.sh vuln-corrector private
#
# Sets a repo-local git identity from your GitHub account (GitHub no-reply email),
# runs 'gh auth login' if needed, then commits and creates/pushes the repo.
set -e
cd "$(dirname "$0")"

REPO="${1:?Usage: ./push_to_github.sh <repo-name> [private|public]}"
VIS="${2:-private}"

command -v git >/dev/null || { echo "git not found (install git)"; exit 1; }
command -v gh  >/dev/null || { echo "gh not found (install gh)"; exit 1; }

# 1. Authenticate if needed
if ! gh auth status >/dev/null 2>&1; then
    echo "Not logged in - launching 'gh auth login'..."
    gh auth login
fi
LOGIN="$(gh api user --jq .login)"
UID_="$(gh api user --jq .id)"
NAME="$(gh api user --jq '.name // .login')"
NOREPLY="${UID_}+${LOGIN}@users.noreply.github.com"

# 2. Repo + identity (repo-local only)
[ -d .git ] || git init -b main
if [ -z "$(git config user.email || true)" ]; then
    git config user.name  "$NAME"
    git config user.email "$NOREPLY"
    echo "Set repo-local identity: $NAME <$NOREPLY>"
fi

# 3. Commit if there is anything to commit
git add .
git commit -m "vuln_corrector: cross-platform Tenable CVSS & rating corrector" >/dev/null 2>&1 || echo "Nothing new to commit - continuing."

# 4. Create the remote (first run) or push (subsequent runs)
if git remote | grep -qx origin; then
    git push -u origin main
else
    gh repo create "$REPO" --"$VIS" --source=. --remote=origin --push
fi
echo "Done. Repo: https://github.com/${LOGIN}/${REPO}"
