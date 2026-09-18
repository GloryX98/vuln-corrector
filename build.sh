#!/usr/bin/env bash
# Build a standalone vuln_corrector binary on macOS or Linux.
set -e
cd "$(dirname "$0")"
PY="$(command -v python3 || command -v python)"
if [ -z "$PY" ]; then echo "Python 3 not found on PATH."; exit 1; fi
"$PY" -m pip install --user --upgrade pyinstaller
"$PY" build.py
echo "Binary is in ./dist/vuln_corrector"
