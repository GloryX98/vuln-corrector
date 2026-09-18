#!/usr/bin/env bash
# Launch the browser UI on macOS / Linux (opens an uncommon local port automatically).
cd "$(dirname "$0")/.."
PY="$(command -v python3 || command -v python)"
exec "$PY" webui.py "$@"
