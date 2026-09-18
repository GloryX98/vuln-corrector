#!/usr/bin/env bash
# Launch the browser UI on macOS / Linux. Opens http://127.0.0.1:8000
cd "$(dirname "$0")"
PY="$(command -v python3 || command -v python)"
exec "$PY" app.py "$@"
