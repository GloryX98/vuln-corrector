@echo off
REM Launch the browser UI on Windows (opens an uncommon local port automatically).
cd /d "%~dp0\.."
python webui.py %*
