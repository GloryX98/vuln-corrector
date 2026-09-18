@echo off
REM Launch the browser UI on Windows. Opens http://127.0.0.1:8000
cd /d "%~dp0"
python app.py %*
