@echo off
REM Build a standalone vuln_corrector.exe on Windows.
cd /d "%~dp0"
python -m pip install --upgrade pyinstaller
python build.py
echo Binary is in .\dist\vuln_corrector.exe
