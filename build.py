#!/usr/bin/env python3
"""
Cross-platform build script for vuln_corrector.

Run on the OS you want a binary for (PyInstaller cannot cross-compile):

    python build.py            # Windows  -> dist/vuln_corrector.exe
    python3 build.py           # macOS    -> dist/vuln_corrector
    python3 build.py           # Linux    -> dist/vuln_corrector

It installs PyInstaller if missing, then produces a single-file executable in ./dist.
"""
import os
import platform
import subprocess
import sys


def ensure_pyinstaller():
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller not found - installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])


def main():
    ensure_pyinstaller()
    here = os.path.dirname(os.path.abspath(__file__))
    os.chdir(here)
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile", "--console", "--name", "vuln_corrector",
        "--distpath", "dist", "--workpath", "build", "--specpath", "build",
        "vuln_corrector.py",
    ]
    print("Running:", " ".join(cmd))
    subprocess.check_call(cmd)
    ext = ".exe" if platform.system() == "Windows" else ""
    out = os.path.join("dist", "vuln_corrector" + ext)
    print(f"\nBuilt: {out}  ({platform.system()} {platform.machine()})")
    if platform.system() != "Windows":
        try:
            os.chmod(out, 0o755)
        except OSError:
            pass


if __name__ == "__main__":
    main()
