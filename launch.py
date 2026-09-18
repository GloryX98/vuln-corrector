#!/usr/bin/env python3
"""
Entry point for the packaged executable.

  * Double-click / run with no file  -> starts the local web interface and opens
    your browser (nothing is exposed to the internet; it listens only on your
    machine, and it - not the browser - talks to Tenable in the background).
  * Run with a sheet path (or --cli)  -> classic command-line correction.

Examples:
    vuln_corrector.exe                     # web interface
    vuln_corrector.exe findings.csv        # command line
    vuln_corrector.exe --web               # force the web interface
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import vuln_corrector          # noqa: E402  (bundled)
import webui                   # noqa: E402  (bundled)

DATA_EXTS = (".csv", ".xlsx", ".xlsm")


def main():
    argv = sys.argv[1:]
    force_web = "--web" in argv
    force_cli = "--cli" in argv
    has_file = any(os.path.splitext(a)[1].lower() in DATA_EXTS for a in argv if not a.startswith("-"))

    # remove launcher-only flags before delegating to the sub-tool's argparse
    sys.argv = [a for a in sys.argv if a not in ("--web", "--cli")]

    if force_cli or (has_file and not force_web):
        vuln_corrector.main()
    else:
        webui.main()


if __name__ == "__main__":
    main()
