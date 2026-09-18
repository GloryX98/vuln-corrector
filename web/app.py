#!/usr/bin/env python3
"""Compatibility shim - the web server now lives in the top-level webui.py."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import webui  # noqa: E402

if __name__ == "__main__":
    webui.main()
