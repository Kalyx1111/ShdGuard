#!/usr/bin/env bash
cd "$(dirname "$0")" || exit 1
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv || { read -r -p "Could not create .venv (Debian/Ubuntu: sudo apt install python3-venv). Press Enter to exit..."; exit 1; }
fi
.venv/bin/python -m pip install --quiet --disable-pip-version-check -r ShdRequirements.txt || { read -r -p "Dependency install failed (offline?). Press Enter to exit..."; exit 1; }
.venv/bin/python ShdGuard.py "$@"
