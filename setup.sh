#!/bin/sh
# One-command setup on Linux (NFR-10): creates .venv, installs the requirements, turns on the git hook that refuses
# commits on main, runs the tests.
# Prefers Python 3.13; any python3 from 3.11 up works (the tests need tomllib).
set -e
PY=$(command -v python3.13 || command -v python3)
"$PY" -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
git config core.hooksPath .githooks
.venv/bin/python -m pytest -q
