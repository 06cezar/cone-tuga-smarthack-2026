#!/bin/sh
# One-command setup on Linux (NFR-10): creates .venv, installs the requirements, runs the tests.
set -e
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pytest -q
