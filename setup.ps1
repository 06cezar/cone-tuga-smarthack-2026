# One-command setup on Windows (NFR-10): creates .venv, installs the requirements, turns on the git hook that refuses
# commits on main, runs the tests.
# Run with: powershell -ExecutionPolicy Bypass -File setup.ps1
# Native commands don't stop the script on failure in PowerShell 5.1, so each step checks its own exit code.
py -3.13 -m venv .venv
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
.venv\Scripts\python -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
git config core.hooksPath .githooks
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
.venv\Scripts\python -m pytest -q
exit $LASTEXITCODE
