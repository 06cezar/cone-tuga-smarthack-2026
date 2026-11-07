# One-command setup on Windows (NFR-10): creates .venv, installs the requirements, turns on the git hook that refuses
# commits on main, runs the tests.
# Run with: powershell -ExecutionPolicy Bypass -File setup.ps1
# Native commands don't stop the script on failure in PowerShell 5.1, so each step checks its own exit code.

# Prefers Python 3.13; any Python from 3.11 up works (the tests need tomllib), as in setup.sh.
$MinimumCheck = "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
$Candidates = @(@("py", "-3.13"), @("py", "-3"), @("python"))
$Python = $null
foreach ($candidate in $Candidates) {
    if (-not (Get-Command $candidate[0] -ErrorAction SilentlyContinue)) { continue }
    $arguments = @($candidate | Select-Object -Skip 1)
    & $candidate[0] @arguments -c $MinimumCheck 2>$null
    if ($LASTEXITCODE -eq 0) { $Python = $candidate; break }
}
if ($null -eq $Python) {
    Write-Host "Python 3.11 or newer is needed (3.13 preferred): install it from python.org, then run setup.ps1 again."
    exit 1
}
$arguments = @($Python | Select-Object -Skip 1)
& $Python[0] @arguments -m venv .venv
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
.venv\Scripts\python -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
git config core.hooksPath .githooks
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
.venv\Scripts\python -m pytest -q
exit $LASTEXITCODE
