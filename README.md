# ConeTuga

**Secure Networks, Simply Explained** (R Systems Hackathon 2026). ConeTuga scans a small network you own, explains each
risk in plain Romanian and English, tells you exactly how to fix it, and shows whether the fix worked.

> Status: hour 0. The commands under "Analyse scan files", "Live scan" and "UI" are the planned interface; this README
> is updated as each one lands.

## Setup (one command, Python 3.13)

- Windows: `powershell -ExecutionPolicy Bypass -File setup.ps1`
- Linux: `sh setup.sh`

Both create `.venv`, install the requirements and run the tests.

Live scans also need nmap (Windows: the nmap.org installer, which includes Npcap; Linux: `sudo apt install nmap`), and
administrator rights (`sudo` on Linux) for the scan step only. File analysis and the UI run without them.

## Analyse scan files (no network, no admin rights)

```bash
python -m conetuga analyse <folder> --out results/
```

Reads every nmap XML file in the folder and writes `results/findings.csv` and `results/scores.csv`. A file that can't be
read gets `ERROR` and the others still run.

## Live scan (administrator rights for this step only)

```bash
python -m conetuga scan --confirm
```

Finds the network it is connected to, scans only that subnet, refuses public IP ranges and anything outside the
allowlist, and refuses to start without `--confirm`. The result goes through the same analysis.

## UI

```bash
streamlit run ui/app.py
```

## Safety

We built and scanned only our own phone-hotspot lab, under the rules of engagement we signed.

## Repository

- `specs/00-brief.md`: the R Systems brief, our contract · `specs/contracts.md`: how the parts talk to each other
- `data/catalog.toml`: the official finding catalog · `tests/fixtures/validation/`: the Validation Set and its answers
- `conetuga/`: analysis, explanations, guardrail, history · `ui/`: the web UI · `lab/`: our hotspot lab and its scans

## Team

ConeTuga, 5 students: A parser and rules · B explanations · C guardrail and security · D UI, history and pitch ·
E lab and QA.
