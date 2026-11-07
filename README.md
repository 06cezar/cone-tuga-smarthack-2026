# ConeTuga

**Secure Networks, Simply Explained** (R Systems Hackathon 2026). ConeTuga scans a small network you own, explains each
risk in plain Romanian and English, tells you exactly how to fix it, and shows whether the fix worked.

## Setup (one command)

- Windows (needs Python 3.13, `py -3.13`): `powershell -ExecutionPolicy Bypass -File setup.ps1`
- Linux (Python 3.13, or any 3.11+): `sh setup.sh`

Both create `.venv`, install the requirements and run the tests. Run every command below **from the repository
folder** (`cd cone-tuga-smarthack-2026`), with the `.venv` Python: `.venv\Scripts\python` on Windows,
`.venv/bin/python` on Linux (written `python` below).

Live scans also need nmap (Windows: the nmap.org installer, which includes Npcap; Linux: `sudo apt install nmap`).
File analysis and the UI need no network and no administrator rights.

## Analyse scan files

```bash
python -m conetuga analyse <folder> --out results/
```

Reads every non-hidden file in the folder, whatever its extension, and writes `results/findings.csv` and
`results/scores.csv`. A file that can't be read gets `ERROR` and the others still run. A folder whose scans sit one
level down (an unzipped archive) is refused with the name of the subfolder to use.

## Live scan (our hotspot only)

```bash
python -m conetuga scan --confirm
python -m conetuga scan 172.20.10.0/28 --confirm --minutes 10
```

Finds the network it is connected to and asks the guardrail first: it refuses public IPs, the mobile carrier's range,
multicast, anything outside the connected subnet, any Wi-Fi other than `RSH-ConeTuga`, and anything without
`--confirm`. Then nmap runs at most 100 packets per second, with at most `--minutes` (default 5) per device; on Linux
only nmap gets administrator rights, so `sudo` asks for your password. The raw XML stays in `results/`
(`scan_<date>-<time>.xml`, real MACs and names, never committed) and goes through the same analysis.
Exit codes: 0 done, 2 couldn't run, 3 refused by the guardrail, 4 done but nmap gave up on some devices.

## UI

```bash
python -m streamlit run ui/app.py
```

The first screen says which device is the most dangerous and what to do first, then shows the traffic-light score,
every device with its findings, explanations and fix steps (RO/EN), the history with before/after and change alerts,
"Șterge istoricul meu", and a one-page report to download. Pick an example (the Validation Set or our lab scans) or
upload your own nmap XML.

## Safety

We built and scanned only our own phone-hotspot lab, under the rules of engagement we signed. MAC addresses keep only
their vendor part in every output; the history stays on this computer (`.history/`); no key or secret is needed.

## Repository

- `specs/00-brief.md`: the R Systems brief, our contract · `specs/contracts.md`: how the parts talk to each other
- `data/catalog.toml`: the official finding catalog · `tests/fixtures/validation/`: the Validation Set and its answers
- `conetuga/`: analysis, explanations and Q&A, guardrail and live scan, history · `ui/`: the web UI and report ·
  `lab/`: our hotspot lab, its masked scans and the mask · `docs/`: technical summary and jury-demo guide

## Team

ConeTuga, 5 students: A parser and rules · B explanations · C guardrail and security · D UI, history and pitch ·
E lab and QA.
