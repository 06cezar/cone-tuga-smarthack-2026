# ConeTuga

**Secure Networks, Simply Explained** (R Systems Hackathon 2026). ConeTuga scans a small network you own, explains each
risk in plain Romanian and English, tells you exactly how to fix it, and shows whether the fix worked.

> Status: hour 0. This README grows as features land.

## Setup (Windows, Python 3.13)

```bat
py -3.13 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m pytest -q
```

## Setup (Linux)

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pytest -q
```

Live scans also need nmap (Windows: the nmap.org installer, which includes Npcap; Linux: `sudo apt install nmap`), and
administrator rights (`sudo` on Linux) for the scan step only. Analysis and the UI run without them.

## Safety

ConeTuga only scans the network it is connected to, refuses public IP ranges, and asks for `--confirm` before a live
scan. We built and scanned only our own phone-hotspot lab.

## Repository

- `specs/00-brief.md`: the R Systems brief, our contract · `specs/contracts.md`: how the parts talk to each other
- `data/catalog.toml`: the official finding catalog · `tests/fixtures/validation/`: the Validation Set and its answers
- `conetuga/`: analysis, explanations, guardrail, history · `ui/`: the web UI · `lab/`: our hotspot lab and its scans

## Team

ConeTuga, 5 students: A parser and rules · B explanations · C guardrail and security · D UI, history and pitch ·
E lab and QA.
