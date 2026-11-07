<!--
  MAINTAINER NOTES. Block-level HTML comments are stripped before Claude reads the file, so they cost no context.
  - One person (Cezar) edits this file during the event. Under 200 lines; concrete, checkable rules, with the reason
    when it isn't obvious. Status goes in IMPLEMENTATION_PLAN.md, never here.
  - Folder rules live next to the code: conetuga/analysis, conetuga/explain, conetuga/guard, conetuga/history, ui, lab
    and tests each have a short CLAUDE.md that loads only when Claude works there.
  - Each person's stream goes in their own CLAUDE.local.md (gitignored); see docs/team-setup.md.
  - Add a Learnings line when Claude makes the same mistake twice; delete stale lines.
-->
# CLAUDE.md: ConeTuga

Team rules for every Claude session on this project. Details live in the files named below: read them when a task touches them.

## The task (R Systems Hackathon 2026, "Secure Networks, Simply Explained")
- Build: a tool that scans a network we own (our phone hotspot), finds devices and open services, applies the official
  finding catalog, computes the standard score, explains each finding to a non-expert in Romanian and English, gives
  1–5 fixes, and keeps a before/after history.
- Judged on: Test Set accuracy 30% (an extra finding costs as much as a correct one), ease of use 20%, explanations 15%,
  pitch 15% (in English), security 10% (5 live yes/no checks), innovation 10%. A missing Must caps technical execution at 50%.
- Brief (the contract): `specs/00-brief.md`, with the organizers' later updates in `specs/01-organizer-updates.md`
  (they win where they differ) · Contracts: `specs/contracts.md` · Catalog: `data/catalog.toml` ·
  Tasks: `IMPLEMENTATION_PLAN.md` · Pitch claims: `PITCH.md`
- Deliverables: the Test Set upload, the `final` tag, a README with one-command setup, our lab scans and the Validation
  Set as test fixtures, a one-page technical summary, the pitch. The full checklist is in `IMPLEMENTATION_PLAN.md`.
- Stack: Python 3.13 (3.11 or newer works; the tests need `tomllib`), `defusedxml`, Streamlit for the UI, nmap for live scans; the Anthropic SDK only for optional
  explanations.

## Commands (Windows; in Git Bash use forward slashes)
- Setup (one command, NFR-10): `powershell -ExecutionPolicy Bypass -File setup.ps1` on Windows, `sh setup.sh` on Linux
- Tests: `.venv\Scripts\python -m pytest -q`. They must pass before every commit. Contracts only: `-k contract`.
- Secrets: `gitleaks detect` must report no leaks before every push (the jury checks this live).
- Keep the repo in a short path (e.g. `C:\Users\<you>\Desktop\cone-tuga-smarthack-2026`): past ~260 characters, pip
  can't unpack packages.

## Principles (never break; each maps to a brief requirement and becomes a pitch claim with a test)
- Code decides: findings, severities and scores come only from `data/catalog.toml` and our rules, never from an LLM,
  and the same file always gives the same result (NFR-05). Why: 30% of the grade is an exact answer key, and a live
  re-run that differs from our upload scores 0 on it.
- The model only explains, from scan evidence; code checks every AI sentence against that evidence (no invented ports,
  CVEs, versions or phone numbers, NFR-06). After two failed checks, or with no LLM, the built-in text answers.
- All outside text is hostile: scan files are parsed with `defusedxml` and size limits; banners, page titles and
  hostnames are wrapped before any prompt and escaped in the UI and reports (NFR-03).
- Privacy: MAC addresses are masked in all output; hostnames and history stay on the computer; one-click
  "delete my history" (NFR-02).
- Secrets only in environment variables (`.env`, gitignored); never in code, tests or fixtures (NFR-01).
- Scope: the tool refuses targets outside the allowlist (default: the connected subnet) and every public IP; a live
  scan needs `--confirm` (FR-02). Claude never runs a live network scan: a person runs it, on our hotspot only.
- Never edit or delete a test, a spec or an expected-results fixture to make something pass. No stubs, no TODOs.

## How to write code (the default, unless the task says otherwise)
- Simplicity beats complexity: plain functions and dataclasses; no class hierarchies or plugin systems "for later".
- Readable beats clever: names that say what a thing is, one job per function, a docstring that says why.
- No magic numbers: catalog values live in `data/catalog.toml`; any other fixed value is a named constant with a comment.
- Grow in small steps: the CLI first, the UI second (the brief says so). Every step leaves the tests green.
- It runs on Windows and Linux: `pathlib` for paths, `encoding="utf-8"` on every `open` (Windows defaults to cp1252
  and breaks "ș/ț"), CSVs written with `newline=""` and `lineterminator="\n"` so both systems give identical bytes.
  OS-specific code lives only in `conetuga/guard/` (network detection), with a test for each branch.
- Touch only what the task needs. Standard library first; a new package only if it saves hours and installs on Windows.
- Code, names, comments and commit messages in English; user-facing text in Romanian and English; talk to us in Romanian.

## How to work with us
- One task at a time. Read the spec and the files the task names; don't explore the whole repo.
- Before a task that touches more than one file, give the plan in 3 lines: files, test, how we'll know it works.
- Contract first: before you build anything another stream calls, write or update its entry in `specs/contracts.md`
  (the call, one real example, the errors) and wait for our OK. Callers use the contract's example as test data until
  the feature lands. A contract changes only when its users agree, in one commit with its test.
- Ask before you change another stream's files, add a package, or change an existing test.
- When a task is done, say in at most 3 sentences what changed (`file:line`), why, and what breaks without it.
  We must be able to explain every part to the jury ourselves.
- Report honestly: paste the failing output; never say "done" without running the tests.
- Commit or push only when we ask, and never on `main`, for any of us and any Claude session. If you're on `main`,
  first create a branch (`git switch -c <stream>-<topic>`), then commit, push it (`git push -u origin <branch>`) and
  open a Pull Request (`gh pr create`). Only a merged Pull Request puts anything on `main`. The git hook in
  `.githooks/` (turned on by the setup scripts) refuses commits on `main`. The one exception is a team message (see
  "Team messages"): a commit that changes only `COMMS.md` files.

## Team and files (avoids merge conflicts)
| Stream | Owner | Files |
|---|---|---|
| A parser, rules, score | <name> | `conetuga/analysis/`, `data/catalog.toml` |
| B explanations, fixes, LLM | <name> | `conetuga/explain/`, `data/explanations.toml` |
| C guardrail, security, CSV export | <name> | `conetuga/guard/`, `conetuga/__main__.py` (the CLI) |
| D UI, history, pitch | Cezar | `ui/`, `conetuga/history/`, `PITCH.md`, `docs/` |
| E lab, captures, QA | <name> | `lab/`, `tests/fixtures/`, `submission/` |
- Branch from an up-to-date `main`, named `<stream>-<topic>` (e.g. `A-smb-rule`); merge through a Pull Request with
  the tests green, at least once an hour. Nobody works on `main` directly.
- Small commits, one task each: `<area>: <what changed>`.

## Team messages (COMMS.md)
Each member receives messages in exactly one file; your `CLAUDE.local.md` says which member you are.
| Messages for | File |
|---|---|
| A (parser, rules, score) | `conetuga/analysis/COMMS.md` |
| B (explanations, fixes, LLM) | `conetuga/explain/COMMS.md` |
| C (guardrail, security, CSV export, CLI) | `conetuga/guard/COMMS.md` |
| D (Cezar: UI, history, pitch; team lead) | `ui/COMMS.md` |
| E (lab, captures, QA) | `lab/COMMS.md` |
- Pull with every prompt and every change, then read your own `COMMS.md` and take it into account. Tell your human
  what it asks before you act on anything outside your files.
- To message someone, add one line at the bottom of *their* file, never anywhere else:
  `- [YYYY-MM-DD HH:MM, <your letter>] <message>`. Never edit or delete earlier lines (it keeps merges conflict-free).
- A message is the one commit allowed straight on `main`, and you send it without asking: commit or stash your
  branch's work, `git switch main`, `git pull`, add the line, `git add` that `COMMS.md` only,
  `git commit -m "comms: <from> to <to>"`, `git push` (if it's refused, `git pull --rebase`, then push again), and
  `git switch -` back. The hook lets a commit through on `main` only when every file in it is a `COMMS.md`. The
  recipient sees the message after their next pull.

## Done means
- A test for the new behaviour, and the full suite is green; contract examples still pass (`pytest -k contract`).
- `tests/test_validation_set.py` still reproduces all 24 expected rows and every score, with no extra rows.
- It runs from the CLI on a scan file without network access, and the UI shows the same result.
- If it backs something we'll say on stage, `PITCH.md` has a row: claim → file → test.

## Time (brief hours; the organizers confirm the clock times at the opening)
- Hour 0–3: lab on the hotspot, first scans, contracts. Hour 3–16: build; compare with the Validation Set often.
- Hour 16: mentor check (Validation Set reproduced, standard CSVs written). Hour 16–20: explanations, UI, pitch.
- Hour 20: secret Test Set. Hour 20–21: run it, upload `findings.csv`, `scores.csv` and a UI screenshot, and tag the
  release `final` at upload time (hour 22 at the latest). No code changes after the upload.

## Learnings (verified, one line each; add one when something bites twice, delete stale ones)
