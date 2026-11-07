# Setup pentru fiecare coleg (10 minute)

1. Acceptă invitația la repo, primită pe email de la GitHub.
2. Clonează într-o cale scurtă: `git clone <link> C:\Users\<tu>\Desktop\cone-tuga-smarthack-2026`
3. În folderul repo-ului, pune-ți emailul „noreply” de pe GitHub (GitHub → Settings → Emails):
   `git config user.email <adresa-ta-noreply>`
4. Instalează și verifică, dintr-o singură comandă: `powershell -ExecutionPolicy Bypass -File setup.ps1` pe Windows,
   `sh setup.sh` pe Linux. Comanda face `.venv`, instalează pachetele și rulează testele.
5. Fă-ți `CLAUDE.local.md` în folderul principal al repo-ului (git îl ignoră), cu rândul stream-ului tău:
   - **A:** „Sunt pe stream-ul A: parser, reguli, scor. Fișierele mele: `conetuga/analysis/`, `data/catalog.toml`.
     Întreabă înainte să atingi altceva.”
   - **B:** „Sunt pe stream-ul B: explicații și fix-uri. Fișierele mele: `conetuga/explain/`, `data/explanations.toml`.
     Întreabă înainte să atingi altceva.”
   - **C:** „Sunt pe stream-ul C: guardrail, securitate, export CSV. Fișierele mele: `conetuga/guard/`. Întreabă
     înainte să atingi altceva.”
   - **D:** „Sunt pe stream-ul D: UI, istoric, pitch. Fișierele mele: `ui/`, `conetuga/history/`, `PITCH.md`, `docs/`.
     Întreabă înainte să atingi altceva.”
   - **E:** „Sunt pe stream-ul E: laboratorul și QA. Fișierele mele: `lab/`, `tests/fixtures/`. Întreabă înainte să
     atingi altceva.”
6. Pornește Claude Code din folderul repo-ului. Primul mesaj: „Citește CLAUDE.md, specs/00-brief.md și
   specs/contracts.md.”
7. Git: branch din `main` actualizat, Pull Request, merge măcar o dată pe oră. Nimeni nu lucrează direct pe `main`.

Pe laptopul care scanează mai trebuie nmap cu Npcap (de pe nmap.org) și gitleaks.
