# Demo-ul la juriu: pașii pentru Mihnea și E

Ghidul pe care îl urmăm pe laptopul lui Mihnea (scanner-ul echipei), la ora 20–22 și în sesiunea de 15 minute cu
juriul (7 minute de pitch, apoi cele 7 verificări live, în ordinea din brief). Toate comenzile se dau **din folderul
principal al repo-ului** (`~/Desktop/SmartHack/cone-tuga-smarthack-2026`): `python -m conetuga` merge doar de acolo.
Comenzile de la verificările 1, 5 și 7 au fost rulate pe 7 noiembrie și dau rezultatul scris aici; cele de la
verificarea 4 sunt refuzate de guardrail înainte să pornească nmap (`conetuga/guard/scan.py`).

## Cine ce face

| Cine | Rol |
|---|---|
| **Mihnea (A)** | ține laptopul și tastează comenzile; deschide UI-ul; explică analiza (findings, scor) |
| **E (Stefan)** | telefonul cu hotspot-ul; `submission/` și tag-ul `final`; citește cu voce tare ce cere juriul; povestește laboratorul (ce a oprit între scanări) |

## Ora 20–22: Test Set-ul și încărcarea (E conduce, Mihnea tastează)

Regula acestor ore: **din momentul în care rulăm Test Set-ul, nimeni nu mai face merge de cod în `main`** până după
tag. Tag-ul `final` trebuie să marcheze exact codul care a produs rezultatele, iar brief-ul îl cere **la momentul
încărcării** („Git repository tagged final at upload time”, pagina 13). De aceea ordinea e: rezultate → PR cu
`submission/` → tag → încărcarea imediată a acelorași fișiere.

1. Descarcă Test Set-ul într-un folder **în afara repo-ului**, de ex. `~/TestSet/`. Dacă e o arhivă, dezarhiveaz-o și
   verifică să nu fie un folder în alt folder (`~/TestSet/TestSet/`): `analyse` refuză atunci și numește subfolderul.
   Apoi `ls ~/TestSet` și mută afară doar ce e clar un fișier în plus al organizatorilor (un README, un PDF, o foaie
   de răspunsuri): `analyse` citește orice fișier care nu e ascuns, și fiecare ar adăuga un rând ERROR în
   `scores.csv`. Nu muta niciodată un `.xml` sau un fișier necunoscut: cel stricat poate avea altă extensie.
2. Pe `main` la zi, rulează pe tot folderul:
   ```bash
   git switch main && git pull
   env | grep CONETUGA_CHAIN || echo "fara blockchain"   # trebuie să scrie: fara blockchain
   grep -E '^ *(export )?CONETUGA_CHAIN_' .env           # nici în .env (citit de CLI): nu trebuie să scrie nimic
   .venv/bin/python -m conetuga analyse ~/TestSet --out submission/
   ```
   Dacă `env` arată vreo variabilă `CONETUGA_CHAIN_*`, rulează întâi
   `unset CONETUGA_CHAIN_RPC_URL CONETUGA_CHAIN_CONTRACT CONETUGA_CHAIN_PRIVATE_KEY`, sau comentează-le în `.env`
   (pune `#` în fața lor) dacă al doilea `grep` le arată acolo: altfel `analyse` încearcă să
   trimită amprentele jurnalului pe un blockchain (#62). CSV-urile nu se schimbă, dar Test Set-ul nu are nevoie de
   rețea. Rândul `Jurnal: N constatări salvate` de la final e normal: e jurnalul local din `.history/`.
3. Verifică repede: `wc -l submission/findings.csv submission/scores.csv` (un rând de antet plus câte un rând pe
   finding / pe fișier) și `grep ERROR submission/scores.csv` (brief-ul spune că un fișier e stricat).
4. Fă captura de ecran a UI-ului (vezi „Înainte de sesiune”, pasul 3), cu unul dintre fișierele Test Set-ului deschis,
   și salveaz-o ca `submission/ui-screenshot.png`.
5. Pune rezultatele în repo, prin PR (nimic pe `main` direct), și fă merge imediat ce CI-ul e verde:
   ```bash
   git switch -c E-submission
   git add submission/ && git commit -m "submission: the Test Set results we upload"
   git push -u origin E-submission
   gh pr create --base main --head E-submission --title "submission: Test Set results as uploaded" --body "The files we upload, unchanged."
   gh pr checks --watch && gh pr merge --merge
   ```
6. Tag-ul `final` pe acel merge, **chiar înainte de încărcare** (nimic după tag nu mai contează):
   ```bash
   git switch main && git pull
   git tag final && git push origin final
   git ls-remote --tags origin final   # tag-ul e pe GitHub
   ```
7. **Imediat**, încarcă în formularul organizatorilor exact fișierele din `submission/`: `findings.csv`, `scores.csv`
   și `ui-screenshot.png`, **până la ora 21**. Tag-ul și încărcarea sunt la câteva minute distanță, cu aceleași
   fișiere. După tag: nicio schimbare de cod.

   **Dacă până la ora 21 au rămas sub 10 minute** și CI-ul n-a terminat: pune tag-ul pe `main` așa cum e (e același
   cod care a produs rezultatele, pentru că nimeni n-a mai făcut merge), urcă-l, încarcă, iar PR-ul cu `submission/`
   intră după. Tag-ul nu se mută și nu se șterge niciodată.

## Înainte de sesiune (cu 30 de minute înainte)

1. **Mihnea:** repo-ul la zi, testele verzi, și niciun blockchain setat în terminal (verificările 1 și 5 rulează
   `analyse`, care altfel ar încerca să trimită amprentele jurnalului):
   ```bash
   git switch main && git pull
   .venv/bin/python -m pytest -q
   env | grep CONETUGA_CHAIN || echo "fara blockchain"   # trebuie să scrie: fara blockchain
   grep -E '^ *(export )?CONETUGA_CHAIN_' .env           # nici în .env (citit de CLI): nu trebuie să scrie nimic
   ```
2. **E:** hotspot-ul `RSH-ConeTuga` pornit, cu ecranul Personal Hotspot deschis pe telefon (iPhone-ul nu se arată
   dispozitivelor noi altfel). **Mihnea:** conectează-te la `RSH-ConeTuga` (meniul Wi-Fi sau
   `nmcli connection up RSH-ConeTuga`) și verifică: `nmcli -t -f DEVICE,CONNECTION device status` arată
   `RSH-ConeTuga`.
3. **Mihnea:** pornește UI-ul și pregătește istoricul pentru verificarea 6:
   ```bash
   .venv/bin/streamlit run ui/app.py
   ```
   În pagină: „🗑️ Șterge istoricul meu”; apoi, la „Alege o scanare din exemple”, `scan_01.xml` (din `lab/scans`),
   apoi `scan_03.xml`. Istoricul are acum înainte/după al laboratorului nostru. Istoricul compară singur doar scanări
   ale aceleiași rețele (#35, #40), deci fișierele juriului nu se amestecă cu laboratorul și nu mai trebuie șters
   între verificări.
   Verifică și modul: comutatorul „Avansat (Cone 🐇)” din stânga **oprit**, ca juriul să înceapă cu Tuga 🐢.
4. **E:** `submission/` are exact ce am încărcat, iar tag-ul e pe GitHub: `git ls-remote --tags origin final`.
5. Laptopul în priză; încărcătorul la îndemână.

## Cele 7 verificări live, în ordinea juriului

### 1. Re-rulare: juriul alege un fișier din Test Set, rezultatul trebuie să fie cel încărcat
E citește cu voce tare fișierul ales. Mihnea rulează pe tot Test Set-ul și compară cu ce am încărcat:
```bash
.venv/bin/python -m conetuga analyse ~/TestSet --out /tmp/rerun \
  && diff /tmp/rerun/findings.csv submission/findings.csv \
  && diff /tmp/rerun/scores.csv submission/scores.csv && echo IDENTICAL
```
Așteptat: `IDENTICAL` (același fișier dă mereu același rezultat, octet cu octet). Apoi rândurile fișierului ales:
`grep '^<fișier>' submission/findings.csv`, și același fișier încărcat în UI („sau încarcă fișierul tău nmap XML”).

### 2. Sarcina practică: un membru al juriului folosește UI-ul singur
Deschide în UI fișierul juriului și dă-i laptopul. **Nu spunem nimic.** Primul ecran răspunde „Cel mai periculos
dispozitiv și ce fac întâi”: titlul mare de pe Acasă, spus de Tuga 🐢 (desenul și numele lui sunt lângă titlu), apoi
scorul cu semaforul, apoi dispozitivele, de la cel mai periculos, primul deschis.

### 3. Explicațiile: trei findings alese de juriu
În UI, deschide cele trei findings: explicația (cel mult 2 propoziții) și pașii (1–5). Comută RO/EN dacă cer.
- Pe **Acasă** sunt toate dispozitivele, fiecare cu problemele lui. Pe pagina **Dispozitive** (meniul din stânga) le
  filtrezi după risc sau tip și le ordonezi: cel mai repede ajungi la un finding anume.
- Dacă juriul e tehnic, pornește „Avansat (Cone 🐇)”: Cone dă textul tehnic, codul din catalog, dovada (portul,
  serviciul, programul și versiunea văzute de nmap) și referințele CIS Controls / OWASP IoT. Titlul de sus nu se
  schimbă.

### 4. Guardrail-ul: un IP public și rețeaua locației sunt refuzate
```bash
.venv/bin/python -m conetuga scan 8.8.8.8 --confirm
.venv/bin/python -m conetuga scan 10.240.0.0/16 --confirm
```
Așteptat: ambele refuzate, cu motivul în română și engleză, și nmap nu pornește. `10.240.0.0/16` e rețeaua Wi-Fi a
locației („UnivBuc”); dacă juriul dă alt interval al locației, folosește-l pe acela. Pe Wi-Fi-ul locației orice
scanare e refuzată (nu e `RSH-ConeTuga`). Fără `--confirm`, și scanarea propriei rețele e refuzată.
În UI, pagina **Scanare** arată același lucru fără să ruleze nimic: rețeaua la care e conectat laptopul, „✅ Ești pe
hotspotul echipei” sau „⛔ Scanarea ar fi refuzată acum”, cu motivul, și comanda exactă de rulat.

### 5. Fișier stricat: o eroare clară, fără crash
În UI, deschide `V7_broken.xml` (sau fișierul stricat din Test Set). Din linia de comandă:
```bash
.venv/bin/python -m conetuga analyse tests/fixtures/validation/scans --out /tmp/v
```
Așteptat: `V7_broken.xml: EROARE / ERROR: ... not complete, valid XML ...`, iar celelalte 7 fișiere sunt analizate.

### 6. Istoricul: înainte/după din laboratorul nostru, cu scorul crescând
Fișierul juriului încărcat are prioritate față de lista de exemple: **întâi scoate-l din „sau încarcă fișierul tău
nmap XML” (×)**, apoi alege `scan_03.xml` din exemple; la „Compară cu scanarea de la” apare `scan_01`. Istoricul arată
`scan_01` → `scan_03`, scor **0 → 70**, 4 findings rezolvate, niciunul nou. E povestește ce a oprit Stefan: telnet și
FTP (0 → 50), apoi Redis (50 → 70). `scan_02` e pasul din mijloc, dacă îl cer.

### 7. Fără secrete în repo
```bash
gitleaks detect --source . --no-banner
```
Așteptat: `no leaks found`.

## Întrebări probabile, cu răspunsul pe scurt

- **„De ce laptopul din laborator apare ca imprimantă?”** Am simulat pe el un port de imprimantă (9100); scanările de
  laborator n-au portul Windows (135), deci nimic din ele nu spune „calculator”. Tipul e doar o etichetă: findings și
  scorul nu depind de el. Scanarea live, cu cele 1.000 de porturi, îl vede drept calculator.
- **„De ce e laptopul din laborator un dispozitiv necunoscut (UNKNOWN_DEVICE)?”** Prefixul MAC al plăcii lui Wi-Fi
  (`6C:2F:80`) nu e în lista de producători a nmap, iar hotspot-ul nu îi dă niciun nume: după catalog, n-are nici
  producător, nici hostname, și are porturi deschise.
- **„De ce are telefonul FTP deschis?”** Telefonul hotspot răspunde pe portul 21, fără banner; nmap îl numește „ftp”,
  iar catalogul decide după numele serviciului.
- **„De ce lipsește MQTT în laborator?”** Cu `-sV`, scriptul `mqtt-subscribe` al nmap pune versiunea brokerului în
  locul numelui serviciului; catalogul decide după nume, deci nu raportăm. E o limitare spusă deschis.
- **„Cine sunt Tuga și Cone?”** Doi ghizi pentru același rezultat: Tuga 🐢 explică pe înțelesul oricui (implicit),
  Cone 🐇 dă detaliile tehnice (comutatorul „Avansat”). Findings și scorul sunt aceleași: le decide codul, din
  catalog, nu ghidul și nu un AI.
- **„La ce folosește blockchain-ul?”** Jurnalul local al problemelor găsite (SQLite, în `.history/`) e protejat la
  modificări: la fiecare 10 rânduri, amprenta lor (SHA-256, legată de lotul dinainte) poate fi pusă într-un contract
  pe un blockchain de test. `ledger verify` arată ce lot a fost schimbat, șters sau inversat. Pleacă de pe calculator
  doar amprentele, și doar dacă un om setează cele trei variabile `CONETUGA_CHAIN_*`. Dacă juriul vrea să vadă, o
  arătăm pe un Anvil local (pe laptopul care are Foundry), nu pe o rețea publică. Util, de exemplu, pentru un
  asigurator care vrea dovada că jurnalul n-a fost rescris.
- **„E accesibil?”** Am verificat cu axe-core (regulile WCAG 2.1 AA) fiecare pagină, pe tema deschisă și pe cea
  închisă: 0 probleme. Textul are cel puțin 16 px, culoarea nu e niciodată singurul semn (mereu iconiță și cuvânt), și
  totul merge din tastatură, cu un contur albastru pe elementul curent.

## Dacă ceva nu merge

| Problemă | Ce faci |
|---|---|
| `RSH-ConeTuga` nu apare | E deschide ecranul Personal Hotspot pe telefon; apoi `nmcli connection up RSH-ConeTuga` |
| Laptopul a trecut singur pe Wi-Fi-ul locației | nu scana nimic; reconectează-te la `RSH-ConeTuga`. Verificările 1, 2, 3, 5, 6, 7 merg și fără rețea |
| UI-ul nu pornește | `.venv/bin/python -m pip install -r requirements.txt`, apoi din nou `streamlit run` |
| `diff` la verificarea 1 arată diferențe | nu repara nimic live: spunem cinstit ce s-a schimbat; după tag nu atingem codul |
| `analyse` spune că folderul e gol | scanările sunt într-un subfolder: dă calea pe care o numește mesajul |
