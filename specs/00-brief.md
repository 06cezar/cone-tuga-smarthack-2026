# R Systems Hackathon 2026: Participant Brief (text extras din PDF)

Sursa: `R Systems Hackathon 2026 - Participant Brief.pdf`, 16 pagini. Tabelele din PDF apar aici ca text, rând cu rând.

## Pagina 1

R Systems Hackathon 2026 
Secure Networks, Simply Explained 
 
All rights reserved. Public 
 
Dear participant,  
 
Thank you for being part of this hackathon and taking on our challenge! We’re looking forward to seeing 
your ideas, getting to know you and building alongside you this weekend. 
Now, most people have no idea what is connected to their Wi -Fi, which doors are open, or what that 
means. Your job this weekend is to change that, safely, ethically, and on a network you own. 
Read this brief before kickoff and keep it at your team table.  
Part A explains who we are and how you will be evaluated.  
Part B (the requirements) is the contract your prototype must meet, because every team will run its tool, 
live, on the same standard test data and be checked against the same answer key. 
Build something that works! Explain it simply! Never scan what you do not own! 
 
Good luck and enjoy the experience! 
The R Systems team  
 
In 24 hours, your team builds a tool that scans a small network it owns, explains the risks in plain 
language, and tells a non-technical person exactly how to fix them. 
Item Detail 
Event R Systems Hackathon 2026 — Secure Networks, Simply Explained 
Format 24 hours, partially on-site (dates and venue: TBD) 
Mission Make everyday networks safer by making their risks visible and understandable 
                                                                             
Part A 
Who we are: About R Systems 
R Systems is a global software engineering company where we build technology that connects people, 
solves practical problems and makes everyday experiences better.

## Pagina 2

R Systems Hackathon 2026 
Secure Networks, Simply Explained 
 
All rights reserved. Public 
 
Founded in 1993 and backed by Blackstone, we bring together 5,300+ professionals across 20 countries. 
In Romania, our offices are in Bucharest, Craiova and Galați  and our work spans telecommunications, 
cloud, AI, automation and digital platforms.  
We’ve helped mobile operators evolve from 2G to 5G, built systems that process thousands of 
transactions per second and developed our own tools to automate complex software testing.  
Today, we also help companies modernize applications and turn AI ideas into reliable solutions through 
EXIQO, our AI Studio. Depending on the project, our teams work with technologies such as Spring Boot, 
React, Angular, Docker, Kubernetes and AWS.  
Behind our technology is a culture of curiosity, collaboration and continuous learning, where different 
perspectives matter.  
That’s the spirit we’re bringing to this hackathon: sharing knowledge, exploring ideas together and 
building something useful for the people who will use it. 
Value What it means this weekend 
Care For users, teammates and anyone affected by what we build. 
Your tool is for a parent or grandparent, not for a security expert. 
Innovation Stay ahead by rethinking people, process and technology. Show 
us an idea worth remembering, not a wrapper around nmap. 
Human-centered Technology should enhance human potential. If a non -technical 
user cannot act on your output, it has not worked. 
Diversity and inclusion Mixed-seniority teams by design. Everyone builds, everyone 
presents. 
Integrity Confidentiality, integrity and privacy are part of our ISO 
commitments. No fabricated results, no scanning without 
consent. 
 
What matters to us and what we’ll look for in your project 
Four public R Systems priorities shape our work with clients, and the jury will look at your project 
through them. 
1. AI -native engineering: R Systems describes its strategy as AI -native: its EXIQO AI Studio combines 
1,400+ AI-native engineers, the OptimaAI platform and 150+ reusable AI agents with a governed delivery 
method (Q2 2026 results, EXIQO launch). For you, that means using AI where it adds value: turning raw 
scan data into explanations, prioritized fixes and conversation. It also means governance: the AI must 
never invent a finding the scan did not show.

## Pagina 3

R Systems Hackathon 2026 
Secure Networks, Simply Explained 
 
All rights reserved. Public 
 
2. Security, cybersecurity and privacy by design: Our integrated management system follows ISO 27001 
(information security) and ISO 27701 (privacy). Treat secrets, device data and MAC addresses as 
personal data. No hard-coded keys, least privilege, and every input treated as hostile, including the scan 
files you parse. 
3. Quality you can measure : We operate to ISO 9001 and commit to delivering services in the most 
efficient and effective way. Every team is checked against the same standard test data and the same 
answer key, so correctness beats polish. 
4. Human experience first: Our purpose is to enhance human experience through technology. A security 
score nobody understands changes nothing; a clear sentence and one concrete step does. 
This is exactly the territory of the hackathon theme. 
Hackathon at a glance 
Item Detail 
Format 24 hours, partially on -site (e.g. Saturday 08:30 –19:00, Sunday 08:30–
17:00) 
Teams 4–5 students each, mixed seniority by design 
Mentors R Systems engineers, security specialists and architects, rotating across 
teams 
Jury R Systems managers and a solution architect 
Theme Secure Networks, Simply Explained — a local network security checker 
Test environment Built by each team on its own phone hotspot; R Systems provides no 
VMs or targets 
Standard data Public Validation Set (with answers) at kickoff; secret Test Set for 
everyone at hour 20 
Deliverables Working tool + simple UI + standard results files + 5 –7 minute pitch + 
1-page technical summary 
Languages Code in any language; pitch in English; user -facing text in Romanian 
and English 
 
How the 24 hours flow 
Hours What happens

## Pagina 4

R Systems Hackathon 2026 
Secure Networks, Simply Explained 
 
All rights reserved. Public 
 
Hours What happens 
0 Opening, theme reveal, rules of engagement signed, Validation Set and finding catalog 
released 
1–3 Build your own hotspot lab (see the example setups), capture your first scans, agree 
the scope 
3–16 Build. Compare your results with the Validation Set answers early and often. 
16 Mentor check:  your tool reproduces the Validation Set answers and writes the 
standard results files 
16–20 Improve explanations and UI, prepare the pitch, rehearse the live checks 
20 Secret Test Set released to all teams at the same moment 
20–21 Run your tool on the Test Set and upload the results. No code changes after upload. 
21–24 Jury sessions (15 minutes per team), then awards 
The theme: Secure Networks, Simply Explained 
Challenge statement. Build a tool that discovers the devices on a local network you own, identifies open 
ports and visible services, explains what they could mean in plain language, gives step -by-step fixes and 
a security score, and keeps a history so users can see whether risks were resolved. 
Why this matters. Home and small-office networks now carry smart TVs, cameras, printers, routers with 
default settings and forgotten laptops. Each open service is a door. Professional scanners show those 
doors to experts. Almost nothing shows them to the person who owns the network and has to close 
them. 
What "secure" means in this challenge 
• Visibility: you know what is connected and what it exposes. 
• Understanding: each finding is explained in one or two sentences a non -expert can follow, 
without jargon. 
• Action: each finding comes with a concrete next step, ranked by risk. 
• Proof: history shows the score improving after the fix, not just a promise that it will. 
Example directions (not limited to these) 
• A "network health check" for families, with a traffic-light score and one fix at a time. 
• An AI assistant that answers "is it safe that my printer has port 9100 open?" using only the real 
scan as evidence. 
• A before/after report a small business can show its insurer or IT supplier.

## Pagina 5

R Systems Hackathon 2026 
Secure Networks, Simply Explained 
 
All rights reserved. Public 
 
• Router-specific remediation guides (e.g. "how to turn off WPS on this model") generated from 
the detected device type. 
• Change detection: alert when a new device appears or a new port opens since the last scan. 
The scenario: your own hotspot lab 
Every team designs, builds and scans its own small network made from one phone hotspot. R Systems 
provides no VMs and no ready -made targets: creating a realistic, safe test environment is part of the 
challenge. 
Minimum lab (ready by hour 3) 
1. Gateway: One team phone runs a personal hotspot with WPA2 or WPA3 and a strong password, 
named RSH-<team-number>. Set a mobile data limit; local scanning uses almost no data. 
2. Scanner: One team laptop joins the hotspot and runs your tool. It must not be connected to the 
venue Wi-Fi or any other network at the same time. 
3. Targets: At least 3 target devices or services, all owned by team members. 
4. Variety: At least 5 different finding types from the official catalog present across your targets. 
5. Captures: Save every scan as nmap XML, e.g. nmap -sS -sV -oX scan_01.xml <your -
subnet> (run as administrator). This is the same format as the standard test data. 
6. Before/after: Fix at least two findings in your lab, rescan, and keep both files. 
Check early that the laptops can see each other (e.g. with ping). Some phones isolate hotspot clients; if 
yours does, try another phone or use setup D. Do not hard -code the subnet: iPhone hotspots typically 
use 172.20.10.0/28, Android ones vary by model. 
Example setups (choose one or combine them) 
Setup What you need How to create the weaknesses Watch out for 
A. 
Containers 
on a laptop 
Hotspot, 2 
laptops, Docker 
Desktop 
Publish services on the laptop's network 
ports: docker run -d -p 6379:6379 redis 
(DB_EXPOSED), docker run -d -p 
1883:1883 eclipse -mosquitto:1.6 
(MQTT_EXPOSED), docker run -d -p 
8080:80 nginx serving a page titled "Admin 
Login" (HTTP_ADMIN_CLEARTEXT) 
Only published 
ports are visible to 
the scanner; stop 
the containers 
when you leave 
B. Real 
team 
devices 
Hotspot, 
laptops, spare 
devices the 
team owns (old 
phone, 
Raspberry Pi, 
ESP32) 
Turn on Windows file sharing ( SMB_EXPOSED) 
or Remote Desktop ( RDP_EXPOSED), an SSH 
server on the Pi ( SSH_OPEN), an FTP server 
app on the old phone (FTP_CLEARTEXT) 
Only team -owned 
devices; switch 
everything off 
afterwards

## Pagina 6

R Systems Hackathon 2026 
Secure Networks, Simply Explained 
 
All rights reserved. Public 
 
Setup What you need How to create the weaknesses Watch out for 
C. 
Simulated 
banners 
Any laptop with 
Python or ncat 
Small listener scripts that only answer with a 
banner, e.g. a fake Telnet on port 2323 that 
replies "BusyBox telnetd" (TELNET_OPEN on a 
non-standard port) 
Safest way to show 
legacy services: no 
real login or shell 
behind them 
D. Single -
laptop 
fallback 
One laptop with 
Docker 
Create a Docker network ( docker network 
create lab ), run the targets and a scanner 
container on it, scan the Docker subnet 
Use it only if 
hotspot isolation 
blocks you; say so 
in the pitch 
 
Golden rule: simulate, do not expose! 
Never run a real shell, real data or real passwords behind a deliberately weak service. A fake banner is 
enough for your scanner and is safe if someone else connects. 
Rules of engagement (signed by every team member at kickoff) 
Allowed Not allowed 
Scanning your own hotspot subnet (or your own 
Docker network) only 
Scanning the venue Wi -Fi, other teams' hotspots, 
the mobile operator network or any public IP 
Host discovery (ARP, ping), TCP/UDP port scans, 
banner and service version detection 
Password guessing or brute force, exploits, 
vulnerability "proof" attacks 
Rate-limited scans (≤ 100 packets/second as a 
guideline) 
Flooding, denial of service, ARP spoofing, traffic 
interception 
Devices and services owned by your team Connecting any device of a person outside your 
team 
Reading passive announcements your tool 
receives (mDNS, SSDP/UPnP) 
Capturing or storing other people's traffic or 
credentials 
 
Built-in guardrail (mandatory) : Your tool must refuse to scan any range outside an explicit allowlist, 
which defaults to the subnet it is connected to. It must also refuse public IP ranges and require a 
confirmation flag before a live scan. You will demonstrate this to the jury.

## Pagina 7

R Systems Hackathon 2026 
Secure Networks, Simply Explained 
 
All rights reserved. Public 
 
Part B: The requirements 
Functional requirements 
Every Must requirement is checked by the jury; a missing Must caps your Technical execution score at 
50%. 
ID Requirement Acceptance criterion Priority 
FR-01 Detect the network Finds the active interface, its subnet and gateway without 
manual input 
Must 
FR-02 Enforce scope Refuses ranges outside the allowlist and all public IP 
ranges; live scans need a --confirm flag 
Must 
FR-03 Discover devices Lists each device with IP, masked MAC, vendor (from 
OUI), hostname if visible, and a device-type guess 
Must 
FR-04 Detect ports and 
services 
Scans at least the top 1,000 TCP ports plus UDP 53, 123, 
161, 1900, 5353; reports service and version when visible 
Must 
FR-05 Analyse scan files Reads an nmap XML file, including the standard test files, 
without needing network access 
Must 
FR-06 Classify findings Applies the official finding catalog and detection rules 
exactly, with port and evidence for each finding 
Must 
FR-07 Explain simply Each finding has an explanation of at most 2 sentences, in 
Romanian and English, with no unexplained technical 
terms 
Must 
FR-08 Recommend fixes 1–5 ordered, concrete steps per finding, written for a 
non-expert 
Must 
FR-09 Calculate the 
standard score 
Network score from the official formula; your own extra 
score may be shown beside it 
Must 
FR-10 Keep history Stores every scan and shows the difference: new or 
removed devices, opened or closed ports, resolved 
findings, score trend 
Must 
FR-11 Provide a simple UI Web page or app showing score, devices, findings, fixes 
and history; a template UI is enough 
Must 
FR-15 Export standard 
results 
Writes findings.csv and scores.csv for a whole folder 
of scan files in one command 
Must

## Pagina 8

R Systems Hackathon 2026 
Secure Networks, Simply Explained 
 
All rights reserved. Public 
 
ID Requirement Acceptance criterion Priority 
FR-12 Answer questions AI assistant answers user questions using only evidence 
from the scan, and says so when the scan cannot answer 
Should 
FR-13 Alert on change Flags a new device or newly opened port compared with 
the previous scan 
Should 
FR-14 Export a report One-page HTML or PDF report a user can send to their IT 
supplier 
Could 
 
A polished design without working functionality earns no points. Build the CLI first, the UI second. 
Standard test data and what we expect 
Every team is evaluated on exactly the same data: a public Validation Set with answers to practise on, 
and a secret Test Set handed to all teams at the same moment. 
Format. Every standard file is an nmap XML file produced with nmap -sS -sU -sV -oX (some files have 
no UDP results). Your own lab scans should use the same format. 
What your tool must produce for a folder of scan files (one command) 
findings.csv — one row per finding: 
file,ip,port,finding_code,severity 
V1_home_basic.xml,192.168.1.1,80,HTTP_ADMIN_CLEARTEXT,medium 
scores.csv — one row per file, ERROR when the file cannot be read: 
file,network_score 
V1_home_basic.xml,90 
V7_broken.xml,ERROR 
The same results must also be visible in your UI. Results must be produced by your tool; hand -edited 
files are disqualified. 
Official finding catalog and detection rules 
Report a finding only for ports in state open, and decide by the service name nmap reports, not by the 
port number alone. 
Code What it means Report when Severity Points 
TELNET_OPEN Remote login without 
encryption 
Service telnet, on any port High 20 
RDP_EXPOSED Remote desktop 
reachable 
Service ms-wbt-server High 20

## Pagina 9

R Systems Hackathon 2026 
Secure Networks, Simply Explained 
 
All rights reserved. Public 
 
Code What it means Report when Severity Points 
VNC_EXPOSED Remote screen sharing 
reachable 
Service vnc High 20 
DB_EXPOSED Database reachable from 
the network 
Service mysql, postgresql, 
redis or mongodb 
High 20 
CAMERA_STREAM_E
XPOSED 
Video stream reachable Service rtsp High 20 
OUTDATED_SERVIC
E 
Software version with 
known security problems 
Version on the outdated list 
below (reported in addition 
to the service's own finding) 
High 20 
FTP_CLEARTEXT File transfer without 
encryption 
Service ftp Medium 10 
HTTP_ADMIN_CLEA
RTEXT 
Admin page over plain 
HTTP 
Service http without SSL, 
and page title contains login, 
admin, config, setup, router 
or settings 
Medium 10 
SMB_EXPOSED Windows file sharing open Service microsoft-ds or 
netbios-ssn; one finding 
per device (port 445 if open, 
else 139) 
Medium 10 
MQTT_EXPOSED IoT message broker 
reachable 
Service mqtt Medium 10 
UPNP_EXPOSED Device can open router 
ports automatically 
Service upnp on UDP Medium 10 
SNMP_EXPOSED Device management 
protocol reachable 
Service snmp on UDP Medium 10 
PRINTER_RAW_EXP
OSED 
Anyone can send jobs to 
the printer 
Service jetdirect Low 5 
UNKNOWN_DEVICE Device that cannot be 
identified 
No MAC vendor and no 
hostname, at least one open 
port (port column left empty) 
Low 5 
SSH_OPEN Encrypted remote login, 
shown for awareness 
Service ssh Info 0

## Pagina 10

R Systems Hackathon 2026 
Secure Networks, Simply Explained 
 
All rights reserved. Public 
 
Outdated list: vsftpd 2.3.4; OpenSSH below 7.4; Apache httpd 2.2.x or older; Microsoft IIS 7.5 or older; 
Samba 3.x or older. 
Standard network score: 
\text{Score} = \max\left(0,\; 100 - \sum \text{points of all findings}\right) 
You may show your own, more advanced score beside it, but the jury checks the standard one. 
Validation Set (public, released at kickoff with these answers) — all devices in 192.168.1.0/24 
File Network Expected findings 
(ip:port code) 
Expected 
score 
Trap to 
avoid 
V1_home_basic.xml Router, 
laptop, 
phone 
.1:80 
HTTP_ADMIN_CLEARTE
XT 
90 Router 
HTTPS 
admin on 
443 is not a 
finding 
V2_smart_home.xml Router, IP 
camera, 
smart hub, 
smart TV 
.1:80 
HTTP_ADMIN_CLEARTE
XT; .1:1900 
UPNP_EXPOSED; 
.40:554 
CAMERA_STREAM_EXP
OSED; .40:80 
HTTP_ADMIN_CLEARTE
XT; .41:1883 
MQTT_EXPOSED 
40 TV ports 
8008/8009 
are not in 
the catalog 
V3_small_office.xml Printer, 
NAS, 
Windows 
PC, Linux 
server 
.10:9100 
PRINTER_RAW_EXPOSE
D; .20:445 
SMB_EXPOSED; .20:22 
SSH_OPEN; .30:3389 
RDP_EXPOSED; .40:22 
SSH_OPEN; .40:3306 
DB_EXPOSED 
45 Printer port 
631 (IPP) is 
not a 
finding 
V4_legacy.xml Old router, 
old server, 
unknown 
device 
.1:23 TELNET_OPEN; 
.1:161 SNMP_EXPOSED; 
.1:80 
HTTP_ADMIN_CLEARTE
XT; .60:21 
FTP_CLEARTEXT; .60:21 
25 vsftpd 2.3.4 
needs two 
findings

## Pagina 11

R Systems Hackathon 2026 
Secure Networks, Simply Explained 
 
All rights reserved. Public 
 
File Network Expected findings 
(ip:port code) 
Expected 
score 
Trap to 
avoid 
OUTDATED_SERVICE; 
.99 UNKNOWN_DEVICE 
V5_nonstandard_ports.xml Five 
devices 
.5:2323 TELNET_OPEN; 
.6:8081 
HTTP_ADMIN_CLEARTE
XT; .7:6380 
DB_EXPOSED 
50 .8:8443 is 
HTTPS; 
.9:3306 is 
filtered, not 
open 
V6a_before.xml Home 
before 
fixes 
.1:80 
HTTP_ADMIN_CLEARTE
XT; .1:1900 
UPNP_EXPOSED; .30:23 
TELNET_OPEN 
60 — 
V6b_after.xml Same 
home after 
fixes 
None 100 History 
must show 
3 resolved 
findings 
V7_broken.xml Truncated 
file 
None ERROR Tool must 
not crash 
and must 
continue 
with other 
files 
In total the Validation Set expects 24 finding rows. If your tool reproduces them all with no extra rows, 
you are ready for the Test Set. 
Secret Test Set: About 9 files in the same format, following the same rules, with different networks and 
new traps, including a before/after pair and an unreadable file. All teams receive it at hour 20 at the 
same moment. 
Evaluation process 
Everything is run and shown by the teams; the jury only compares your results with its answer key and 
watches you demonstrate. 
When What happens 
Hour 0 Validation Set, finding catalog and this brief released

## Pagina 12

R Systems Hackathon 2026 
Secure Networks, Simply Explained 
 
All rights reserved. Public 
 
When What happens 
Hour 20 Test Set released to all teams at the same moment (shared link and 
USB stick) 
Hour 20–21 Run your tool on the whole Test Set folder; upload findings.csv, 
scores.csv and a UI screenshot via the submission form. The form 
closes for everyone at the same time. 
Hour 21–24 15-minute jury session per team: 7 minutes of pitch, then 8 minutes of 
live checks 
After the sessions Jury totals the scores; awards 
 
Live checks you must be ready to show (in this order) 
1. Re-run: the jury picks one Test Set file; you run your tool on it live and the result must match 
your upload. 
2. Hands-on task: a jury member uses your UI without help to answer "Which device is the most 
dangerous, and what should I do first?" 
3. Explanations: you show the explanation and fix for three findings the jury names. 
4. Guardrail: you try to scan a public IP and the venue network; your tool must refuse. 
5. Broken file: you open an unreadable file; your tool shows a clear error and does not crash. 
6. History: you show a before/after from your own hotspot lab with the score improving. 
7. No secrets:  you show that your repository contains no keys or passwords (e.g. by running a 
secret scanner such as gitleaks). 
Using an LLM. Findings, severities and scores must be produced by your own rules, without an LLM, so 
they are identical on every run. Explanations, fixes and the Q&A assistant may use an LLM; if it is 
unavailable, your tool must fall back to built-in text. 
Non-functional requirements 
These mirror R Systems' ISO 27001, ISO 27701 and ISO 9001 commitments and feed the Security & 
Reliability score. 
ID Area Requirement 
NFR-01 Secrets No keys, tokens or passwords in the repository; configuration 
through environment variables. You will show this live with a 
secret scanner. 
NFR-02 Privacy MAC addresses masked in all output; hostnames and history 
stored only locally; a one-click "delete my history" option.

## Pagina 13

R Systems Hackathon 2026 
Secure Networks, Simply Explained 
 
All rights reserved. Public 
 
ID Area Requirement 
NFR-03 Hostile input Safe parsing of scan files: no XML external entities, size limits, 
banners treated as untrusted text and escaped in the UI. 
NFR-04 Least privilege Root or admin rights only for the live scan step; the analyser 
and UI run unprivileged. 
NFR-05 Determinism Same input file gives the same findings, severities and scores on 
every run. 
NFR-06 Grounded AI Every AI -written sentence refers only to evidence in the scan; 
no invented ports, CVEs or phone numbers. 
NFR-07 Performance Offline analysis under 30 seconds per file; a /24 live scan of top 
ports under 5 minutes. 
NFR-08 Accessibility Minimum 16 px text, colour never the only signal (icon + label), 
keyboard navigable, WCAG AA contrast. 
NFR-09 Language All user -facing text in Romanian and English, at roughly a 12 -
year-old reading level. 
NFR-10 Reproducibility README with one-command setup; your own lab scans and the 
Validation Set included in the repo as test fixtures. 
Deliverables and submission checklist 
Submit everything as one tagged Git release (final) by hour 22; nothing after that tag is considered. 
• ☐ Test Set results uploaded by hour 21: findings.csv, scores.csv and a UI screenshot 
• ☐ Git repository tagged final at upload time, with a README.md explaining setup, live scan and 
file analysis 
• ☐ Validation Set reproduced: all 24 expected rows, no extra rows, correct scores 
• ☐ Your own hotspot lab scans (nmap XML) including one before/after pair 
• ☐ Simple UI showing score, devices, findings, fixes and history 
• ☐ 1-page technical summary: lab setup, architecture, assumptions, limitations, LLM use (if any) 
• ☐ 5–7 minute pitch: problem, demo, numbers, trade -offs, next steps; at least two team 
members speak 
• ☐ Laptop ready for the 7 live checks 
• ☐ Signed rules-of-engagement form for every team member

## Pagina 14

R Systems Hackathon 2026 
Secure Networks, Simply Explained 
 
All rights reserved. Public 
 
How the jury will score you 
Every team is scored with the same sheet: 30% comes from matching the Test Set answer key, and 70% 
from structured ratings of what you show in your session. 
Criterion Weight How it is measured 
Test Set accuracy 30% Your uploaded results compared with the jury's answer 
key: correct findings, wrong or invented findings, 
correct network scores 
Ease of use 20% Live hands -on task: can a jury member find the most 
dangerous device and the first fix without help? 
Explanation quality 15% Explanations and fixes for three findings the jury 
names: correct, plain, actionable 
Pitch and teamwork 15% Clear problem, demo, numbers, limitations, next steps; 
juniors and seniors both speak 
Security and responsibility 10% Five yes/no live checks: guardrail, broken file, masked 
MACs, no secrets, history before/after 
Innovation 10% An idea worth remembering beyond listing ports 
 
Test Set accuracy, in plain terms : Each expected finding you report earns credit; each extra finding the 
answer key does not contain costs the same credit; each file with the correct network score adds a 
bonus. If the live re-run does not match your upload, this criterion scores 0. 
Ratings: For each rated criterion, every jury member gives 1 to 5 using the same written descriptions, 
and the average is used. Ties are broken by Test Set accuracy, then by Ease of use. 
Bonus signals: mapping findings to recognised references (CIS Controls, OWASP IoT Top 10), a measured 
before/after improvement in your own lab, and a Romanian explanation tested with a non -technical 
person. 
Working as a mixed-seniority team 
The strongest teams split the work along the system's natural parts, so everyone owns something end to 
end. 
Part Good owner First milestone 
Hotspot lab + test targets + scan 
captures 
Junior Three scans saved by hour 3

## Pagina 15

R Systems Hackathon 2026 
Secure Networks, Simply Explained 
 
All rights reserved. Public 
 
Part Good owner First milestone 
Parser + finding rules + scoring Senior Reproduces the Validation Set answers 
by hour 10 
Explanations + fixes (RO/EN), 
optional LLM 
Junior + senior pair Every catalog code has template text by 
hour 12 
UI + history + before/after view Junior Score, findings and history visible by 
hour 16 
Guardrail, security checks, CSV 
export 
Senior Out-of-scope test refused by hour 14 
 
For senior students: cut the scope in the first hour, own the contract and the architecture, and hand at 
least one pitch section to a junior. 
For junior students: ask early, own one part end to end, and say "I do not understand yet" when you do 
not. It is a productive sentence here. 
For everyone: commit often, sleep at least once, use the mentors, and be kind. The person next to you 
may be a future R Systems colleague. 
Ethics and legal reminder 
In Romania, unauthorized access to a computer system is a criminal offence (Criminal Code, Art. 360). 
The rules of engagement are therefore not optional: a team that scans outside its own hotspot is 
disqualified. If you are unsure whether something is allowed, stop and ask a mentor. 
 
Closing 
Thank you for spending your weekend on a problem that affects almost every home in the country. 
Build something that works, explain it so anyone can understand, and prove every claim with a scan. 
Whatever the leaderboard says, you will leave a stronger and more responsible engineer. 
— R Systems Hackathon Organizing Committee 
 
Sources 
• R Systems Integrated Policy Statement, January 2025  — mission, purpose, values, ISO 
9001/27001/27701

## Pagina 16

R Systems Hackathon 2026 
Secure Networks, Simply Explained 
 
All rights reserved. Public 
 
• R Systems Q2 2026 earnings press release, 4 August 2026 — AI-native strategy, OptimaAI, EXIQO 
• EXIQO launch announcement, March 2026 — 1,400+ AI-native engineers, 150+ agents 
• India's Top 500 Value Creators 2023 (D&B) — delivery locations, Blackstone backing 
• Great Place To Work profile — diversity and inclusion, progress, human-centred approach
