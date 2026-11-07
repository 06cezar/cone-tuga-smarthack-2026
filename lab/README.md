# Our hotspot lab (stream E)

The brief (pages 5–6) asks every team to build and scan its own small network. We combine its setup A (containers on
a laptop) and setup C (simulated banners): no real login, shell, data or password sits behind any weak service.

## Who does what

| Role | Device | What it does |
|---|---|---|
| Gateway | Stefan's phone | Hotspot `RSH-ConeTuga`, WPA2 or WPA3, a long password, a mobile data limit |
| Targets | Stefan's laptop (Windows, Docker Desktop) | The services below, only while it is on the hotspot |
| Scanner | Mihnea's laptop (A, Ubuntu, nmap 7.94) | Every capture, started by a person with `sudo`, only on the hotspot |

## The targets and what they should give

| Service | Runs as | Port | Expected finding | Points |
|---|---|---|---|---|
| Redis, empty | container | 6380 | DB_EXPOSED | 20 |
| Mosquitto 1.6 | container | 1883 | MQTT_EXPOSED | 10 |
| nginx, page "Admin Login" | container | 8080 | HTTP_ADMIN_CLEARTEXT | 10 |
| Fake telnet (greeting only) | `fake_services.py` | 2323 | TELNET_OPEN | 20 |
| Fake FTP ("vsFTPd 2.3.4", refuses every login) | `fake_services.py` | 21 | FTP_CLEARTEXT + OUTDATED_SERVICE | 10 + 20 |
| Fake printer port (silent) | `fake_services.py` | 9100 | PRINTER_RAW_EXPOSED | 5 |

7 catalog codes (the brief asks for 5). The phone and the laptops can add real findings of their own: check each
capture with `analyse_file` before keeping it.

| Capture | What runs | Expected score |
|---|---|---|
| `scan_01.xml` (before) | everything | 5 |
| `scan_02.xml` (fix 1: telnet and FTP off) | containers + printer | 55 |
| `scan_03.xml` (fix 2: Redis off too) | Mosquitto, nginx, printer | 75 |

## On the targets laptop (Windows)

```powershell
docker compose -f lab/targets/docker-compose.yml pull     # once, on any Wi-Fi, before the hotspot: saves mobile data
docker compose -f lab/targets/docker-compose.yml up -d    # start the containers
.venv\Scripts\python lab\targets\fake_services.py         # start telnet, FTP and printer; leave it open
```

Windows blocks ping and these ports by default. In an administrator PowerShell, for the hotspot only (network profile
"Private"):

```powershell
New-NetFirewallRule -DisplayName "ConeTuga lab ping" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Private
New-NetFirewallRule -DisplayName "ConeTuga lab ports" -Direction Inbound -Protocol TCP -LocalPort 21,1883,2323,6380,8080,9100 -Action Allow -Profile Private
```

Fix 1: Ctrl+C in the fake services window, then `.venv\Scripts\python lab\targets\fake_services.py printer`.
Fix 2: `docker compose -f lab/targets/docker-compose.yml stop redis`.

## On the scanner (Mihnea's laptop), started by a person

```bash
mkdir -p results   # nmap doesn't create the folder; results/ is gitignored
sudo nmap -sS -sU -sV --script http-title --max-rate 100 \
  -p T:21-23,80,139,445,554,1883,2323,3306,3389,5900,6379,6380,8080,8443,9100,U:53,123,161,1900,5353 \
  --exclude <scanner IP> -oX results/scan_01.xml <hotspot subnet>
.venv/bin/python lab/mask_scan.py results/scan_01.xml results/masked/scan_01.xml
```

`--exclude` leaves out the scanner itself: nmap lists it with no MAC, so it would show up as an UNKNOWN_DEVICE. The
masked copy is the only file that leaves the laptop; E commits it to `lab/scans/`. In it, MACs keep only their vendor
part, hostnames become `lab-host-<n>`, and the other places where nmap writes a computer name are dropped (the
service's `hostname` and `extrainfo`, scripts other than http-title). The script refuses to write a copy that still
contains an original name or MAC, or that analyses differently from the raw file.

## When you leave

Ctrl+C in the fake services window; `docker compose -f lab/targets/docker-compose.yml down`;
`Get-NetFirewallRule -DisplayName "ConeTuga lab*" | Remove-NetFirewallRule` (administrator); hotspot off.
