# Rules for lab (stream E: the hotspot lab, test targets, scan captures)

- Golden rule: simulate, don't expose. Weak services are banner-only listeners or containers with no real shell, data
  or passwords behind them.
- Only our hotspot (`RSH-<team name>`, i.e. `RSH-ConeTuga`, WPA2 or WPA3, a strong password, a mobile data limit) or our Docker lab
  network. While it scans, the scanner laptop is on no other network: no venue Wi-Fi, no cable. Only devices the team
  owns.
- Captures are nmap XML in `lab/scans/` (`scan_01.xml`, ...), the same format as the standard files, run as
  administrator. Until our own `scan --confirm` works, a quick capture of the lab's ports is enough:
  `nmap -sS -sU -sV --script http-title -p T:21-23,80,139,445,554,1883,2323,3306,3389,5900,6379,6380,8080,8443,9100,U:53,123,161,1900,5353 -oX lab/scans/scan_01.xml <our subnet>`.
  The brief's example has no `--script http-title`, but without it no page title is recorded. Keep at least one
  before/after pair.
- The lab needs at least 3 targets and at least 5 different catalog codes; fix at least 2 findings and rescan.
- Targets that work: `redis` published on 6380 (DB_EXPOSED on a non-standard port), `eclipse-mosquitto:1.6`
  (MQTT_EXPOSED; 2.x listens only locally by default), `nginx` on 8080 serving a page titled "Admin Login"
  (HTTP_ADMIN_CLEARTEXT), a fake telnet banner on 2323 (TELNET_OPEN), plus SSH (SSH_OPEN). Test client isolation
  with `ping` first; if the hotspot blocks it, use setup D and say so in the pitch.
- On Windows: setup D (scanning the internal Docker subnet) doesn't work from the host, because the bridge network
  lives inside the WSL2 VM; run the scanner in a container on the same network. The Windows firewall blocks ping and
  test ports by default: open them for the lab and close them afterwards.
- Claude may write listener scripts and Docker commands; a person runs every scan. Stop the containers and listeners
  when you leave.
