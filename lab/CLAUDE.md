# Rules for lab (stream E: the hotspot lab, test targets, scan captures)

- Golden rule: simulate, don't expose. Weak services are banner-only listeners or containers with no real shell, data
  or passwords behind them.
- Only our hotspot (`RSH-<team number>`, WPA2 or WPA3) or our Docker lab network. The scanner laptop is never on the
  venue Wi-Fi at the same time. Only devices the team owns.
- Captures are nmap XML in `lab/scans/` (`scan_01.xml`, ...), the same format as the standard files. Keep at least
  one before/after pair.
- The lab needs at least 3 targets and at least 5 different catalog codes; fix at least 2 findings and rescan.
- Targets that work: `redis` published on 6380 (DB_EXPOSED on a non-standard port), `eclipse-mosquitto:1.6`
  (MQTT_EXPOSED; 2.x listens only locally by default), `nginx` on 8080 serving a page titled "Admin Login"
  (HTTP_ADMIN_CLEARTEXT), a fake telnet banner on 2323 (TELNET_OPEN), plus SSH (SSH_OPEN). Test client isolation
  with `ping` first; if the hotspot blocks it, use setup D.
- On Windows: setup D (scanning the internal Docker subnet) doesn't work from the host, because the bridge network
  lives inside the WSL2 VM; run the scanner in a container on the same network. The Windows firewall blocks ping and
  test ports by default: open them for the lab and close them afterwards.
- Claude may write listener scripts and Docker commands; a person runs every scan. Stop the containers and listeners
  when you leave.
