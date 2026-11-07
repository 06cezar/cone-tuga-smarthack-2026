# Rules for lab (stream E: the hotspot lab, test targets, scan captures)

- Golden rule: simulate, don't expose. Weak services are banner-only listeners or containers with no real shell, data
  or passwords behind them.
- Only our hotspot (`RSH-<team name>`, i.e. `RSH-ConeTuga`, WPA2 or WPA3, a strong password, a mobile data limit) or our Docker lab
  network. While it scans, the scanner laptop is on no other network: no venue Wi-Fi, no cable. Only devices the team
  owns.
- Roles, settled by the team on 2026-11-07: Mihnea's laptop (A, Ubuntu, nmap with sudo) is the only scanner; Stefan's
  laptop (Windows, Docker Desktop) runs the targets; Stefan's phone is the hotspot. The steps, the capture command and
  the expected findings are in `lab/README.md`: keep that the one place for them.
- Captures: nmap XML, the same format as the standard files, rate-limited (`--max-rate 100`, the rules of engagement)
  and with `--script http-title` (without it no page title is recorded). The raw XML stays in `results/` on the
  scanner (gitignored); only copies made by `lab/mask_scan.py` go into `lab/scans/` (`scan_01.xml`, ...). The mask
  keeps the `vendor` attribute and checks that the copy gives the same findings and score.
- The lab needs at least 3 targets and at least 5 different catalog codes; fix at least 2 findings and rescan.
- Targets: `lab/targets/docker-compose.yml` (redis on 6380, `eclipse-mosquitto:1.6` on 1883, nginx "Admin Login" on
  8080) and `lab/targets/fake_services.py` (banner-only telnet on 2323, FTP saying vsFTPd 2.3.4 on 21, a silent printer
  port on 9100). Test client isolation with `ping` first; if the hotspot blocks it, use setup D and say so in the pitch.
- On Windows: setup D (scanning the internal Docker subnet) doesn't work from the host, because the bridge network
  lives inside the WSL2 VM; run the scanner in a container on the same network. The Windows firewall blocks ping and
  test ports by default: open them for the lab and close them afterwards.
- Claude may write listener scripts and Docker commands; a person runs every scan. Stop the containers and listeners
  when you leave.
