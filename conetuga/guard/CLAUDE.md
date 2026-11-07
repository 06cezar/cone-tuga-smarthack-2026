# Rules for conetuga/guard (stream C: scope guardrail, live scan, masking, CSV export)

- Scope: the allowlist defaults to the subnet of the active interface. Refuse every public IP (`ipaddress`, `is_global`)
  and every range outside the allowlist; a live scan without `--confirm` is refused too. Each refusal has a test.
- The allowlist decides, not "is it private": the venue Wi-Fi is private too, but it isn't ours. 100.64.0.0/10 (the
  mobile carrier's shared range) is neither private nor global for `ipaddress`: refuse it explicitly.
- Network detection (FR-01) finds the active interface, its subnet and its gateway with no manual input. Never hard-code
  a subnet: iPhone hotspots usually use 172.20.10.0/28, Android ones vary. Local IP: a UDP socket "connected" to an
  outside address (nothing is sent); netmask: `psutil.net_if_addrs()`; gateway: `ip route show default` on Linux,
  `Get-NetRoute -DestinationPrefix 0.0.0.0/0` on Windows. Branch on `sys.platform`.
- nmap: `apt install nmap` on Linux; the nmap.org installer with Npcap on Windows (without Npcap, `-sS` fails). The scan
  step runs with `sudo` on Linux or from an administrator terminal on Windows.
- "Top 1,000 TCP ports" means nmap's most common 1,000 (`--top-ports 1000`), not ports 1–1000; nmap can't combine
  `--top-ports` with a UDP list in one `-p`, so either run TCP and UDP separately and merge, or build the TCP list from
  `nmap-services`. Scanning more TCP ports is allowed: the catalog decides by service, so a redis on 6380 is found only
  if 6380 is scanned.
- Live scan: nmap with `-sS -sU -sV`, the top 1,000 TCP ports plus UDP 53, 123, 161, 1900 and 5353, rate-limited to at
  most 100 packets/second, plus `--script http-title` (a "safe" script): `-sV` alone doesn't record page titles, and
  without them HTTP_ADMIN_CLEARTEXT can never fire on a live scan. Discover the live hosts first and scan ports only on them: that's the only way to keep the
  packet limit and still finish a /24 in under 5 minutes (NFR-07). It writes nmap XML to `lab/scans/`, and the same analyser reads it. Only this step needs
  administrator rights.
- Claude never starts a live scan; a team member runs it, on our hotspot only.
- Allowed: host discovery (ARP, ping), TCP and UDP port scans, version and banner detection, and reading passive
  mDNS/SSDP announcements. Never: password guessing, exploits, NSE scripts from the brute, exploit, dos, intrusive or
  vuln categories, flooding, ARP spoofing or traffic capture. Breaking these rules means disqualification.
- MAC addresses are masked in every output: keep the vendor part (the first 3 bytes), hide the rest
  (`AA:BB:CC:xx:xx:xx`).
- CSV export: exactly the headers and values in `specs/contracts.md`, with nothing added or changed (no prefixes, no
  extra quoting: the jury compares every cell with its answer key), one command for a whole folder, opened with
  `newline=""`, `encoding="utf-8"` and `lineterminator="\n"` (the live re-run is compared with the upload).
- No keys or passwords anywhere in the repo; `gitleaks detect` runs clean.
