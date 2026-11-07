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
- Live scan: nmap with `-sS -sU -sV`, the top 1,000 TCP ports plus UDP 53, 123, 161, 1900 and 5353, rate-limited to at
  most 100 packets/second. Discover the live hosts first and scan ports only on them: that's the only way to keep the
  packet limit and still finish a /24 in under 5 minutes (NFR-07). It writes nmap XML to `lab/scans/`, and the same analyser reads it. Only this step needs
  administrator rights.
- Claude never starts a live scan; a team member runs it, on our hotspot only.
- MAC addresses are masked in every output: keep the vendor part (the first 3 bytes), hide the rest
  (`AA:BB:CC:xx:xx:xx`).
- CSV export: exactly the headers in `specs/contracts.md`, one command for a whole folder, opened with `newline=""`,
  `encoding="utf-8"` and `lineterminator="\n"` (the jury compares the live re-run with the upload); values that start with
  `=`, `+`, `-` or `@` get a `'` in front (CSV injection).
- No keys or passwords anywhere in the repo; `gitleaks detect` runs clean.
