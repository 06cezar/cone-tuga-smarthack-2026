# Rules for conetuga/analysis (stream A: parser, finding rules, score)

- Every code, severity and point value comes from `data/catalog.toml`; nothing here calls an LLM.
- Report a finding only for ports in state `open`, and decide by the service name nmap reports, never by the port
  number: telnet on 2323 is TELNET_OPEN, HTTPS on 8443 is not HTTP_ADMIN_CLEARTEXT, a `filtered` 3306 is nothing.
- HTTP_ADMIN_CLEARTEXT: service `http`, no `tunnel="ssl"`, and the page title contains one of the catalog keywords,
  case-insensitive. The title is the `<elem key="title">` of the `http-title` script, never its `output` text: on a
  redirect nmap writes "Did not follow redirect to …/login", and that "login" is not a title.
- SMB_EXPOSED: one finding per device, on 445 if open, else 139. UPNP and SNMP count only on UDP.
- OUTDATED_SERVICE comes in addition to the service's own finding, on the same port (vsftpd 2.3.4 gives two rows).
- UNKNOWN_DEVICE: no MAC vendor and no hostname, at least one open port; the port column stays empty. A MAC with no
  vendor still counts (V4's .99 has a locally administered `02:…` MAC).
- `open|filtered` (common on UDP) is not `open`: no finding. Hosts with status `down` are skipped.
- Versions compare as numbers, never as strings: "OpenSSH 7.2p2" is 7.2 (outdated), 7.4 exactly is not, 7.10 > 7.4.
  Products look like `Samba smbd 4.15` or `OpenSSH 8.4p1 Debian 5+deb11u3`: match the product, then read the leading
  numbers of the version as a tuple. `at_most` compares only as many parts as the limit has: Apache 2.2.15 is (2, 2)
  against "2.2", so outdated; Samba 3.6.25 is (3,) against "3", so outdated. A plain tuple compare says
  (2, 2, 15) > (2, 2) and misses it. Each outdated rule gets its own test.
- Don't trust `<scaninfo>` for the port range: the standard files say "1-1000" and still contain 3389 and 8081.
- Not in the catalog means no finding: TV ports 8008/8009, IPP on 631, dnsmasq on 53, an unknown service on 8888.
- Expect Test Set traps: HTTP with no title (no finding), titles in capitals ("LOGIN" matches), SMB open on both 139
  and 445 (one row, on 445).
- A file that can't be read gives score `ERROR` and the run continues with the next file; never crash. That covers a
  truncated XML, an empty file, a file that isn't nmap output and an XML with entities (XXE). A file in error gives
  no findings and no hosts at all: never a recovering or streaming parser, because V7 holds a whole router before the
  cut and any row from it would be an extra row.
- Parse with `defusedxml` and a file-size limit; every string from the file is untrusted text. Keep defusedxml's
  defaults (entities forbidden, DTDs allowed): every nmap XML starts with `<!DOCTYPE nmaprun>`, so `forbid_dtd=True`
  would reject valid files. Offline analysis takes under 30 seconds per file (NFR-07).
- Output order is stable: file, then IP as a number (not as text), then port, then code, so two runs on the same
  folder give byte-identical CSVs. UNKNOWN_DEVICE has no port: sort it as -1, because `None` can't be compared with
  an `int`.
- The oracle is `tests/test_validation_set.py`: an extra row is as wrong as a missing one.

## Our readings of open questions (each one is a single named constant or function, so a mentor's answer changes one place)
The questions are in `IMPLEMENTATION_PLAN.md`, "Questions for humans"; when a mentor answers, update the code, its
test and this list together.
- TCP and UDP on the same port giving the same code: one finding, the TCP one (`findings.csv` has no proto column,
  so two would be a duplicate row).
- `http-proxy`, `http-alt`: not `http` (the catalog says "Service http").
- OUTDATED_SERVICE: reported on every open port whose product and version are on the list, whether or not that
  service has a finding of its own.
- Old Samba open on both 139 and 445: OUTDATED_SERVICE on each of them (riskiest reading; the other is "445 only").
- A host with no MAC address at all counts as "no MAC vendor".
- A valid nmap XML with no hosts: score 100, not ERROR.
