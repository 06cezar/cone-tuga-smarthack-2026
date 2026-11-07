# Rules for conetuga/analysis (stream A: parser, finding rules, score)

- Every code, severity and point value comes from `data/catalog.toml`; nothing here calls an LLM.
- Report a finding only for ports in state `open`, and decide by the service name nmap reports, never by the port
  number: telnet on 2323 is TELNET_OPEN, HTTPS on 8443 is not HTTP_ADMIN_CLEARTEXT, a `filtered` 3306 is nothing.
- HTTP_ADMIN_CLEARTEXT: service `http`, no `tunnel="ssl"`, and the page title (the `http-title` script output)
  contains one of the catalog keywords, case-insensitive.
- SMB_EXPOSED: one finding per device, on 445 if open, else 139. UPNP and SNMP count only on UDP.
- OUTDATED_SERVICE comes in addition to the service's own finding, on the same port (vsftpd 2.3.4 gives two rows).
- UNKNOWN_DEVICE: no MAC vendor and no hostname, at least one open port; the port column stays empty. A MAC with no
  vendor still counts (V4's .99 has a locally administered `02:…` MAC).
- `open|filtered` (common on UDP) is not `open`: no finding. Hosts with status `down` are skipped.
- Versions compare as numbers, never as strings: "OpenSSH 7.2p2" is 7.2 (outdated), 7.4 exactly is not, 7.10 > 7.4.
  Products look like `Samba smbd 4.15` or `OpenSSH 8.4p1 Debian 5+deb11u3`: match the product, then read the leading
  numbers of the version as a tuple.
- Not in the catalog means no finding: TV ports 8008/8009, IPP on 631, dnsmasq on 53, an unknown service on 8888.
- Expect Test Set traps: HTTP with no title (no finding), titles in capitals ("LOGIN" matches), SMB open on both 139
  and 445 (one row, on 445).
- A file that can't be read gives score `ERROR` and the run continues with the next file; never crash. That covers a
  truncated XML, an empty file, a file that isn't nmap output and an XML with entities (XXE).
- Parse with `defusedxml` and a file-size limit; every string from the file is untrusted text.
- Output order is stable: file, then IP as a number (not as text), then port, then code, so two runs on the same
  folder give byte-identical CSVs.
- The oracle is `tests/test_validation_set.py`: an extra row is as wrong as a missing one.
