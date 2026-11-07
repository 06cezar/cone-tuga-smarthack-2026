"""Apply the official catalog to the hosts of one scan, and compute the standard score.

Pure code, no LLM: the same hosts always give the same findings, in the same order (NFR-05). Where the brief leaves
a question open, our reading is one named constant or function below, listed in conetuga/analysis/CLAUDE.md, so a
mentor's answer changes one place."""
import ipaddress

from conetuga.analysis.catalog import Catalog, FindingRule
from conetuga.analysis.models import Finding, Host, Port

OUTDATED_CODE = "OUTDATED_SERVICE"
UNKNOWN_DEVICE_CODE = "UNKNOWN_DEVICE"

# nmap service names that count as another catalog service. Empty by our reading: the catalog says "Service http",
# so "http-proxy" and "http-alt" are not http (open question for a mentor).
SERVICE_ALIASES: dict[str, str] = {}

# When TCP and UDP of one port give the same code, findings.csv (no protocol column) can hold only one row: keep the
# first protocol of this list (open question for a mentor).
PROTOCOL_PREFERENCE = ("tcp", "udp")


def find_findings(file: str, hosts: list[Host], catalog: Catalog) -> list[Finding]:
    """Every catalog finding for these hosts, unique on the findings.csv columns and in a stable order."""
    findings: list[Finding] = []
    for host in hosts:
        findings += _service_findings(file, host, catalog)
        findings += _outdated_findings(file, host, catalog)
        findings += _device_findings(file, host, catalog)
    return _unique_and_sorted(findings)


def standard_score(findings: list[Finding], catalog: Catalog) -> int:
    """The brief's network score: max(0, 100 - sum of the points of all findings)."""
    return max(0, catalog.start - sum(finding.points for finding in findings))


def _service_findings(file: str, host: Host, catalog: Catalog) -> list[Finding]:
    """Findings decided by the service on a port: TELNET_OPEN, DB_EXPOSED, SMB_EXPOSED, and so on."""
    findings = []
    for rule in catalog.rules:
        ports = [port for port in host.ports if _port_matches(rule, port)]
        if rule.one_per_device and ports:
            ports = [_device_port(rule, ports)]
        findings += [_finding(file, host, port, rule.code, catalog, _service_evidence(port)) for port in ports]
    return findings


def _port_matches(rule: FindingRule, port: Port) -> bool:
    """The brief's "Report when" column for one port: decided by nmap's service name, never by the port number."""
    if _service_name(port) not in rule.services:
        return False
    if rule.protocol is not None and port.proto != rule.protocol:
        return False
    if rule.without_ssl and port.ssl:
        return False
    if rule.title_keywords and not any(keyword in port.title.casefold() for keyword in rule.title_keywords):
        return False
    return True


def _service_name(port: Port) -> str:
    return SERVICE_ALIASES.get(port.service, port.service)


def _device_port(rule: FindingRule, ports: list[Port]) -> Port:
    """The one port a one-per-device finding is reported on: the first of the rule's preferred ports that is open
    (SMB: 445, else 139), else the lowest one."""
    for preferred in rule.preferred_ports:
        candidates = [port for port in ports if port.port == preferred]
        if candidates:
            return min(candidates, key=_protocol_rank)
    return min(ports, key=lambda port: (port.port, _protocol_rank(port)))


def _outdated_findings(file: str, host: Host, catalog: Catalog) -> list[Finding]:
    """OUTDATED_SERVICE, in addition to the service's own finding, for every open port with a listed version."""
    findings = []
    for port in host.ports:
        if catalog.is_outdated(port.product, port.version):
            report_on = _outdated_report_port(host, port, catalog)
            evidence = f"{port.product} {port.version} on {port.proto}/{port.port} is on the brief's outdated list"
            findings.append(_finding(file, host, report_on, OUTDATED_CODE, catalog, evidence))
    return findings


def _outdated_report_port(host: Host, port: Port, catalog: Catalog) -> Port:
    """The port an OUTDATED_SERVICE row goes on: the one that carries the service's own finding. For a one-per-device
    service that is the port its finding chose, so old Samba on 139 and 445 gives one row, on 445 (our reading of
    "in addition to the service's own finding"; open question for a mentor). Otherwise, the port itself."""
    for rule in catalog.rules:
        if rule.one_per_device and _port_matches(rule, port):
            return _device_port(rule, [p for p in host.ports if _port_matches(rule, p)])
    return port


def _device_findings(file: str, host: Host, catalog: Catalog) -> list[Finding]:
    """UNKNOWN_DEVICE: a rule about a device, not a port, so its port column stays empty."""
    if not _is_unidentified(host):
        return []
    open_ports = ", ".join(f"{port.port}/{port.proto}" for port in host.ports)
    evidence = f"no MAC vendor and no hostname; open ports: {open_ports}"
    return [_finding(file, host, None, UNKNOWN_DEVICE_CODE, catalog, evidence)]


def _is_unidentified(host: Host) -> bool:
    """No MAC vendor, no hostname, at least one open port. A host with no MAC address at all has no MAC vendor
    either (our reading; open question for a mentor)."""
    return not host.vendor and not host.hostname and bool(host.ports)


def _finding(file: str, host: Host, port: Port | None, code: str, catalog: Catalog, evidence: str) -> Finding:
    return Finding(
        file=file,
        ip=host.ip,
        port=port.port if port else None,
        proto=port.proto if port else "",
        code=code,
        severity=catalog.rule(code).severity,
        points=catalog.points(code),
        evidence=evidence,
    )


def _service_evidence(port: Port) -> str:
    """What nmap saw on the port, e.g. 'tcp/80 http (lighttpd), page title "Router Login"'."""
    software = " ".join(part for part in (port.product, port.version) if part)
    text = f"{port.proto}/{port.port} {port.service}" + (f" ({software})" if software else "")
    return text + (f', page title "{port.title}"' if port.title else "")


def _protocol_rank(item: Port | Finding) -> int:
    """0 for the most preferred protocol; protocols not in PROTOCOL_PREFERENCE come last."""
    if item.proto in PROTOCOL_PREFERENCE:
        return PROTOCOL_PREFERENCE.index(item.proto)
    return len(PROTOCOL_PREFERENCE)


def _unique_and_sorted(findings: list[Finding]) -> list[Finding]:
    """One finding per (file, ip, port, code), the columns of findings.csv, keeping the preferred protocol; sorted by
    IP as a number, then port (none first) and code, so two runs give byte-identical CSVs."""
    unique: dict[tuple, Finding] = {}
    for finding in sorted(findings, key=_protocol_rank):
        unique.setdefault((finding.file, finding.ip, finding.port, finding.code), finding)
    return sorted(unique.values(), key=_sort_key)


def _sort_key(finding: Finding) -> tuple:
    address = ipaddress.ip_address(finding.ip)
    return (finding.file, address.version, int(address), -1 if finding.port is None else finding.port, finding.code)
