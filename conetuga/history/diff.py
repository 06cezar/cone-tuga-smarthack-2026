"""Before/after between two analysed scans (FR-10), and the change alerts (FR-13): contract "diff".

A device is the same device in both scans when its IP and hostname match, never by MAC: phones and laptops change
their MAC (in the Validation Set, V6a and V6b show the same router and laptop with different MACs)."""
from dataclasses import dataclass

from conetuga.analysis import FileResult, Finding, Host, Port

DeviceKey = tuple[str, str]  # (ip, hostname)
PortKey = tuple[int, str]  # (port, proto)


@dataclass(frozen=True)
class Diff:
    new_devices: list[Host]  # alert: a device the earlier scan didn't have
    removed_devices: list[Host]
    opened_ports: list[tuple[Host, Port]]  # alert: a port that was closed before, on a device both scans have
    closed_ports: list[tuple[Host, Port]]
    resolved_findings: list[Finding]  # from `before`: its device, port and code are gone from `after`
    score_before: int
    score_after: int


def diff(before: FileResult, after: FileResult) -> Diff:
    """What changed from `before` to `after`. Raises ValueError for a result with an error, which has no devices."""
    for result in (before, after):
        if result.error or result.score is None:
            raise ValueError(f"{result.file} can't be compared: {result.error or 'it has no score'}")
    old, new = _devices(before), _devices(after)
    opened, closed = [], []
    for key in old.keys() & new.keys():
        old_ports, new_ports = _ports(old[key]), _ports(new[key])
        opened += [(new[key], new_ports[p]) for p in sorted(new_ports.keys() - old_ports.keys())]
        closed += [(old[key], old_ports[p]) for p in sorted(old_ports.keys() - new_ports.keys())]
    still_there = {_finding_key(f, after) for f in after.findings}
    return Diff(
        new_devices=[new[k] for k in sorted(new.keys() - old.keys())],
        removed_devices=[old[k] for k in sorted(old.keys() - new.keys())],
        opened_ports=sorted(opened, key=_port_order),
        closed_ports=sorted(closed, key=_port_order),
        resolved_findings=[f for f in before.findings if _finding_key(f, before) not in still_there],
        score_before=before.score,
        score_after=after.score,
    )


def _devices(result: FileResult) -> dict[DeviceKey, Host]:
    return {(host.ip, host.hostname): host for host in result.hosts}


def _ports(host: Host) -> dict[PortKey, Port]:
    return {(port.port, port.proto): port for port in host.ports}


def _finding_key(finding: Finding, result: FileResult) -> tuple:
    hostname = next((h.hostname for h in result.hosts if h.ip == finding.ip), "")
    return finding.ip, hostname, finding.port, finding.proto, finding.code


def _port_order(item: tuple[Host, Port]) -> tuple:
    host, port = item
    return host.ip, port.port, port.proto
