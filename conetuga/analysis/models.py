"""The data that `analyse_file` returns, exactly as agreed in `specs/contracts.md` ("analyse_file").

Every other stream reads these types, so a field changes only through the contract."""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Port:
    """One open port of a host, as nmap reported it. Every string comes from the scan file: untrusted text."""

    port: int
    proto: str  # "tcp" or "udp"
    service: str  # nmap's service name, e.g. "http", "ms-wbt-server"; "" when nmap reported none
    product: str
    version: str
    ssl: bool  # nmap reported tunnel="ssl"
    title: str  # the http-title script's <elem key="title">, "" when there is none


@dataclass(frozen=True)
class Host:
    """One device that was up during the scan. The raw MAC never leaves the parser: only its masked form."""

    ip: str
    mac_masked: str  # "AA:BB:CC:xx:xx:xx", or "" when the scan has no MAC for this host
    vendor: str  # nmap's OUI vendor, "" when unknown
    hostname: str  # the first hostname nmap reported, "" when none
    device_type: str  # our best guess, see devices.py
    ports: list[Port] = field(default_factory=list)  # open ports only


@dataclass(frozen=True)
class Finding:
    """One row of findings.csv, plus what the other streams need to explain and rank it."""

    file: str
    ip: str
    port: int | None  # None only for UNKNOWN_DEVICE, which is about a device, not a port
    proto: str  # "tcp" or "udp"; "" when port is None
    code: str
    severity: str
    points: int  # the catalog's points for this severity
    evidence: str  # what in the scan triggered it, in plain words (untrusted text inside)


@dataclass(frozen=True)
class FileResult:
    """The analysis of one scan file. When the file can't be read, `error` says why and nothing else is reported."""

    file: str
    hosts: list[Host]
    findings: list[Finding]
    score: int | None  # None exactly when `error` is set
    error: str  # "" when the file was read
