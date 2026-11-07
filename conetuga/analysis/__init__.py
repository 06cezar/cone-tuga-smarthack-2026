"""Stream A: parse nmap XML, apply the official catalog, compute the standard score.

The one call other streams use is `analyse_file` (contract in specs/contracts.md)."""
from pathlib import Path

from conetuga.analysis.catalog import load_catalog
from conetuga.analysis.models import FileResult, Finding, Host, Port
from conetuga.analysis.parser import ScanReadError, mask_macs_in, parse_scan
from conetuga.analysis.rules import find_findings, standard_score

__all__ = ["analyse_file", "FileResult", "Finding", "Host", "Port"]


def analyse_file(path: Path) -> FileResult:
    """Hosts, findings and the standard score of one scan file. Never raises for a bad file: an unreadable one gives
    `error` set, `score=None` and no hosts or findings, so a folder run goes on with the next file."""
    path = Path(path)
    try:
        hosts = parse_scan(path)
    except ScanReadError as exc:
        # The reason can quote text from the file (a bad address, a bad port number): no MAC in it either. The file
        # name stays as it is, because it is the `file` column of findings.csv and scores.csv.
        return FileResult(file=path.name, hosts=[], findings=[], score=None,
                          error=f"{path.name}: {mask_macs_in(str(exc))}")
    catalog = load_catalog()
    findings = find_findings(path.name, hosts, catalog)
    return FileResult(file=path.name, hosts=hosts, findings=findings, score=standard_score(findings, catalog),
                      error="")
