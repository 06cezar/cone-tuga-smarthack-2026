"""Load the official finding catalog (`data/catalog.toml`): codes, severities, points and the outdated list.

Every code, severity and point value the analysis uses comes from here, so the brief's tables live in one file that
tests/test_catalog.py checks against the brief."""
import tomllib
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from conetuga.analysis.versions import is_outdated_version

CATALOG_PATH = Path(__file__).resolve().parents[2] / "data" / "catalog.toml"
OUTDATED_RULE_KINDS = ("equals", "below", "at_most")


@dataclass(frozen=True)
class FindingRule:
    """One row of the brief's catalog table."""

    code: str
    severity: str
    services: frozenset[str]  # nmap service names; empty for the rules about versions or devices
    protocol: str | None  # "udp" for UPNP/SNMP, None for any protocol
    without_ssl: bool  # HTTP_ADMIN_CLEARTEXT: not when nmap reports tunnel="ssl"
    title_keywords: tuple[str, ...]  # HTTP_ADMIN_CLEARTEXT: the page title must contain one of them
    one_per_device: bool  # SMB_EXPOSED: one finding per device, on the first open port of `preferred_ports`
    preferred_ports: tuple[int, ...]


@dataclass(frozen=True)
class OutdatedRule:
    """One entry of the brief's outdated list, e.g. "OpenSSH below 7.4"."""

    product: str
    kind: str  # one of OUTDATED_RULE_KINDS
    limit: str


@dataclass(frozen=True)
class Catalog:
    start: int  # standard score = max(0, start - sum of points)
    severity_points: dict[str, int]
    rules: tuple[FindingRule, ...]
    outdated: tuple[OutdatedRule, ...]

    def rule(self, code: str) -> FindingRule:
        return next(rule for rule in self.rules if rule.code == code)

    def points(self, code: str) -> int:
        return self.severity_points[self.rule(code).severity]

    def is_outdated(self, product: str, version: str) -> bool:
        """True when this product and version are on the outdated list.

        A list entry matches when its product name appears in nmap's product, ignoring case: "Samba" matches
        "Samba smbd", "Microsoft IIS" matches "Microsoft IIS httpd" (assumption, see the catalog's comment)."""
        product = product.casefold()
        return any(
            entry.product.casefold() in product and is_outdated_version(version, entry.kind, entry.limit)
            for entry in self.outdated
        )


@cache
def load_catalog(path: Path = CATALOG_PATH) -> Catalog:
    """The catalog, read once. A malformed catalog raises at load time, never silently mid-analysis."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    points = dict(data["severity_points"])
    rules = tuple(_finding_rule(entry, points) for entry in data["finding"])
    outdated = tuple(_outdated_rule(entry) for entry in data["outdated"])
    return Catalog(start=data["score"]["start"], severity_points=points, rules=rules, outdated=outdated)


def _finding_rule(entry: dict, severity_points: dict[str, int]) -> FindingRule:
    if entry["severity"] not in severity_points:
        raise ValueError(f"{entry['code']}: severity {entry['severity']!r} has no points in the catalog")
    return FindingRule(
        code=entry["code"],
        severity=entry["severity"],
        services=frozenset(entry.get("services", [])),
        protocol=entry.get("protocol"),
        without_ssl=entry.get("without_ssl", False),
        title_keywords=tuple(keyword.casefold() for keyword in entry.get("title_keywords", [])),
        one_per_device=entry.get("one_per_device", False),
        preferred_ports=tuple(entry.get("preferred_ports", [])),
    )


def _outdated_rule(entry: dict) -> OutdatedRule:
    kinds = [kind for kind in OUTDATED_RULE_KINDS if kind in entry]
    if len(kinds) != 1:
        raise ValueError(f"outdated entry {entry['product']!r} needs exactly one of {OUTDATED_RULE_KINDS}")
    return OutdatedRule(product=entry["product"], kind=kinds[0], limit=str(entry[kinds[0]]))
