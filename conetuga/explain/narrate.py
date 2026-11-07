"""What the guides say about one finding (specs/contracts.md, section narrate): Tuga 🐢 in Simple mode, Cone 🐇 in
Advanced mode.

Tuga is exactly explain(): the plain, reviewed text everyone sees first. Cone speaks to technical users with its own
texts from data/cone.toml, which hold no scan value, plus evidence lines that code builds from the scan and the
catalog. Every scan value enters an evidence line through fill() as plain text, never read as a template (NFR-03);
no hostname, MAC address or page title is ever used (NFR-02).
"""
import tomllib
from dataclasses import dataclass
from pathlib import Path

from conetuga.explain.template import (EXPLANATIONS, LANGUAGES, SOURCE_TEMPLATE, explain, fill, finding_port,
                                       hide_hostname)

CONE_FILE = Path(__file__).resolve().parents[2] / "data" / "cone.toml"
MODES = ("simple", "advanced")  # the UI passes "advanced" if current().advanced else "simple" (ui/state.py)
SPEAKERS = {"simple": "tuga", "advanced": "cone"}
# A MAC address is locally administered (private, often picked at random by phones and laptops) when the second bit
# of its first byte is set, i.e. when its second hex digit is one of these.
PRIVATE_MAC_DIGITS = "26AE"
EVIDENCE_LINE = "{label}: {value}"  # our template; the label is ours, the value may come from the scan

# Read once, at import: the file is small and never changes while the app runs.
_FILE = tomllib.loads(CONE_FILE.read_text(encoding="utf-8"))
CONE = _FILE["codes"]
LABELS = _FILE["labels"]


@dataclass(frozen=True)
class Narration:
    speaker: str
    title: str
    text: str
    evidence: list[str]
    steps: list[str]
    references: list[str]
    source: str


def narrate(finding, host, lang: str, mode: str) -> Narration:
    """What the current guide says about a finding, in Romanian or English.

    Raises KeyError for an unknown code, language or mode, and LookupError when a finding with a port has no matching
    port on its host (analyse_file returned inconsistent data: a bug to fix, not a case to hide).
    """
    if mode not in MODES:
        raise KeyError(mode)
    if mode == "simple":
        told = explain(finding, host, lang)
        return Narration(SPEAKERS[mode], told.title, told.text, [], told.steps, told.references, told.source)
    if lang not in LANGUAGES:
        raise KeyError(lang)
    cone = CONE[finding.code][lang]
    return Narration(
        speaker=SPEAKERS[mode],
        title=cone["title"],
        text=cone["text"],
        evidence=evidence(finding, host, lang),
        steps=list(cone["steps"]),
        references=list(EXPLANATIONS[finding.code]["references"]),
        source=SOURCE_TEMPLATE,
    )


def evidence(finding, host, lang: str) -> list[str]:
    """Cone's evidence lines: what nmap saw and the catalog rule that fired. Never a hostname, a MAC or a page title:
    the host's name is hidden inside banner text with explain()'s own hide_hostname()."""
    labels = LABELS[lang]
    if finding.port is None:  # UNKNOWN_DEVICE: a rule about a device, not a port
        lines = [line(labels["ip"], host.ip), labels["no_vendor"], labels["no_name"],
                 line(labels["open_ports"], str(len(host.ports)))]
        if is_private_mac(host.mac_masked):
            lines.append(labels["private_mac"])
    else:
        port = finding_port(finding, host)
        lines = [line(labels["port"], f"{port.port}/{port.proto}")]
        if port.service:
            lines.append(line(labels["service"], hide_hostname(port.service, host, lang)))
        program = " ".join(hide_hostname(part, host, lang) for part in (port.product, port.version) if part)
        if program:
            lines.append(line(labels["product"], program))
    lines.append(line(labels["rule"], f"{finding.code} — {CONE[finding.code][lang]['rule']}"))
    lines.append(line(labels["severity"],
                      f"{labels['severity_' + finding.severity]}, {finding.points} {labels['points']}"))
    return lines


def line(label: str, value: str) -> str:
    """One evidence line; the value is inserted as plain text, so "{ip}" from a hostile scan stays literal."""
    return fill(EVIDENCE_LINE, {"label": label, "value": value})


def is_private_mac(mac_masked: str) -> bool:
    """True for a locally administered MAC; only its second hex digit is read, the MAC itself never leaves here."""
    return len(mac_masked) > 1 and mac_masked[1].upper() in PRIVATE_MAC_DIGITS
