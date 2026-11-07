"""Built-in explanations: the text from data/explanations.toml, filled in with values from the scan.

This is what the user reads for every finding: there is no LLM in this version (team decision, 2026-11-07;
specs/contracts.md, section explain). Finding and Host come from stream A; only their attributes are used here, so
this module doesn't import conetuga.analysis.
"""
import re
import string
import tomllib
from dataclasses import dataclass
from pathlib import Path

EXPLANATIONS_FILE = Path(__file__).resolve().parents[2] / "data" / "explanations.toml"
LANGUAGES = ("ro", "en")  # NFR-09: all user-facing text in Romanian and English
SOURCE_TEMPLATE = "template"  # Explanation.source when the text comes from explanations.toml
PRODUCT_CODE = "OUTDATED_SERVICE"  # the only code whose text names the product and version of its port
DEVICE_TYPES_SECTION = "device_types"  # the one top-level table in explanations.toml that isn't a catalog code
# What a host's own name becomes when a scan value (a banner) contains it (NFR-02: no hostname in the output).
# Here and not in explanations.toml, whose top-level tables are catalog codes plus [device_types].
HIDDEN_HOSTNAME = {"ro": "nume ascuns", "en": "hidden name"}
# A character that would make a match only part of a longer word: a letter, a digit or "-" (as in "desk-01").
WORD_CHARACTER = r"[^\W_]|-"

# Read once, at import: the file is small and never changes while the app runs.
_FILE = tomllib.loads(EXPLANATIONS_FILE.read_text(encoding="utf-8"))
DEVICE_LABELS = _FILE[DEVICE_TYPES_SECTION]
EXPLANATIONS = {code: entry for code, entry in _FILE.items() if code != DEVICE_TYPES_SECTION}


@dataclass(frozen=True)
class Explanation:
    title: str
    text: str
    steps: list[str]
    references: list[str]
    source: str


def explain(finding, host, lang: str) -> Explanation:
    """The built-in explanation of one finding, in Romanian or English.

    Raises KeyError for an unknown code or language, and LookupError when an OUTDATED_SERVICE finding has no matching
    port on its host (analyse_file returned inconsistent data: a bug to fix, not a case to hide).
    """
    entry = EXPLANATIONS[finding.code]
    if lang not in LANGUAGES:
        raise KeyError(lang)
    block = entry[lang]
    values = scan_values(finding, host, lang)
    return Explanation(
        title=fill(block["title"], values),
        text=fill(block["text"], values),
        steps=[fill(step, values) for step in block["steps"]],
        references=list(entry["references"]),
        source=SOURCE_TEMPLATE,
    )


def device_label(device_type: str, lang: str) -> str:
    """The label people read for a Host.device_type, such as "Imprimantă" for "printer".

    Raises KeyError for an unknown device type or language.
    """
    if lang not in LANGUAGES:
        raise KeyError(lang)
    return DEVICE_LABELS[device_type][lang]


def device_name(host, lang: str) -> str:
    """How the UI names a device: "office-printer — Imprimantă", or only the label when the scan shows no hostname.

    The same as ui.view.device_name (a test keeps the two equal), here so the Q&A can name devices as the page does
    without conetuga/ importing ui/. The hostname is scan text and is not escaped here: the UI escapes it with md().
    Raises KeyError for an unknown device type or language.
    """
    label = device_label(host.device_type, lang)
    return f"{host.hostname} — {label}" if host.hostname else label


def scan_values(finding, host, lang: str) -> dict[str, str]:
    """The values a template may use, all taken from the finding and its host (NFR-06: nothing invented), with the
    host's name hidden inside banner text (NFR-02)."""
    values = {"ip": finding.ip, "port": "" if finding.port is None else str(finding.port)}
    if finding.code == PRODUCT_CODE:
        port = finding_port(finding, host)
        values["product"] = hide_hostname(port.product, host, lang)
        values["version"] = hide_hostname(port.version, host, lang)
    return values


def hide_hostname(value: str, host, lang: str) -> str:
    """The scan value with host.hostname replaced by "nume ascuns" / "hidden name", ignoring case.

    A banner is hostile text and may carry the device's own name. nmap's name comes from reverse DNS ("desk-01.lan"),
    while a banner (SMB on Windows) often says only the short name ("DESK-01"), so both are hidden: the full name
    first, then its part before the first dot. Only a whole name is replaced, never a part of a longer word: hostname
    "nas.home" leaves "Synology NASdrive" as it is. An empty hostname changes nothing. Raises KeyError for an unknown
    language.
    """
    label = HIDDEN_HOSTNAME[lang]
    for name in host_names(host.hostname):
        whole_name = re.compile(rf"(?<!{WORD_CHARACTER}){re.escape(name)}(?!{WORD_CHARACTER})", re.IGNORECASE)
        value = whole_name.sub(lambda _match: label, value)
    return value


def host_names(hostname: str) -> list[str]:
    """The forms of a host's name to hide, longest first: "desk-01.lan" gives ["desk-01.lan", "desk-01"]."""
    names = [hostname] if hostname else []
    short_name = hostname.split(".", 1)[0]
    if short_name and short_name != hostname:
        names.append(short_name)
    return names


def finding_port(finding, host):
    """The Port of the finding: same number and protocol, since one number can be open on both TCP and UDP."""
    for port in host.ports:
        if (port.port, port.proto) == (finding.port, finding.proto):
            return port
    raise LookupError(f"no port {finding.port}/{finding.proto} on {finding.ip} for {finding.code}")


def fill(template: str, values: dict[str, str]) -> str:
    """Put the values in the template's {name} slots.

    Only our template is parsed; a value is appended as plain text, so a product name such as "{x}" from a hostile
    scan file shows up literally and is never read as a placeholder. A name with no value raises KeyError.
    """
    parts = []
    for literal, name, _spec, _conversion in string.Formatter().parse(template):
        parts.append(literal)
        if name is not None:
            parts.append(values[name])
    return "".join(parts)
