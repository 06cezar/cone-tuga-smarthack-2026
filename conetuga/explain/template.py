"""Built-in explanations: the text from data/explanations.toml, filled in with values from the scan.

This is what the user reads when there's no LLM, or when an LLM answer fails the grounding check
(specs/contracts.md, section explain). Finding and Host come from stream A; only their attributes are used here, so
this module doesn't import conetuga.analysis.
"""
import string
import tomllib
from dataclasses import dataclass
from pathlib import Path

EXPLANATIONS_FILE = Path(__file__).resolve().parents[2] / "data" / "explanations.toml"
LANGUAGES = ("ro", "en")  # NFR-09: all user-facing text in Romanian and English
SOURCE_TEMPLATE = "template"  # Explanation.source when the text comes from explanations.toml
PRODUCT_CODE = "OUTDATED_SERVICE"  # the only code whose text names the product and version of its port

# Read once, at import: the file is small and never changes while the app runs.
EXPLANATIONS = tomllib.loads(EXPLANATIONS_FILE.read_text(encoding="utf-8"))


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
    values = scan_values(finding, host)
    return Explanation(
        title=fill(block["title"], values),
        text=fill(block["text"], values),
        steps=[fill(step, values) for step in block["steps"]],
        references=list(entry["references"]),
        source=SOURCE_TEMPLATE,
    )


def scan_values(finding, host) -> dict[str, str]:
    """The values a template may use, all taken from the finding and its host (NFR-06: nothing invented)."""
    values = {"ip": finding.ip, "port": "" if finding.port is None else str(finding.port)}
    if finding.code == PRODUCT_CODE:
        port = finding_port(finding, host)
        values["product"] = port.product
        values["version"] = port.version
    return values


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
