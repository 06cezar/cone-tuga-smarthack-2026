"""The threat wiki ("Wiki amenințări", specs/contracts.md, section wiki_entries): one entry per catalog code, then a
few basic network concepts, as Tuga 🐢 tells them in Simple mode or Cone 🐇 in Advanced mode.

No scan is needed and none is read: the texts come from data/wiki.toml (Simple, and Advanced for the concepts) and
data/cone.toml (Advanced for the codes), and none of them holds a scan value. References come from
data/explanations.toml, so the wiki cites the same CIS Controls / OWASP IoT items as the finding pages; related codes
(the Wiki's links between entries) come from data/wiki.toml and are the same in every language and mode.
"""
import tomllib
from dataclasses import dataclass
from pathlib import Path

from conetuga.explain.narrate import CONE, MODES, SPEAKERS
from conetuga.explain.template import EXPLANATIONS, LANGUAGES

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
WIKI_FILE = DATA_DIR / "wiki.toml"
# The catalog is read here only for the order of its codes; this module doesn't import conetuga.analysis.
CATALOG_FILE = DATA_DIR / "catalog.toml"
CONCEPTS = ("port", "encryption", "firewall", "mac", "upnp")  # shown after the codes, in this order
KIND_CODE = "code"
KIND_CONCEPT = "concept"

# Read once, at import: the files are small and never change while the app runs.
_WIKI = tomllib.loads(WIKI_FILE.read_text(encoding="utf-8"))
SIMPLE = _WIKI["simple"]
ADVANCED = _WIKI["advanced"]
RELATED_CODES = _WIKI["related_codes"]
CODES = tuple(finding["code"] for finding in tomllib.loads(CATALOG_FILE.read_text(encoding="utf-8"))["finding"])


@dataclass(frozen=True)
class WikiEntry:
    id: str
    kind: str
    speaker: str
    title: str
    text: str
    references: list[str]
    related_codes: list[str]


def wiki_entries(lang: str, mode: str) -> list[WikiEntry]:
    """Every wiki entry, in Romanian or English, as the current guide tells it: the 15 catalog codes in catalog order,
    then the concepts. The ids and their order are the same in every language and mode.

    Raises KeyError for an unknown language or mode.
    """
    if lang not in LANGUAGES:
        raise KeyError(lang)
    if mode not in MODES:
        raise KeyError(mode)
    codes = [entry(code, KIND_CODE, lang, mode) for code in CODES]
    concepts = [entry(concept, KIND_CONCEPT, lang, mode) for concept in CONCEPTS]
    return codes + concepts


def entry(entry_id: str, kind: str, lang: str, mode: str) -> WikiEntry:
    """One entry: its text from the right file for the mode, references only for codes, the same related codes
    in every language and mode."""
    if mode == "simple":
        block = SIMPLE[entry_id][lang]
    elif kind == KIND_CODE:
        block = CONE[entry_id][lang]
    else:
        block = ADVANCED[entry_id][lang]
    references = list(EXPLANATIONS[entry_id]["references"]) if kind == KIND_CODE else []
    return WikiEntry(entry_id, kind, SPEAKERS[mode], block["title"], block["text"], references,
                     list(RELATED_CODES[entry_id]))
