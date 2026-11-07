"""The built-in explanations (data/explanations.toml) are what the user reads when there's no LLM: these tests keep them
complete, short and free of invented facts (FR-07, FR-08, NFR-06, NFR-09)."""
import re
import string
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = tomllib.loads((ROOT / "data" / "catalog.toml").read_text(encoding="utf-8"))
EXPLANATIONS = tomllib.loads((ROOT / "data" / "explanations.toml").read_text(encoding="utf-8"))
RAW_EXPLANATIONS = (ROOT / "data" / "explanations.toml").read_text(encoding="utf-8")

LANGUAGES = ("ro", "en")  # NFR-09: all user-facing text in Romanian and English
MAX_SENTENCES = 2  # FR-07: an explanation of at most 2 sentences
MIN_STEPS, MAX_STEPS = 1, 5  # FR-08: 1–5 ordered steps per finding
ALLOWED_PLACEHOLDERS = {"ip", "port", "product", "version"}  # the evidence code fills in from Finding and Host
PRODUCT_PLACEHOLDERS = {"product", "version"}  # only an outdated-software finding names the product
PRODUCT_CODE = "OUTDATED_SERVICE"
PORTLESS_CODE = "UNKNOWN_DEVICE"  # the brief: its port column stays empty

# A sentence ends at . ! or ?, optionally followed by a closing quote or bracket, then a space or the end of the text.
SENTENCE_END = re.compile(r"[.!?][\"”»)]*(?=\s|$)")
# A standalone number (a port, a version such as 2.3.4, an IP, a phone number). A digit glued to a word, as in the
# protocol name "SNMPv3", is part of a name, not a value from a scan.
STANDALONE_NUMBER = re.compile(r"(?<![\w.])\d+(?:\.\d+)*(?!\w)")
IP_ADDRESS = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
CVE_ID = re.compile(r"\bCVE\b", re.IGNORECASE)
CEDILLA_LETTERS = "şţŞŢ"  # U+015F, U+0163, U+015E, U+0162: the wrong Romanian letters (Turkish style)


def user_texts() -> list[tuple[str, str, str, str]]:
    """Every user-facing string, as (code, language, field, text), so one check runs over all of them."""
    texts = []
    for code, entry in EXPLANATIONS.items():
        for lang in LANGUAGES:
            block = entry[lang]
            texts.append((code, lang, "title", block["title"]))
            texts.append((code, lang, "text", block["text"]))
            texts += [(code, lang, f"steps[{i}]", step) for i, step in enumerate(block["steps"])]
    return texts


def placeholders(text: str) -> set[str]:
    """The {names} in a str.format template; a malformed brace raises ValueError, which fails the test."""
    return {field for _, field, _, _ in string.Formatter().parse(text) if field is not None}


def placeholders_of(code: str) -> set[str]:
    return set().union(*(placeholders(text) for c, _, _, text in user_texts() if c == code))


def test_explanations_cover_exactly_the_catalog_codes():
    assert set(EXPLANATIONS) == {finding["code"] for finding in CATALOG["finding"]}


def test_every_code_has_references_and_both_languages():
    for code, entry in EXPLANATIONS.items():
        assert set(entry) == {"references", *LANGUAGES}, code
        assert entry["references"] and all(isinstance(r, str) and r for r in entry["references"]), code


def test_every_language_has_a_title_a_text_and_steps():
    for code, entry in EXPLANATIONS.items():
        for lang in LANGUAGES:
            block = entry[lang]
            assert set(block) == {"title", "text", "steps"}, (code, lang)
            assert isinstance(block["title"], str) and block["title"].strip(), (code, lang)
            assert isinstance(block["text"], str) and block["text"].strip(), (code, lang)
            assert isinstance(block["steps"], list), (code, lang)
            assert all(isinstance(s, str) and s.strip() for s in block["steps"]), (code, lang)


def test_text_is_at_most_two_sentences():
    too_long = [
        (code, lang, len(SENTENCE_END.findall(entry[lang]["text"].strip())))
        for code, entry in EXPLANATIONS.items()
        for lang in LANGUAGES
        if len(SENTENCE_END.findall(entry[lang]["text"].strip())) > MAX_SENTENCES
    ]
    assert too_long == []


def test_every_language_has_one_to_five_steps():
    for code, entry in EXPLANATIONS.items():
        for lang in LANGUAGES:
            assert MIN_STEPS <= len(entry[lang]["steps"]) <= MAX_STEPS, (code, lang)


def test_romanian_and_english_have_the_same_number_of_steps():
    for code, entry in EXPLANATIONS.items():
        assert len(entry["ro"]["steps"]) == len(entry["en"]["steps"]), code


def test_only_evidence_placeholders_are_used():
    unknown = [(code, lang, field, placeholders(text) - ALLOWED_PLACEHOLDERS)
               for code, lang, field, text in user_texts() if placeholders(text) - ALLOWED_PLACEHOLDERS]
    assert unknown == []


def test_product_and_version_appear_only_in_outdated_service():
    for code in EXPLANATIONS:
        if code != PRODUCT_CODE:
            assert not placeholders_of(code) & PRODUCT_PLACEHOLDERS, code


def test_unknown_device_has_no_port_placeholder():
    assert "port" not in placeholders_of(PORTLESS_CODE)


def test_no_hard_coded_ip_address():
    assert [(c, lang, field) for c, lang, field, text in user_texts() if IP_ADDRESS.search(text)] == []


def test_no_hard_coded_number_such_as_a_port_version_or_phone():
    found = [(c, lang, field, STANDALONE_NUMBER.findall(text))
             for c, lang, field, text in user_texts() if STANDALONE_NUMBER.search(text)]
    assert found == []


def test_no_cve_identifier():
    assert [(c, lang, field) for c, lang, field, text in user_texts() if CVE_ID.search(text)] == []


def test_romanian_uses_comma_below_s_and_t_not_cedilla():
    assert [ch for ch in CEDILLA_LETTERS if ch in RAW_EXPLANATIONS] == []
