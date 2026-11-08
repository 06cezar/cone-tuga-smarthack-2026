"""wiki_entries(): 20 entries (the 15 catalog codes in catalog order, then 5 concepts), the same ids in every language
and mode, short scan-free texts, and references only for codes."""
import re
import tomllib
from pathlib import Path

import pytest

from conetuga.explain import wiki_entries
from conetuga.explain.narrate import CONE
from conetuga.explain.template import EXPLANATIONS
from conetuga.explain.wiki import ADVANCED, RELATED_CODES, SIMPLE

ROOT = Path(__file__).resolve().parents[1]
CATALOG = tomllib.loads((ROOT / "data" / "catalog.toml").read_text(encoding="utf-8"))
CODES = [finding["code"] for finding in CATALOG["finding"]]
CONCEPTS = ["port", "encryption", "firewall", "mac", "upnp"]  # the contract's order
IDS = CODES + CONCEPTS
LANGUAGES = ("ro", "en")
MODES = ("simple", "advanced")
MAX_SENTENCES = {"simple": 3, "advanced": 4}  # the wiki_entries contract
SENTENCE_END = re.compile(r"[.!?][\"”»)]*(?=\s|$)")  # . ! or ?, maybe a closing quote, then a space or the end
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# A number on its own (a port, a version): the wiki is read without a scan. "SNMPv3" is a name, not a number.
LONE_NUMBER = re.compile(r"(?<![\w.])\d+(?![\w])")
CEDILLA_LETTERS = "şŞţŢ"  # Romanian uses ș/ț with a comma below


def test_contract_wiki_entries():
    entries = wiki_entries("ro", "simple")

    assert len(entries) == 20
    first = entries[0]
    assert (first.id, first.kind, first.speaker) == ("TELNET_OPEN", "code", "tuga")
    assert [entry.id for entry in entries[-5:]] == CONCEPTS
    assert all(entry.kind == "concept" for entry in entries[-5:])
    for entry in entries:
        assert entry.title and entry.text, entry.id
        assert not set("{}") & set(entry.title + entry.text), entry.id
        assert set(entry.related_codes) <= set(CODES), entry.id
    encryption = next(entry for entry in entries if entry.id == "encryption")
    assert "FTP_CLEARTEXT" in encryption.related_codes


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("lang", LANGUAGES)
def test_ids_and_order_are_the_same_in_every_language_and_mode(lang, mode):
    assert [entry.id for entry in wiki_entries(lang, mode)] == IDS


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("lang", LANGUAGES)
def test_every_entry_has_a_title_text_speaker_and_kind(lang, mode):
    for entry in wiki_entries(lang, mode):
        assert entry.title.strip() and entry.text.strip(), (entry.id, lang, mode)
        assert entry.speaker == {"simple": "tuga", "advanced": "cone"}[mode]
        assert entry.kind == ("concept" if entry.id in CONCEPTS else "code")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("lang", LANGUAGES)
def test_codes_cite_their_references_and_concepts_none(lang, mode):
    for entry in wiki_entries(lang, mode):
        expected = EXPLANATIONS[entry.id]["references"] if entry.kind == "code" else []
        assert entry.references == expected, (entry.id, lang, mode)


@pytest.mark.parametrize("lang", LANGUAGES)
def test_advanced_codes_are_cones_title_and_text(lang):
    for entry in wiki_entries(lang, "advanced"):
        if entry.kind == "code":
            assert (entry.title, entry.text) == (CONE[entry.id][lang]["title"], CONE[entry.id][lang]["text"])


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("lang", LANGUAGES)
def test_texts_stay_within_the_sentence_limit(lang, mode):
    for entry in wiki_entries(lang, mode):
        assert len(SENTENCE_END.findall(entry.text.strip())) <= MAX_SENTENCES[mode], (entry.id, lang, mode)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("lang", LANGUAGES)
def test_texts_hold_no_placeholder_address_or_number(lang, mode):
    for entry in wiki_entries(lang, mode):
        for text in (entry.title, entry.text):
            assert "{" not in text and "}" not in text, (entry.id, lang, mode)
            assert not IPV4.search(text), (entry.id, lang, mode)
            assert not LONE_NUMBER.search(text), (entry.id, lang, mode, text)


@pytest.mark.parametrize("mode", MODES)
def test_romanian_uses_comma_below_letters(mode):
    for entry in wiki_entries("ro", mode):
        assert not set(CEDILLA_LETTERS) & set(entry.title + entry.text), (entry.id, mode)


def test_wiki_file_covers_exactly_the_expected_ids_in_both_languages():
    assert set(SIMPLE) == set(IDS)
    assert set(ADVANCED) == set(CONCEPTS)  # Cone's texts for the codes live in data/cone.toml
    for table in (SIMPLE, ADVANCED):
        for entry_id, block in table.items():
            assert set(block) == set(LANGUAGES), entry_id
            for lang in LANGUAGES:
                assert set(block[lang]) == {"title", "text"}, (entry_id, lang)


@pytest.mark.parametrize("lang, mode", [("fr", "simple"), ("ro", "expert"), ("", "")])
def test_unknown_language_or_mode_raises_key_error(lang, mode):
    with pytest.raises(KeyError):
        wiki_entries(lang, mode)


def test_every_id_has_its_related_codes_listed():
    assert set(RELATED_CODES) == set(IDS)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("lang", LANGUAGES)
def test_related_codes_are_valid_catalog_codes_in_catalog_order_and_never_the_entry_itself(lang, mode):
    for entry in wiki_entries(lang, mode):
        assert all(code in CODES for code in entry.related_codes), entry.id
        assert entry.id not in entry.related_codes, entry.id
        assert entry.related_codes == sorted(set(entry.related_codes), key=CODES.index), entry.id


def test_related_codes_are_the_same_in_every_language_and_mode():
    expected = [entry.related_codes for entry in wiki_entries("ro", "simple")]
    for lang in LANGUAGES:
        for mode in MODES:
            assert [entry.related_codes for entry in wiki_entries(lang, mode)] == expected, (lang, mode)


def test_contract_wiki_entries_steps():
    """The contract's example for `steps` (added for the About page's wiki): Telnet's five steps, none for concepts."""
    entries = {entry.id: entry for entry in wiki_entries("ro", "simple")}
    assert len(entries["TELNET_OPEN"].steps) == 5
    assert entries["TELNET_OPEN"].steps[0] == ("Intră în setările dispozitivului (din aplicația lui sau din browser) "
                                               "și caută opțiunea „Telnet”.")
    assert all(entries[concept].steps == [] for concept in CONCEPTS)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("lang", LANGUAGES)
def test_every_code_has_its_fixes_as_steps_without_a_scan_value(lang, mode):
    """As many steps as the finding page shows, in the same order, with no placeholder, address or lone number."""
    for entry in wiki_entries(lang, mode):
        if entry.kind != "code":
            continue
        assert len(entry.steps) == len(EXPLANATIONS[entry.id][lang]["steps"]), (entry.id, lang)
        assert 1 <= len(entry.steps) <= 5, entry.id
        for step in entry.steps:
            assert not set("{}") & set(step) and not IPV4.search(step), (entry.id, step)
            assert not LONE_NUMBER.search(step), (entry.id, step)


def test_steps_without_a_placeholder_are_the_finding_pages_own_words():
    """Only the steps that name a scan value are rewritten; every other step is word for word the finding page's."""
    for entry in wiki_entries("en", "simple"):
        for original, generic in zip(EXPLANATIONS.get(entry.id, {}).get("en", {}).get("steps", []), entry.steps):
            if "{" not in original:
                assert generic == original, entry.id
