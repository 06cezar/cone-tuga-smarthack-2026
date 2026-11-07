"""narrate(): Tuga 🐢 is today's explain() word for word; Cone 🐇 has its own scan-free texts plus evidence lines
built from the scan and the catalog, with scan values as plain text and never a hostname, a MAC or a page title."""
import re
import tomllib
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from conetuga.analysis import analyse_file
from conetuga.explain import explain, narrate
from conetuga.explain.narrate import CONE, CONE_FILE, LABELS, MODES
from conetuga.explain.template import HIDDEN_HOSTNAME
from nmap_xml import host as xml_host, port as xml_port, write_scan

ROOT = Path(__file__).resolve().parents[1]
SCANS = ROOT / "tests" / "fixtures" / "validation" / "scans"
LAB_SCAN = ROOT / "lab" / "scans" / "scan_01.xml"
CATALOG = tomllib.loads((ROOT / "data" / "catalog.toml").read_text(encoding="utf-8"))
CODES = [finding["code"] for finding in CATALOG["finding"]]
LANGUAGES = ("ro", "en")
READABLE_SCANS = sorted(path for path in SCANS.glob("*.xml") if path.name != "V7_broken.xml")
MAX_SENTENCES = 2  # FR-07
MIN_STEPS, MAX_STEPS = 1, 5  # FR-08
SENTENCE_END = re.compile(r"[.!?][\"”»)]*(?=\s|$)")  # . ! or ?, maybe a closing quote, then a space or the end
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# A number on its own (a port, a version): Cone's texts must stay true for every scan. "SNMPv3" or "SMBv1" are names.
LONE_NUMBER = re.compile(r"(?<![\w.])\d+(?![\w])")
CEDILLA_LETTERS = "şŞţŢ"  # Romanian uses ș/ț with a comma below


def finding_on(result, code: str, ip: str | None = None):
    finding = next(f for f in result.findings if f.code == code and (ip is None or f.ip == ip))
    host = next(h for h in result.hosts if h.ip == finding.ip)
    return finding, host


def all_text(narration) -> str:
    return " ".join([narration.title, narration.text, *narration.evidence, *narration.steps, *narration.references])


def test_contract_narrate():
    finding, host = finding_on(analyse_file(SCANS / "V3_small_office.xml"), "PRINTER_RAW_EXPOSED")

    tuga = narrate(finding, host, "ro", "simple")
    told = explain(finding, host, "ro")
    assert tuga.speaker == "tuga"
    assert (tuga.title, tuga.text, tuga.steps, tuga.references) == (told.title, told.text, told.steps,
                                                                    told.references)
    assert tuga.evidence == []

    cone = narrate(finding, host, "en", "advanced")
    assert cone.speaker == "cone"
    lines = " ".join(cone.evidence)
    assert "9100/tcp" in lines and "jetdirect" in lines and "PRINTER_RAW_EXPOSED" in lines
    assert not any(line.startswith(LABELS["en"]["product"]) for line in cone.evidence)
    assert cone.references == explain(finding, host, "en").references
    assert MIN_STEPS <= len(cone.steps) <= MAX_STEPS
    assert cone.source == "template"


def make_finding(code: str):
    port, proto = (None, "") if code == "UNKNOWN_DEVICE" else (8080, "tcp")
    return SimpleNamespace(file="test.xml", ip="10.0.0.7", port=port, proto=proto, code=code, severity="high",
                           points=20, evidence="")


def make_host():
    port = SimpleNamespace(port=8080, proto="tcp", service="http", product="vsftpd", version="2.3.4", ssl=False,
                           title="")
    return SimpleNamespace(ip="10.0.0.7", mac_masked="", vendor="", hostname="", device_type="unknown", ports=[port],
                           timed_out=False)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("lang", LANGUAGES)
@pytest.mark.parametrize("code", CODES)
def test_every_code_language_and_mode_is_narrated(code, lang, mode):
    narration = narrate(make_finding(code), make_host(), lang, mode)
    assert narration.speaker == {"simple": "tuga", "advanced": "cone"}[mode]
    assert narration.title and narration.text
    assert MIN_STEPS <= len(narration.steps) <= MAX_STEPS
    assert narration.references and narration.source == "template"
    assert bool(narration.evidence) == (mode == "advanced")


def cone_texts():
    for code in CODES:
        for lang in LANGUAGES:
            entry = CONE[code][lang]
            for field in ("title", "text", "rule"):
                yield code, lang, field, entry[field]
            for step in entry["steps"]:
                yield code, lang, "step", step


def test_cone_covers_exactly_the_catalog_codes_in_both_languages():
    assert set(CONE) == set(CODES)
    for code in CODES:
        assert set(CONE[code]) == set(LANGUAGES), code
        for lang in LANGUAGES:
            assert set(CONE[code][lang]) == {"title", "text", "rule", "steps"}, (code, lang)


def test_cone_text_is_at_most_two_sentences():
    for code in CODES:
        for lang in LANGUAGES:
            assert len(SENTENCE_END.findall(CONE[code][lang]["text"].strip())) <= MAX_SENTENCES, (code, lang)


def test_cone_has_one_to_five_steps_and_the_same_number_in_both_languages():
    for code in CODES:
        assert MIN_STEPS <= len(CONE[code]["ro"]["steps"]) <= MAX_STEPS, code
        assert len(CONE[code]["ro"]["steps"]) == len(CONE[code]["en"]["steps"]), code


def test_cone_texts_hold_no_placeholder_address_or_number():
    for code, lang, field, text in cone_texts():
        assert "{" not in text and "}" not in text, (code, lang, field)
        assert not IPV4.search(text), (code, lang, field)
        assert not LONE_NUMBER.search(text), (code, lang, field, text)


def test_labels_have_the_same_keys_in_both_languages():
    assert set(LABELS["ro"]) == set(LABELS["en"])


def test_romanian_uses_comma_below_s_and_t_not_cedilla():
    raw = CONE_FILE.read_text(encoding="utf-8")
    assert [char for char in CEDILLA_LETTERS if char in raw] == []


@pytest.mark.parametrize("lang", LANGUAGES)
@pytest.mark.parametrize("path", READABLE_SCANS, ids=lambda path: path.name)
def test_simple_is_explain_word_for_word(path, lang):
    result = analyse_file(path)
    hosts = {host.ip: host for host in result.hosts}
    for finding in result.findings:
        told = explain(finding, hosts[finding.ip], lang)
        tuga = narrate(finding, hosts[finding.ip], lang, "simple")
        assert (tuga.title, tuga.text, tuga.steps, tuga.references, tuga.source) == (
            told.title, told.text, told.steps, told.references, told.source)
        assert tuga.evidence == []


def test_outdated_service_evidence_names_the_product_and_version():
    finding, host = finding_on(analyse_file(LAB_SCAN), "OUTDATED_SERVICE")
    assert f"{LABELS['en']['product']}: vsftpd 2.3.4" in narrate(finding, host, "en", "advanced").evidence


def test_hostile_product_and_version_stay_literal_in_the_evidence():
    finding, host = finding_on(analyse_file(LAB_SCAN), "OUTDATED_SERVICE")
    hostile = [replace(port, product="{ip}<script>", version="{port}") if port.port == finding.port else port
               for port in host.ports]
    narration = narrate(finding, replace(host, ports=hostile), "ro", "advanced")
    assert f"{LABELS['ro']['product']}: {{ip}}<script> {{port}}" in narration.evidence


def test_unknown_device_evidence_on_the_lab_scan():
    finding, host = finding_on(analyse_file(LAB_SCAN), "UNKNOWN_DEVICE")
    labels = LABELS["ro"]

    narration = narrate(finding, host, "ro", "advanced")

    assert narration.evidence[:4] == [f"{labels['ip']}: 172.20.10.2", labels["no_vendor"], labels["no_name"],
                                      f"{labels['open_ports']}: {len(host.ports)}"]
    assert labels["private_mac"] not in narration.evidence  # 6C:..., not locally administered


@pytest.mark.parametrize("mac", ["DA:12:34:xx:xx:xx", "a2:12:34:xx:xx:xx", "36:12:34:xx:xx:xx", "1E:12:34:xx:xx:xx"])
def test_a_private_mac_is_named_but_never_shown(mac):
    finding, host = finding_on(analyse_file(LAB_SCAN), "UNKNOWN_DEVICE")
    narration = narrate(finding, replace(host, mac_masked=mac), "en", "advanced")
    assert LABELS["en"]["private_mac"] in narration.evidence
    assert mac[:8].upper() not in all_text(narration).upper()


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("lang", LANGUAGES)
def test_no_hostname_mac_or_page_title_in_any_narration(lang, mode):
    result = analyse_file(SCANS / "V1_home_basic.xml")  # router.lan, page title "Router Login"
    finding, host = finding_on(result, "HTTP_ADMIN_CLEARTEXT")
    host = replace(host, hostname="secret-hostname", ports=[replace(p, title="Secret Page Title") for p in host.ports])

    text = all_text(narrate(finding, host, lang, mode))

    for private in ("secret-hostname", "Secret Page Title", host.mac_masked, host.mac_masked[:8]):
        assert private not in text


def test_unknown_mode_raises_key_error():
    finding, host = finding_on(analyse_file(SCANS / "V3_small_office.xml"), "PRINTER_RAW_EXPOSED")
    with pytest.raises(KeyError):
        narrate(finding, host, "en", "expert")


@pytest.mark.parametrize("mode", MODES)
def test_unknown_language_raises_key_error(mode):
    finding, host = finding_on(analyse_file(SCANS / "V3_small_office.xml"), "PRINTER_RAW_EXPOSED")
    with pytest.raises(KeyError):
        narrate(finding, host, "fr", mode)


@pytest.mark.parametrize("mode", MODES)
def test_unknown_code_raises_key_error(mode):
    with pytest.raises(KeyError):
        narrate(make_finding("NOT_A_CODE"), make_host(), "en", mode)


def test_advanced_without_the_findings_port_raises_lookup_error():
    finding, host = finding_on(analyse_file(SCANS / "V3_small_office.xml"), "PRINTER_RAW_EXPOSED")
    with pytest.raises(LookupError):
        narrate(finding, replace(host, ports=[]), "en", "advanced")


HOSTILE_MAC = "AA:BB:CC:11:22:33"


def outdated_on(tmp_path, product: str, version: str, hostname: str):
    """The OUTDATED_SERVICE finding and its host, from a scan written in tmp_path (vsftpd 2.3.4 is on the list)."""
    path = write_scan(tmp_path, xml_host("10.0.0.5", xml_port(21, "ftp", product=product, version=version),
                                         hostname=hostname))
    return finding_on(analyse_file(path), "OUTDATED_SERVICE")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("lang", LANGUAGES)
def test_hostname_inside_product_and_version_is_hidden_in_every_mode(tmp_path, lang, mode):
    finding, host = outdated_on(tmp_path, "vsftpd on DESK-01", "2.3.4 desk-01", hostname="desk-01")
    text = all_text(narrate(finding, host, lang, mode))
    assert "desk-01" not in text.casefold()
    assert HIDDEN_HOSTNAME[lang] in text


def test_hostname_in_the_evidence_is_replaced_by_the_label(tmp_path):
    finding, host = outdated_on(tmp_path, "vsftpd on DESK-01", "2.3.4 desk-01", hostname="desk-01")
    evidence = narrate(finding, host, "en", "advanced").evidence
    assert f"{LABELS['en']['product']}: vsftpd on hidden name 2.3.4 hidden name" in evidence


def test_hostname_inside_a_longer_word_is_kept_in_the_evidence(tmp_path):
    finding, host = outdated_on(tmp_path, "vsftpd Synology NASdrive", "2.3.4", hostname="nas")
    evidence = narrate(finding, host, "ro", "advanced").evidence
    assert f"{LABELS['ro']['product']}: vsftpd Synology NASdrive 2.3.4" in evidence


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("lang", LANGUAGES)
def test_mac_inside_product_never_reaches_the_narration(tmp_path, lang, mode):
    finding, host = outdated_on(tmp_path, f"device {HOSTILE_MAC} vsftpd", "2.3.4", hostname="")
    assert HOSTILE_MAC not in all_text(narrate(finding, host, lang, mode)).upper()


def test_short_and_full_hostname_are_hidden_in_the_evidence(tmp_path):
    finding, host = outdated_on(tmp_path, "vsftpd on DESK-01", "2.3.4 desk-01.lan", hostname="desk-01.lan")
    evidence = narrate(finding, host, "en", "advanced").evidence
    assert f"{LABELS['en']['product']}: vsftpd on hidden name 2.3.4 hidden name" in evidence
