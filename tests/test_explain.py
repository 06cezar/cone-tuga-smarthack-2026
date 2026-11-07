"""explain() with the built-in text: every finding gets a filled-in explanation, built only from scan values.

Finding, Host and Port are built with types.SimpleNamespace and keyword arguments, after the examples in
specs/contracts.md: they are test data until stream A's dataclasses land (PR #5), not stubs of them.
"""
import importlib
import importlib.util
import re
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from conetuga.explain import device_label, explain
from conetuga.explain.template import HIDDEN_HOSTNAME, hide_hostname
from nmap_xml import host as xml_host, port as xml_port, write_scan

ROOT = Path(__file__).resolve().parents[1]
CATALOG = tomllib.loads((ROOT / "data" / "catalog.toml").read_text(encoding="utf-8"))
CODES = [finding["code"] for finding in CATALOG["finding"]]
LANGUAGES = ("ro", "en")
SCANS = ROOT / "tests" / "fixtures" / "validation" / "scans"
MAX_SENTENCES = 2  # FR-07
MIN_STEPS, MAX_STEPS = 1, 5  # FR-08
SENTENCE_END = re.compile(r"[.!?][\"”»)]*(?=\s|$)")  # . ! or ?, maybe a closing quote, then a space or the end
# The 10 values of Host.device_type in the analyse_file contract (specs/contracts.md).
DEVICE_TYPES = ["camera", "printer", "nas", "router", "tv", "smart-home", "computer", "server", "phone", "unknown"]
EXPLANATIONS_DEVICE_TYPES = tomllib.loads((ROOT / "data" / "explanations.toml").read_text(encoding="utf-8"))[
    "device_types"]
HAS_DEVICES_MODULE = importlib.util.find_spec("conetuga.analysis.devices") is not None

try:
    from conetuga.analysis import analyse_file
except ImportError:
    analyse_file = None


def make_port(port: int, proto: str = "tcp", service: str = "", product: str = "", version: str = ""):
    return SimpleNamespace(port=port, proto=proto, service=service, product=product, version=version, ssl=False,
                           title="")


def make_host(ip: str, ports: list):
    return SimpleNamespace(ip=ip, mac_masked="", vendor="", hostname="", device_type="", ports=ports)


def make_finding(code: str, ip: str, port: int | None, proto: str):
    return SimpleNamespace(file="test.xml", ip=ip, port=port, proto=proto, code=code, severity="", points=0,
                           evidence="")


def all_text(explanation) -> str:
    return " ".join([explanation.title, explanation.text, *explanation.steps])


def test_contract_explain():
    finding = SimpleNamespace(file="V1_home_basic.xml", ip="192.168.1.1", port=80, proto="tcp",
                              code="HTTP_ADMIN_CLEARTEXT", severity="medium", points=10, evidence="")
    host = make_host("192.168.1.1", [make_port(80, "tcp", service="http", product="lighttpd")])

    explanation = explain(finding, host, "ro")

    assert len(SENTENCE_END.findall(explanation.text.strip())) <= MAX_SENTENCES
    assert MIN_STEPS <= len(explanation.steps) <= MAX_STEPS
    assert explanation.source == "template"
    assert "192.168.1.1" in explanation.text


@pytest.mark.parametrize("lang", LANGUAGES)
@pytest.mark.parametrize("code", CODES)
def test_every_code_and_language_leaves_no_placeholder(code, lang):
    port, proto = (None, "") if code == "UNKNOWN_DEVICE" else (8080, "tcp")
    host = make_host("10.0.0.7", [make_port(8080, "tcp", product="vsftpd", version="2.3.4")])

    text = all_text(explain(make_finding(code, "10.0.0.7", port, proto), host, lang))

    assert "{" not in text and "}" not in text


def test_outdated_service_takes_product_and_version_from_the_port_with_the_same_proto():
    host = make_host("10.0.0.5", [
        make_port(53, "tcp", product="TcpProduct", version="1.1"),
        make_port(53, "udp", product="UdpProduct", version="2.2"),
    ])

    over_tcp = all_text(explain(make_finding("OUTDATED_SERVICE", "10.0.0.5", 53, "tcp"), host, "en"))
    over_udp = all_text(explain(make_finding("OUTDATED_SERVICE", "10.0.0.5", 53, "udp"), host, "en"))

    assert "TcpProduct 1.1" in over_tcp and "UdpProduct" not in over_tcp
    assert "UdpProduct 2.2" in over_udp and "TcpProduct" not in over_udp


def test_unknown_device_without_port_or_proto_is_explained():
    host = make_host("10.0.0.9", [make_port(8888, "tcp")])

    explanation = explain(make_finding("UNKNOWN_DEVICE", "10.0.0.9", None, ""), host, "ro")

    assert "10.0.0.9" in explanation.text
    assert "{" not in all_text(explanation)


def test_unknown_code_raises_key_error():
    with pytest.raises(KeyError):
        explain(make_finding("NOT_A_CODE", "10.0.0.1", 80, "tcp"), make_host("10.0.0.1", []), "ro")


@pytest.mark.parametrize("lang", ["fr", "", "references"])
def test_unknown_language_raises_key_error(lang):
    host = make_host("10.0.0.1", [make_port(23, "tcp")])
    with pytest.raises(KeyError):
        explain(make_finding("TELNET_OPEN", "10.0.0.1", 23, "tcp"), host, lang)


def test_product_containing_braces_appears_literally():
    # Each value names a placeholder filled after it, so a fill that re-reads its own output would change it.
    host = make_host("10.0.0.5", [make_port(21, "tcp", product="evil{x}{version}", version="{product}")])

    text = explain(make_finding("OUTDATED_SERVICE", "10.0.0.5", 21, "tcp"), host, "en").text

    assert "evil{x}{version} {product}" in text


def test_outdated_service_without_matching_port_raises_lookup_error():
    host = make_host("10.0.0.5", [make_port(21, "udp", product="vsftpd", version="2.3.4")])

    with pytest.raises(LookupError) as excinfo:
        explain(make_finding("OUTDATED_SERVICE", "10.0.0.5", 21, "tcp"), host, "en")

    assert excinfo.type is LookupError  # not its subclass KeyError, which means an unknown code or language


@pytest.mark.skipif(analyse_file is None, reason="stream A: conetuga.analysis.analyse_file doesn't exist yet")
def test_every_validation_set_finding_is_explained_in_both_languages():
    for path in sorted(p for p in SCANS.iterdir() if p.is_file() and not p.name.startswith(".")):
        result = analyse_file(path)
        hosts = {host.ip: host for host in result.hosts}
        for finding in result.findings:
            for lang in LANGUAGES:
                assert "{" not in all_text(explain(finding, hosts[finding.ip], lang)), (path.name, finding, lang)


def test_contract_device_label():
    assert device_label("nas", "ro") == "Dispozitiv de stocare în rețea (NAS)"
    assert device_label("nas", "en") == "Network storage (NAS)"


@pytest.mark.parametrize("lang", LANGUAGES)
@pytest.mark.parametrize("device_type", DEVICE_TYPES)
def test_every_device_type_has_a_label_in_both_languages(device_type, lang):
    label = device_label(device_type, lang)
    assert isinstance(label, str) and label.strip()


def test_unknown_device_type_raises_key_error():
    with pytest.raises(KeyError):
        device_label("toaster", "ro")


@pytest.mark.parametrize("lang", ["fr", ""])
def test_unknown_language_for_a_device_label_raises_key_error(lang):
    with pytest.raises(KeyError):
        device_label("printer", lang)


@pytest.mark.skipif(not HAS_DEVICES_MODULE, reason="stream A: conetuga.analysis.devices doesn't exist yet")
def test_device_labels_cover_exactly_the_analysis_device_types():
    """A device type that stream A adds or renames fails here, instead of showing up untranslated in the UI."""
    devices = importlib.import_module("conetuga.analysis.devices")
    analysis_types = {value for name, value in vars(devices).items()
                      if name.startswith("DEVICE_") and isinstance(value, str)}  # DEVICE_RULES is a tuple, not a type
    assert analysis_types == set(EXPLANATIONS_DEVICE_TYPES)


HOSTILE_MAC = "AA:BB:CC:11:22:33"


def outdated_on(tmp_path, product: str, version: str, hostname: str):
    """The OUTDATED_SERVICE finding and its host, from a scan written in tmp_path (vsftpd 2.3.4 is on the list)."""
    path = write_scan(tmp_path, xml_host("10.0.0.5", xml_port(21, "ftp", product=product, version=version),
                                         hostname=hostname))
    result = analyse_file(path)
    finding = next(f for f in result.findings if f.code == "OUTDATED_SERVICE")
    return finding, next(h for h in result.hosts if h.ip == finding.ip)


@pytest.mark.parametrize("lang", LANGUAGES)
def test_hostname_inside_product_and_version_is_hidden(tmp_path, lang):
    finding, host = outdated_on(tmp_path, "vsftpd on DESK-01", "2.3.4 desk-01", hostname="desk-01")
    text = all_text(explain(finding, host, lang))
    assert "desk-01" not in text.casefold()
    assert HIDDEN_HOSTNAME[lang] in text


@pytest.mark.parametrize("lang", LANGUAGES)
def test_hostname_inside_a_longer_word_is_kept(tmp_path, lang):
    finding, host = outdated_on(tmp_path, "vsftpd Synology NASdrive", "2.3.4", hostname="nas")
    text = all_text(explain(finding, host, lang))
    assert "Synology NASdrive" in text
    assert HIDDEN_HOSTNAME[lang] not in text


@pytest.mark.parametrize("hostname, value, expected", [
    ("nas", "NAS box", "hidden name box"),
    ("nas", "Synology NASdrive", "Synology NASdrive"),
    ("nas", "my-nas", "my-nas"),
    ("nas", "nas2", "nas2"),
    ("desk-01", "vsftpd on Desk-01.", "vsftpd on hidden name."),
    ("a.b", "aXb a.b", "aXb hidden name"),  # the hostname is matched as text, never as a pattern
    ("", "vsftpd", "vsftpd"),
    ("desk-01.lan", "vsftpd on DESK-01", "vsftpd on hidden name"),  # banners carry the short name
    ("desk-01.lan", "2.3.4 desk-01.lan", "2.3.4 hidden name"),  # the full name first, so no ".lan" is left
    ("nas.home", "Synology NASdrive", "Synology NASdrive"),
    (".lan", "x.lan .lan", "x.lan hidden name"),  # no empty short name
])
def test_hide_hostname_replaces_only_the_whole_name(hostname, value, expected):
    assert hide_hostname(value, SimpleNamespace(hostname=hostname), "en") == expected


@pytest.mark.parametrize("lang", LANGUAGES)
def test_mac_inside_product_never_reaches_the_explanation(tmp_path, lang):
    finding, host = outdated_on(tmp_path, f"vsftpd device {HOSTILE_MAC}", "2.3.4", hostname="")
    assert HOSTILE_MAC not in all_text(explain(finding, host, lang)).upper()


@pytest.mark.parametrize("lang", LANGUAGES)
def test_short_hostname_inside_product_is_hidden(tmp_path, lang):
    finding, host = outdated_on(tmp_path, "vsftpd on DESK-01", "2.3.4", hostname="desk-01.lan")
    text = all_text(explain(finding, host, lang))
    assert "desk-01" not in text.casefold()
    assert HIDDEN_HOSTNAME[lang] in text


@pytest.mark.parametrize("lang", LANGUAGES)
def test_full_hostname_inside_version_is_hidden_with_no_domain_left(tmp_path, lang):
    finding, host = outdated_on(tmp_path, "vsftpd", "2.3.4 desk-01.lan", hostname="desk-01.lan")
    text = all_text(explain(finding, host, lang))
    assert "desk-01" not in text.casefold()
    assert f"{HIDDEN_HOSTNAME[lang]}.lan" not in text
    assert HIDDEN_HOSTNAME[lang] in text


@pytest.mark.parametrize("lang", LANGUAGES)
def test_short_hostname_inside_a_longer_word_is_kept(tmp_path, lang):
    finding, host = outdated_on(tmp_path, "vsftpd Synology NASdrive", "2.3.4", hostname="nas.home")
    text = all_text(explain(finding, host, lang))
    assert "Synology NASdrive" in text
    assert HIDDEN_HOSTNAME[lang] not in text
