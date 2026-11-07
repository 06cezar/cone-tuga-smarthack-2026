"""The catalog and the expected results are the brief's tables, transcribed by hand: these tests catch a typo before it
costs Test Set points."""
import csv
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = tomllib.loads((ROOT / "data" / "catalog.toml").read_text(encoding="utf-8"))
VALIDATION = ROOT / "tests" / "fixtures" / "validation"
EXPECTED_FINDING_ROWS = 24  # the brief: "In total the Validation Set expects 24 finding rows"
BRIEF_CODES = {
    "TELNET_OPEN", "RDP_EXPOSED", "VNC_EXPOSED", "DB_EXPOSED", "CAMERA_STREAM_EXPOSED", "OUTDATED_SERVICE",
    "FTP_CLEARTEXT", "HTTP_ADMIN_CLEARTEXT", "SMB_EXPOSED", "MQTT_EXPOSED", "UPNP_EXPOSED", "SNMP_EXPOSED",
    "PRINTER_RAW_EXPOSED", "UNKNOWN_DEVICE", "SSH_OPEN",
}


def findings_by_code() -> dict:
    return {f["code"]: f for f in CATALOG["finding"]}


def read_csv(name: str) -> list[dict]:
    with (VALIDATION / name).open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def test_catalog_has_exactly_the_codes_of_the_brief():
    assert set(findings_by_code()) == BRIEF_CODES


def test_points_per_severity_match_the_brief():
    assert CATALOG["severity_points"] == {"high": 20, "medium": 10, "low": 5, "info": 0}


def test_every_finding_has_a_known_severity():
    assert {f["severity"] for f in CATALOG["finding"]} <= set(CATALOG["severity_points"])


def test_database_services_are_the_four_in_the_brief():
    assert sorted(findings_by_code()["DB_EXPOSED"]["services"]) == ["mongodb", "mysql", "postgresql", "redis"]


def test_upnp_and_snmp_count_only_on_udp():
    codes = findings_by_code()
    assert codes["UPNP_EXPOSED"]["protocol"] == codes["SNMP_EXPOSED"]["protocol"] == "udp"


def test_expected_rows_use_catalog_codes_and_severities():
    rows = read_csv("expected_findings.csv")
    codes = findings_by_code()
    assert len(rows) == EXPECTED_FINDING_ROWS
    assert all(row["severity"] == codes[row["finding_code"]]["severity"] for row in rows)


def test_expected_scores_follow_the_standard_formula():
    """Each Validation Set score in the brief equals 100 minus the points of its expected findings."""
    points = {f["code"]: CATALOG["severity_points"][f["severity"]] for f in CATALOG["finding"]}
    rows = read_csv("expected_findings.csv")
    for row in read_csv("expected_scores.csv"):
        if row["network_score"] == "ERROR":
            continue
        lost = sum(points[r["finding_code"]] for r in rows if r["file"] == row["file"])
        assert int(row["network_score"]) == max(0, CATALOG["score"]["start"] - lost), row["file"]
