"""The brief's outdated list, through the real catalog: versions compare as numbers, at each rule's boundary."""
import pytest

from conetuga.analysis.catalog import load_catalog
from conetuga.analysis.versions import is_outdated_version, parse_version

CATALOG = load_catalog()


@pytest.mark.parametrize("product, version", [
    ("vsftpd", "2.3.4"),
    ("OpenSSH", "7.2p2"), ("OpenSSH", "7.2p2 Ubuntu 4ubuntu2.10"), ("OpenSSH", "6.6.1p1"), ("OpenSSH", "7.3"),
    ("Apache httpd", "2.2.15"), ("Apache httpd", "2.2"), ("Apache httpd", "2.0.64"), ("Apache httpd", "1.3.42"),
    ("Microsoft IIS httpd", "7.5"), ("Microsoft IIS httpd", "7.0"), ("Microsoft IIS httpd", "6.0"),
    ("Samba smbd", "3.6.25"), ("Samba smbd", "3.0.20-Debian"), ("Samba smbd", "2.2.8a"), ("Samba smbd", "3.X"),
    ("Samba smbd", "2.X - 3.X"),
])
def test_listed_version_is_outdated(product, version):
    assert CATALOG.is_outdated(product, version)


@pytest.mark.parametrize("product, version", [
    ("vsftpd", "2.3.5"), ("vsftpd", "3.0.3"), ("vsftpd", "2.3"),
    ("OpenSSH", "7.4"), ("OpenSSH", "7.4p1"), ("OpenSSH", "7.10"), ("OpenSSH", "8.9p1"), ("OpenSSH", "7.X"),
    ("Apache httpd", "2.4.7"), ("Apache httpd", "2.3.1"), ("Apache httpd", "2.X"),
    ("Microsoft IIS httpd", "8.0"), ("Microsoft IIS httpd", "7.6"), ("Microsoft IIS httpd", "10.0"),
    ("Samba smbd", "4.15"), ("Samba smbd", "4.0.0"), ("Samba smbd", "3.X - 4.X"),
])
def test_newer_or_uncertain_version_is_not_outdated(product, version):
    assert not CATALOG.is_outdated(product, version)


@pytest.mark.parametrize("version", ["", "unknown", "p2"])
def test_version_without_numbers_is_not_outdated(version):
    assert not CATALOG.is_outdated("OpenSSH", version)


def test_product_not_on_the_list_is_not_outdated():
    assert not CATALOG.is_outdated("nginx", "1.0")


def test_product_match_ignores_case():
    assert CATALOG.is_outdated("openssh", "7.2")


def test_version_numbers_are_read_from_the_start():
    assert parse_version("8.4p1 Debian 5+deb11u3").numbers == (8, 4)


def test_unknown_rule_kind_is_refused():
    with pytest.raises(ValueError):
        is_outdated_version("1.0", "newer_than", "2.0")
