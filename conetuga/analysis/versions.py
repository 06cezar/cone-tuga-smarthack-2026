"""Compare the versions nmap reports with the brief's outdated list, as numbers and never as text.

nmap versions look like "7.2p2", "8.4p1 Debian 5+deb11u3", "2.2.15", but also "3.X" (any 3.x) or "3.X - 4.X" (somewhere
between). A version counts as outdated only when every version it could stand for is outdated: an extra
OUTDATED_SERVICE row costs as much as a correct one, so an unsure version is never reported."""
import re
from dataclasses import dataclass

LEADING_NUMBERS = re.compile(r"^\s*(\d+(?:\.\d+)*)(\.[xX*])?")  # "7.2p2" -> "7.2"; "3.X" -> "3" plus a wildcard
RANGE_SEPARATOR = re.compile(r"\s+-\s+")  # "3.X - 4.X"; a plain "-" can be part of a version ("2.4.7-1ubuntu4")


@dataclass(frozen=True)
class Version:
    """The leading numbers of a version, and whether anything after them is unknown (a wildcard)."""

    numbers: tuple[int, ...]
    open_ended: bool  # "3.X": the parts after `numbers` could be anything


def parse_version(text: str) -> Version | None:
    """The numbers at the start of a version, or None when there are none ("", "unknown")."""
    match = LEADING_NUMBERS.match(text)
    if not match:
        return None
    return Version(tuple(int(part) for part in match.group(1).split(".")), open_ended=match.group(2) is not None)


def is_outdated_version(text: str, rule_kind: str, limit: str) -> bool:
    """True when the version `text` is outdated for one rule of the list.

    rule_kind is "equals" (exactly that version), "below" (strictly older) or "at_most" (that version line or older:
    "2.2" covers every 2.2.x). A range is outdated only if both of its ends are."""
    parts = RANGE_SEPARATOR.split(text.strip())
    versions = [parse_version(part) for part in parts]
    if not versions or any(version is None for version in versions):
        return False
    limit_numbers = parse_version(limit).numbers
    return all(_is_outdated(version, rule_kind, limit_numbers) for version in versions)


def _is_outdated(version: Version, rule_kind: str, limit: tuple[int, ...]) -> bool:
    if rule_kind == "equals":
        return not version.open_ended and _padded(version.numbers, len(limit)) == _padded(limit, len(version.numbers))
    if rule_kind == "below":
        return _surely_below(version, limit)
    if rule_kind == "at_most":
        # Compare only as many parts as the limit has: Apache 2.2.15 is (2, 2) against "2.2", so it is outdated.
        # A plain tuple compare says (2, 2, 15) > (2, 2) and misses it.
        if version.open_ended and len(version.numbers) < len(limit):
            return _surely_below(version, limit)  # "2.X" against "2.2": could be 2.4, so only if surely older
        return _padded(version.numbers, len(limit))[: len(limit)] <= limit
    raise ValueError(f"unknown outdated rule kind {rule_kind!r} in data/catalog.toml")


def _surely_below(version: Version, limit: tuple[int, ...]) -> bool:
    """Strictly older than `limit` for every version this one could stand for."""
    if not version.open_ended:
        width = max(len(version.numbers), len(limit))
        return _padded(version.numbers, width) < _padded(limit, width)
    known = len(version.numbers)  # "6.X" vs 7.4: (6,) < (7,), so surely below; "7.X" vs 7.4: could be 7.9
    return version.numbers < _padded(limit, known)[:known]


def _padded(numbers: tuple[int, ...], width: int) -> tuple[int, ...]:
    """(7,) -> (7, 0) for width 2: "7" means 7.0 when compared with 7.4."""
    return numbers + (0,) * (width - len(numbers))
