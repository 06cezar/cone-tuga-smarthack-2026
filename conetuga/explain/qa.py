"""The Q&A assistant (FR-12): answers a question about one scan using only that scan's findings, with no LLM, no network
and no key (specs/contracts.md, section answer_question).

The question only selects: it may name an IP, a port, a device type, a service or catalog code, or ask what is the most
dangerous. The answer is built from fixed phrases in data/qa.toml, explain()'s built-in text and values from the scan,
and cites every finding it relies on, e.g. [192.168.1.10:9100 PRINTER_RAW_EXPOSED]. No part of the question is ever
copied into the answer, because it is untrusted text (NFR-03, NFR-06). When the question names nothing the scan shows,
the answer says so instead of guessing.
"""
import ipaddress
import re
import tomllib
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from conetuga.explain.template import LANGUAGES, device_label, explain, fill

QA_FILE = Path(__file__).resolve().parents[2] / "data" / "qa.toml"
SOURCE_RETRIEVAL = "retrieval"  # Answer.source: built from the scan and our texts, no model involved
# A longer question is refused: a real question about a home network fits in a few lines, and the limit keeps a pasted
# wall of text (or a hostile one) out of the matcher (NFR-03).
MAX_QUESTION_CHARS = 300
# At most this many findings are spelled out in one answer, riskiest first; the UI's list shows them all.
MAX_FINDINGS_SHOWN = 3
STEM_MARK = "*"  # a word in qa.toml ending in "*" matches every word that starts with it
PORT_WORD = "port"  # a number right after a word starting with this is a port: "port 9100", "portul 9100"
PROTOCOLS = ("tcp", "udp")  # a number right before one of these is a port: "9100/tcp"
LOWEST_PORT, HIGHEST_PORT = 1, 65535

# An IPv4 address, maybe with ":port"; not glued to other digits or dots, but a sentence's final "." is fine.
IP_AND_PORT = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?(?!\d)(?!\.\d)")
WORD = re.compile(r"[a-z0-9_]+")  # after normalise(): letters without diacritics, digits and "_" (codes keep theirs)


def normalise(text: str) -> str:
    """Lower case without diacritics: "Ș", "ş" (cedilla) and "s" all become "s", "ă" and "â" become "a"."""
    decomposed = unicodedata.normalize("NFD", text.casefold())
    return "".join(char for char in decomposed if unicodedata.category(char) != "Mn")


def _phrase(words: str) -> tuple[tuple[str, bool], ...]:
    """A word or phrase from qa.toml as (word, is_stem) pairs, normalised like a question."""
    pairs = []
    for part in words.split():
        stem = part.endswith(STEM_MARK)
        tokens = WORD.findall(normalise(part.rstrip(STEM_MARK)))
        pairs += [(token, stem and i == len(tokens) - 1) for i, token in enumerate(tokens)]
    return tuple(pairs)


# Read once, at import: the file is small and never changes while the app runs.
_FILE = tomllib.loads(QA_FILE.read_text(encoding="utf-8"))
PHRASES = _FILE["phrases"]
TOP_WORDS = [_phrase(words) for words in _FILE["top"]["words"]]
DEVICE_WORDS = {device_type: [_phrase(words) for words in all_words]
                for device_type, all_words in _FILE["devices"].items()}
# Every code is also named by itself, e.g. "ssh_open".
CODE_WORDS = {code: [_phrase(words) for words in all_words] + [_phrase(code)]
              for code, all_words in _FILE["services"].items()}


@dataclass(frozen=True)
class Answer:
    text: str
    citations: list[str]
    source: str


@dataclass(frozen=True)
class Asked:
    """What a question points at, read from its words; it holds only values found in our lists or in the scan."""

    ips: set[str]
    ports: set[int]
    device_types: set[str]
    codes: set[str]
    most_dangerous: bool

    def names_something(self) -> bool:
        return bool(self.ips or self.ports or self.device_types or self.codes)


def answer_question(question: str, result, lang: str) -> Answer:
    """Answer a question about one scan, in Romanian or English, citing the findings the answer relies on.

    Raises KeyError for an unknown language, and ValueError for an empty or too long question or a result with an error.
    """
    if lang not in LANGUAGES:
        raise KeyError(lang)
    if not question.strip():
        raise ValueError("the question is empty")
    if len(question.strip()) > MAX_QUESTION_CHARS:
        raise ValueError(f"the question is longer than {MAX_QUESTION_CHARS} characters")
    if result.error:
        raise ValueError("the scan file could not be read, so there is nothing to answer from")

    asked = read_question(question, result)
    if asked.names_something():
        return _answer_about(asked, result, lang)
    if asked.most_dangerous:
        return _most_dangerous(result, lang)
    return _cannot_answer(lang)


def read_question(question: str, result) -> Asked:
    """Find the IPs, ports, device types, codes and "most dangerous" words in a question."""
    text = normalise(question)
    ips, ports = set(), set()
    for match in IP_AND_PORT.finditer(text):
        ips.add(match[1])
        if match[2] and LOWEST_PORT <= int(match[2]) <= HIGHEST_PORT:
            ports.add(int(match[2]))
    words = WORD.findall(IP_AND_PORT.sub(" ", text))
    open_ports = {port.port for host in result.hosts for port in host.ports}
    for i, word in enumerate(words):
        if word.isdigit() and LOWEST_PORT <= int(word) <= HIGHEST_PORT:
            after_port_word = i > 0 and words[i - 1].startswith(PORT_WORD)
            before_protocol = i + 1 < len(words) and words[i + 1] in PROTOCOLS
            if after_port_word or before_protocol or int(word) in open_ports:
                ports.add(int(word))
    return Asked(
        ips=ips,
        ports=ports,
        device_types={kind for kind, phrases in DEVICE_WORDS.items() if _any_in(phrases, words)},
        codes={code for code, phrases in CODE_WORDS.items() if _any_in(phrases, words)},
        most_dangerous=_any_in(TOP_WORDS, words),
    )


def _any_in(phrases, words: list[str]) -> bool:
    return any(_phrase_in(phrase, words) for phrase in phrases)


def _phrase_in(phrase, words: list[str]) -> bool:
    """True when the phrase's words appear in a row; a stem matches every word that starts with it."""
    for start in range(len(words) - len(phrase) + 1):
        if all(words[start + i].startswith(word) if stem else words[start + i] == word
               for i, (word, stem) in enumerate(phrase)):
            return True
    return False


def _answer_about(asked: Asked, result, lang: str) -> Answer:
    """The findings on what the question names, or that the scan found none there, or that the scan doesn't show it."""
    hosts = [host for host in result.hosts
             if (not asked.ips or host.ip in asked.ips)
             and (not asked.device_types or host.device_type in asked.device_types)]
    scanned_ips = {host.ip for host in result.hosts}
    if asked.ips - scanned_ips or not hosts:
        return _cannot_answer(lang)  # an address or a device the scan doesn't have: nothing to say about it
    places = [(host, number) for host in hosts for number in sorted(asked.ports)
              if number in {port.port for port in host.ports}]
    if asked.ports and not places:
        return _cannot_answer(lang)  # the scan lists open ports only, so a closed one is not something it shows

    chosen_ips = {host.ip for host in hosts}
    chosen_places = {(host.ip, number) for host, number in places}
    at_place = [finding for finding in result.findings
                if finding.ip in chosen_ips and (not asked.ports or (finding.ip, finding.port) in chosen_places)]
    of_asked_kind = [finding for finding in at_place if not asked.codes or finding.code in asked.codes]
    if of_asked_kind:
        return _found(of_asked_kind, result, lang)
    names_a_place = bool(asked.ips or asked.device_types or asked.ports)
    if at_place and names_a_place:
        # The place has findings, just not of the kind asked about: show them, never "no problem" where there is one.
        # When only a service is named there is no place, so "no problem from the catalog about this" is never false.
        return _found(at_place, result, lang)

    phrases = PHRASES[lang]
    if asked.ports:
        where = [f"{host.ip}:{number} ({device_label(host.device_type, lang)})" for host, number in places]
    elif asked.ips or asked.device_types:
        where = [f"{host.ip} ({device_label(host.device_type, lang)})" for host in hosts]
    else:
        return Answer(phrases["no_problem_topic"], [], SOURCE_RETRIEVAL)
    return Answer(fill(phrases["no_problem_at"], {"where": ", ".join(where)}), [], SOURCE_RETRIEVAL)


def _found(findings, result, lang: str) -> Answer:
    """The riskiest findings (ties: analyse_file's order), each with its title, text, first step and citation."""
    phrases = PHRASES[lang]
    hosts = {host.ip: host for host in result.hosts}
    ranked = sorted(findings, key=lambda finding: -finding.points)  # stable: equal points keep analyse_file's order
    parts, citations = [], []
    for finding in ranked[:MAX_FINDINGS_SHOWN]:
        host = hosts[finding.ip]
        explanation = explain(finding, host, lang)
        found = fill(phrases["found"], {"where": place(finding), "device": device_label(host.device_type, lang),
                                        "title": explanation.title})
        parts += [found, explanation.text, fill(phrases["first_step"], {"step": explanation.steps[0]}),
                  citation(finding)]
        citations.append(citation(finding))
    if len(ranked) > MAX_FINDINGS_SHOWN:
        parts.append(phrases["more_found"])
    return Answer(" ".join(parts), citations, SOURCE_RETRIEVAL)


def _most_dangerous(result, lang: str) -> Answer:
    """The UI's rule (ui/view.py, devices_by_risk and headline), so the page and the assistant never disagree: the
    device with the highest sum of points (ties: the lower IP as a number), then its finding with the most points
    (ties: analyse_file's order), and that finding's first step."""
    phrases = PHRASES[lang]

    def risk(host) -> int:
        return sum(finding.points for finding in result.findings if finding.ip == host.ip)

    devices = sorted(result.hosts, key=lambda host: (-risk(host), ip_order(host.ip)))
    if not devices or risk(devices[0]) == 0:
        return Answer(phrases["nothing_dangerous"], [], SOURCE_RETRIEVAL)
    top = devices[0]
    own = [finding for finding in result.findings if finding.ip == top.ip]
    finding = sorted(own, key=lambda finding: -finding.points)[0]  # stable: equal points keep analyse_file's order
    explanation = explain(finding, top, lang)
    headline = fill(phrases["most_dangerous"], {"device": device_label(top.device_type, lang), "ip": top.ip,
                                                "title": explanation.title})
    parts = [headline, explanation.text, fill(phrases["do_first"], {"step": explanation.steps[0]}), citation(finding)]
    return Answer(" ".join(parts), [citation(finding)], SOURCE_RETRIEVAL)


def _cannot_answer(lang: str) -> Answer:
    return Answer(PHRASES[lang]["cannot_answer"], [], SOURCE_RETRIEVAL)


def place(finding) -> str:
    """Where a finding is: "ip:port", or only "ip" for UNKNOWN_DEVICE, which is about a device, not a port."""
    return finding.ip if finding.port is None else f"{finding.ip}:{finding.port}"


def citation(finding) -> str:
    """The evidence an answer relies on, e.g. "[192.168.1.10:9100 PRINTER_RAW_EXPOSED]"."""
    return f"[{place(finding)} {finding.code}]"


def ip_order(ip: str) -> tuple[int, int]:
    """IPs compared as numbers, as in ui/view.py: 192.168.1.9 comes before 192.168.1.10."""
    address = ipaddress.ip_address(ip)
    return address.version, int(address)
