"""The optional local model behind reply() (specs/contracts.md, section reply, "Optional local model"): off unless
CONETUGA_LLM_MODEL names a model; it only rephrases an answer that cites findings, from those findings and our own
text; every answer it gives is checked against that evidence (NFR-06), and whatever goes wrong, the retrieval answer
stays. The model is always a fake here: no test needs Ollama or the network."""
import io
import json
import re
import urllib.error
from pathlib import Path

import pytest

from conetuga.analysis import analyse_file
from conetuga.explain import answer_question, reply
from conetuga.explain import llm
from conetuga.explain.llm import (LLM_ATTEMPTS, LLM_CACHE_SIZE, LLM_TIMEOUT_SECONDS, MAX_LLM_CHARS, MODEL_VARIABLE,
                                  OLLAMA_URL, ModelUnavailable, check)

ROOT = Path(__file__).resolve().parents[1]
SCANS = ROOT / "tests" / "fixtures" / "validation" / "scans"
MODEL = "test-model"
CITATION = re.compile(r"\[[^\]\n]+\]")
PRINTER_QUESTION = "Is my printer's port 9100 dangerous?"  # V3: PRINTER_RAW_EXPOSED on 192.168.1.10:9100
PRINTER = "[192.168.1.10:9100 PRINTER_RAW_EXPOSED]"


def scan(name: str):
    return analyse_file(SCANS / name)


def user(text: str) -> dict:
    return {"role": "user", "text": text}


def given_citations(prompt: str) -> str:
    """The citations the prompt hands the model, once each, in order."""
    return " ".join(dict.fromkeys(CITATION.findall(prompt)))


def good(prompt: str) -> str:
    return f"Anyone on your network can send jobs to this printer. Turn off direct printing. {given_citations(prompt)}"


class FakeModel:
    """Stands in for llm.chat: answers from a list (the last one repeats) and records every call."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, model: str, system: str, prompt: str, timeout: float) -> str:
        self.calls.append({"model": model, "system": system, "prompt": prompt, "timeout": timeout})
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, Exception):
            raise answer
        return answer(prompt) if callable(answer) else answer

    def sent(self) -> str:
        return "\n".join(call["system"] + "\n" + call["prompt"] for call in self.calls)


@pytest.fixture(autouse=True)
def empty_cache():
    llm.clear_cache()
    yield
    llm.clear_cache()


@pytest.fixture
def model_on(monkeypatch):
    monkeypatch.setenv(MODEL_VARIABLE, MODEL)


def use(monkeypatch, fake: FakeModel) -> FakeModel:
    monkeypatch.setattr(llm, "chat", fake)
    return fake


def test_the_contract_constants():
    assert OLLAMA_URL == "http://127.0.0.1:11434/api/chat"  # fixed, on this computer only
    assert (LLM_TIMEOUT_SECONDS, LLM_ATTEMPTS, MAX_LLM_CHARS, LLM_CACHE_SIZE) == (10, 2, 800, 128)
    assert MODEL_VARIABLE == "CONETUGA_LLM_MODEL"


def test_off_by_default_the_model_is_never_called(monkeypatch):
    fake = use(monkeypatch, FakeModel(good))
    result = scan("V3_small_office.xml")
    assert reply([user(PRINTER_QUESTION)], result, "en", "simple") == answer_question(PRINTER_QUESTION, result, "en")
    assert fake.calls == []


@pytest.mark.parametrize("value", ["", "   "])
def test_an_empty_model_name_means_off(monkeypatch, value):
    monkeypatch.setenv(MODEL_VARIABLE, value)
    fake = use(monkeypatch, FakeModel(good))
    assert reply([user(PRINTER_QUESTION)], scan("V3_small_office.xml"), "en", "simple").source == "retrieval"
    assert fake.calls == []


def test_an_accepted_answer_is_the_models_with_the_same_citations(monkeypatch, model_on):
    fake = use(monkeypatch, FakeModel(good))
    result = scan("V3_small_office.xml")
    retrieval = answer_question(PRINTER_QUESTION, result, "en")

    answer = reply([user(PRINTER_QUESTION)], result, "en", "simple")

    assert answer.source == "llm"
    assert answer.citations == retrieval.citations == [PRINTER]
    assert answer.text.startswith("Anyone on your network") and PRINTER in answer.text
    assert len(fake.calls) == 1
    assert fake.calls[0]["model"] == MODEL and fake.calls[0]["timeout"] == LLM_TIMEOUT_SECONDS


REJECTED = {
    "an IP not in the evidence": "The printer at 10.9.9.9 is open to everyone. {c}",
    "a number not in the evidence": "Close port 8080 on the printer. {c}",
    "a CVE": "The printer has CVE-2017-0144. {c}",
    "a citation it wasn't given": "Telnet is open too. [192.168.1.10:9100 TELNET_OPEN] {c}",
    "no citation": "Anyone on your network can send jobs to this printer.",
    "safe": "Your printer is safe once you turn it off. {c}",
    "secure": "The printer is secure now. {c}",
    "sigur": "Imprimanta e sigură acum. {c}",
    "în siguranță": "Imprimanta e în siguranță. {c}",
    "HTML": "<b>Anyone</b> can print on it. {c}",
    "a link": "Read [this guide](http://evil.example) first. {c}",
    "too long": "Anyone can print on it. " * 40 + "{c}",
}


@pytest.mark.parametrize("bad", REJECTED.values(), ids=REJECTED.keys())
def test_a_rejected_answer_is_retried_once_then_the_retrieval_answer_stays(monkeypatch, model_on, bad):
    fake = use(monkeypatch, FakeModel(lambda prompt: bad.format(c=given_citations(prompt))))
    result = scan("V3_small_office.xml")

    answer = reply([user(PRINTER_QUESTION)], result, "en", "simple")

    assert answer == answer_question(PRINTER_QUESTION, result, "en")
    assert len(fake.calls) == LLM_ATTEMPTS


def test_a_second_attempt_can_be_accepted(monkeypatch, model_on):
    fake = use(monkeypatch, FakeModel("Close port 8080.", good))
    answer = reply([user(PRINTER_QUESTION)], scan("V3_small_office.xml"), "en", "simple")
    assert answer.source == "llm"
    assert len(fake.calls) == 2


@pytest.mark.parametrize("failure", [ModelUnavailable("timed out"), ModelUnavailable("connection refused")],
                         ids=["timeout", "connection error"])
def test_a_model_that_doesnt_answer_is_called_once(monkeypatch, model_on, failure):
    fake = use(monkeypatch, FakeModel(failure, good))
    result = scan("V3_small_office.xml")
    assert reply([user(PRINTER_QUESTION)], result, "en", "simple") == answer_question(PRINTER_QUESTION, result, "en")
    assert len(fake.calls) == 1


def test_an_accepted_answer_is_cached(monkeypatch, model_on):
    fake = use(monkeypatch, FakeModel(good))
    result = scan("V3_small_office.xml")
    first = reply([user(PRINTER_QUESTION)], result, "en", "simple")
    again = reply([user(PRINTER_QUESTION)], result, "en", "simple")
    assert first == again and first.source == "llm"
    assert len(fake.calls) == 1


def test_a_failure_is_cached_too_so_a_page_rerun_doesnt_wait_again(monkeypatch, model_on):
    fake = use(monkeypatch, FakeModel(ModelUnavailable("timed out")))
    result = scan("V3_small_office.xml")
    reply([user(PRINTER_QUESTION)], result, "en", "simple")
    reply([user(PRINTER_QUESTION)], result, "en", "simple")
    assert len(fake.calls) == 1


def test_language_and_mode_are_cached_apart(monkeypatch, model_on):
    fake = use(monkeypatch, FakeModel(good))
    result = scan("V3_small_office.xml")
    for lang, mode in [("en", "simple"), ("en", "advanced"), ("ro", "simple")]:
        reply([user(PRINTER_QUESTION)], result, lang, mode)
    assert len(fake.calls) == 3


def test_the_cache_keeps_at_most_its_size(monkeypatch, model_on):
    use(monkeypatch, FakeModel(good))
    for number in range(LLM_CACHE_SIZE + 5):
        llm.remember(("key", number), None)
    assert llm.cache_size() == LLM_CACHE_SIZE


def test_the_mode_sets_the_guides_tone(monkeypatch, model_on):
    fake = use(monkeypatch, FakeModel(good))
    result = scan("V3_small_office.xml")
    reply([user(PRINTER_QUESTION)], result, "en", "simple")
    reply([user(PRINTER_QUESTION)], result, "en", "advanced")
    simple, advanced = fake.calls[0]["system"], fake.calls[1]["system"]
    assert simple != advanced
    assert "Tuga" in simple and "Cone" in advanced


def test_the_answer_language_is_asked_for(monkeypatch, model_on):
    fake = use(monkeypatch, FakeModel(good))
    reply([user("E periculos portul 9100 al imprimantei?")], scan("V3_small_office.xml"), "ro", "simple")
    assert "Romanian" in fake.calls[0]["system"]


def test_the_model_gets_only_the_cited_findings_and_our_text(monkeypatch, model_on):
    fake = use(monkeypatch, FakeModel(good))
    result = scan("V1_home_basic.xml")  # router.lan, page title "Router Login", real MAC addresses
    router = next(host for host in result.hosts if host.hostname == "router.lan")
    earlier = "my neighbour's wifi is called zebra-crossing-42"
    question = "Is the admin page of the router encrypted? purple elephant"
    messages = [user(earlier), {"role": "assistant", "text": "Scanul nu arată asta."}, user(question)]

    answer = reply(messages, result, "en", "advanced")

    assert answer.source == "llm"
    sent = fake.sent()
    assert "purple" not in sent and "elephant" not in sent  # never the question
    assert "zebra" not in sent  # never an earlier message
    assert "router.lan" not in sent  # never a hostname
    assert "Router Login" not in sent  # never a page title
    for host in result.hosts:
        assert host.mac_masked[:8] not in sent  # never a MAC address, not even its maker part
    assert router.ip in sent and "HTTP_ADMIN_CLEARTEXT" in sent  # the cited finding is there
    assert "<evidence>" in sent


@pytest.mark.parametrize("question, lang, name", [
    ("Is WPS turned on?", "en", "V3_small_office.xml"),  # the cannot-answer sentence
    ("Is port 631 on the printer dangerous?", "en", "V3_small_office.xml"),  # no catalog problem at …
    ("Ce repar întâi?", "ro", "V3_small_office.xml"),  # the most dangerous
    ("What should I fix first?", "en", "V6a_before.xml"),  # the most dangerous
    ("What should I fix first?", "en", "V6b_after.xml"),  # nothing dangerous
])
def test_fixed_answers_and_the_most_dangerous_never_go_to_the_model(monkeypatch, model_on, question, lang, name):
    fake = use(monkeypatch, FakeModel(good))
    result = scan(name)
    assert reply([user(question)], result, lang, "simple") == answer_question(question, result, lang)
    assert fake.calls == []


EVIDENCE = ("<evidence>\n[192.168.1.10:9100 PRINTER_RAW_EXPOSED] severity: medium\n"
            "Explanation: The printer at 192.168.1.10 accepts print jobs on port 9100.\n</evidence>")


def test_check_accepts_what_the_evidence_holds():
    text = ("1. The printer at 192.168.1.10 prints anything sent to port 9100. 2. Turn that off. "
            "[192.168.1.10:9100 PRINTER_RAW_EXPOSED]")
    assert check(text, EVIDENCE, [PRINTER]) == []


@pytest.mark.parametrize("text, problem", [
    ("At 192.168.1.1 too. " + PRINTER, "IP"),
    ("Port 9101 as well. " + PRINTER, "number"),
    ("See CVE-2017-0144. " + PRINTER, "CVE"),
    ("Turn it off.", "citation"),
    ("Also [192.168.1.10:9100 SNMP_EXPOSED]. " + PRINTER, "citation"),
    ("It's safe. " + PRINTER, "safe"),
    ("<i>Off</i> " + PRINTER, "HTML"),
    ("[guide](http://x.example) " + PRINTER, "link"),
    ("x" * (MAX_LLM_CHARS + 1) + PRINTER, "long"),
])
def test_check_names_each_problem(text, problem):
    problems = check(text, EVIDENCE, [PRINTER])
    assert any(problem in found for found in problems), problems


def test_check_needs_every_citation_it_was_given():
    other = "[192.168.1.20:23 TELNET_OPEN]"
    assert check("Turn it off. " + PRINTER, EVIDENCE + other, [PRINTER, other])


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_chat_posts_to_the_local_address_without_a_proxy(monkeypatch):
    seen = {}

    def fake_open(request, timeout):
        seen["url"], seen["timeout"] = request.full_url, timeout
        seen["body"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse(json.dumps({"message": {"content": " hello "}}).encode("utf-8"))

    monkeypatch.setattr(llm.OPENER, "open", fake_open)
    assert llm.chat(MODEL, "system text", "prompt text", LLM_TIMEOUT_SECONDS) == "hello"
    assert seen["url"] == OLLAMA_URL and seen["timeout"] == LLM_TIMEOUT_SECONDS
    assert seen["body"]["model"] == MODEL and seen["body"]["stream"] is False
    assert [m["content"] for m in seen["body"]["messages"]] == ["system text", "prompt text"]
    assert not any(handler.__class__.__name__ == "ProxyHandler" and handler.proxies
                   for handler in llm.OPENER.handlers)


@pytest.mark.parametrize("failure", [urllib.error.URLError("refused"), TimeoutError("timed out"),
                                     ConnectionResetError("reset")], ids=["refused", "timeout", "reset"])
def test_chat_turns_a_network_failure_into_model_unavailable(monkeypatch, failure):
    def fake_open(request, timeout):
        raise failure

    monkeypatch.setattr(llm.OPENER, "open", fake_open)
    with pytest.raises(ModelUnavailable):
        llm.chat(MODEL, "s", "p", LLM_TIMEOUT_SECONDS)


@pytest.mark.parametrize("body", [b"not json", b"{}", b'{"message": {}}'])
def test_chat_turns_a_strange_reply_into_model_unavailable(monkeypatch, body):
    monkeypatch.setattr(llm.OPENER, "open", lambda request, timeout: FakeResponse(body))
    with pytest.raises(ModelUnavailable):
        llm.chat(MODEL, "s", "p", LLM_TIMEOUT_SECONDS)
