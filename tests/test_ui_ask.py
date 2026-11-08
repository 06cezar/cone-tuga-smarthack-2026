"""The Întreabă page (FE-B5): a chat about the scan picked on Acasă, answered by reply(). It names the current guide,
keeps the conversation for the session, escapes every text (the question too), and says what to do without a scan.
The page is run on its own with the scan Acasă would remember (ui/state.py), as in test_ui_devices_page.py."""
from pathlib import Path

import pytest

from ui.view import md

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

ROOT = Path(__file__).resolve().parents[1]
SCANS = ROOT / "tests" / "fixtures" / "validation" / "scans"
V2 = SCANS / "V2_smart_home.xml"
V3 = SCANS / "V3_small_office.xml"
V7 = SCANS / "V7_broken.xml"
PRINTER = "[192.168.1.10:9100 PRINTER_RAW_EXPOSED]"
QUESTION = {"Română": "E periculos portul 9100 al imprimantei?", "English": "Is my printer's port 9100 dangerous?"}
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds


def show(scan: Path | None, language: str = "Română", advanced: bool = False) -> AppTest:
    script = (f"import streamlit as st\nst.session_state['language_choice'] = {language!r}\n"
              f"st.session_state['advanced_mode'] = {advanced!r}\n")
    if scan is not None:
        script += ("from pathlib import Path\nfrom conetuga.analysis import analyse_file\n"
                   f"from ui.state import remember_scan\nremember_scan(analyse_file(Path({str(scan)!r})))\n")
    script += "from ui.pages import ask\nask.render()"
    app = AppTest.from_string(script, default_timeout=TIMEOUT_SECONDS).run()
    assert not app.exception
    return app


def ask(app: AppTest, question: str) -> AppTest:
    app.chat_input[0].set_value(question).run()
    assert not app.exception
    return app


def chat_text(app: AppTest) -> list[str]:
    return [element.value for message in app.chat_message for element in message.markdown]


def unescaped(text: str) -> str:
    """The text as a reader sees it: md() puts a backslash before every Markdown character."""
    return text.replace("\\", "")


@pytest.mark.parametrize("language, words", [("Română", "pagina Acasă"), ("English", "the Home page")])
def test_without_a_scan_the_page_says_where_to_pick_one(language, words):
    app = show(None, language)
    assert words in app.info[0].value
    assert not app.chat_input


@pytest.mark.parametrize("language, words", [("Română", "nu poate fi citit"), ("English", "can't be read")])
def test_a_broken_scan_shows_an_error_and_no_chat(language, words):
    app = show(V7, language)
    assert words in app.error[0].value
    assert not app.chat_input


@pytest.mark.parametrize("advanced, guide", [(False, "Tuga"), (True, "Cone")])
@pytest.mark.parametrize("language", ["Română", "English"])
def test_a_question_gets_an_answer_with_its_citation(language, advanced, guide):
    app = ask(show(V3, language, advanced), QUESTION[language])
    assert guide in "\n".join(m.value for m in app.markdown)
    messages = chat_text(app)
    assert len(app.chat_message) == 2
    assert app.chat_message[0].name == "user" and app.chat_message[1].name == "assistant"
    assert PRINTER in unescaped(messages[1])


def test_the_conversation_is_kept_for_the_session():
    app = ask(ask(show(V3), QUESTION["Română"]), "Ce repar întâi?")
    assert len(app.chat_message) == 4
    app.run()  # a rerun with no new question still shows the whole conversation
    assert len(app.chat_message) == 4


def test_a_hostile_question_is_shown_escaped():
    app = ask(show(V3, "English"), "<script>alert(1)</script> [x](http://evil.example) port 9100")
    question = chat_text(app)[0]
    assert "<script>" not in question and "](" not in question
    assert "\\<script\\>" in question


def test_the_box_keeps_a_question_within_the_limit():
    app = ask(show(V3, "English"), "port 9100 " * 40)  # 400 characters typed
    assert len(unescaped(chat_text(app)[0])) <= 300  # reply() would refuse a longer one
    assert PRINTER in unescaped(chat_text(app)[1])


def test_clearing_empties_the_conversation():
    app = ask(show(V3), QUESTION["Română"])
    app.button[0].click().run()
    assert not app.exception
    assert not app.chat_message


def test_an_answer_rephrased_by_the_local_model_says_so(monkeypatch):
    from conetuga.explain import llm

    llm.clear_cache()
    monkeypatch.setenv(llm.MODEL_VARIABLE, "test-model")
    monkeypatch.setattr(llm, "chat", lambda model, system, prompt, timeout: (
        "Anyone on your network can print on it. [192.168.1.10:9100 PRINTER_RAW_EXPOSED]"))
    try:
        app = ask(show(V3, "English"), QUESTION["English"])
    finally:
        llm.clear_cache()
    answer = chat_text(app)[1:]
    assert unescaped(answer[0]).startswith("Anyone on your network")
    assert "Rephrased by a local model" in answer[1]


def test_without_the_model_the_answer_says_it_comes_from_the_scan():
    answer = chat_text(ask(show(V3, "English"), QUESTION["English"]))[1:]
    assert "comes only from this scan" in answer[1]


def page_text(app: AppTest) -> list[str]:
    return [element.value for element in app.markdown]


@pytest.mark.parametrize("language, words", [("Română", "🤖 Model local: oprit."), ("English", "🤖 Local model: off.")])
def test_without_the_model_the_page_says_it_is_off(language, words):
    assert any(text.startswith(words) for text in page_text(show(V3, language)))


@pytest.mark.parametrize("language, words", [("Română", "Model local: activat (qwen2.5:7b)"),
                                             ("English", "Local model: on (qwen2.5:7b)")])
def test_with_the_model_set_the_page_says_it_is_on_and_names_it(monkeypatch, language, words):
    from conetuga.explain import llm

    monkeypatch.setenv(llm.MODEL_VARIABLE, "qwen2.5:7b")
    status = [text for text in page_text(show(V3, language)) if text.startswith("🤖")]
    assert len(status) == 1 and words in unescaped(status[0])


@pytest.mark.parametrize("language", ["Română", "English"])
def test_a_hostile_model_name_is_shown_escaped(monkeypatch, language):
    from conetuga.explain import llm

    monkeypatch.setenv(llm.MODEL_VARIABLE, "<script>x</script>")
    status = [text for text in page_text(show(V3, language)) if text.startswith("🤖")][0]
    assert "<script>" not in status
    assert "\\<script\\>x\\</script\\>" in status


@pytest.mark.parametrize("language", ["Română", "English"])
def test_showing_the_page_never_contacts_the_model(monkeypatch, language):
    from conetuga.explain import llm

    def no_network(*args, **kwargs):
        raise AssertionError("the page contacted the local model on load")

    monkeypatch.setenv(llm.MODEL_VARIABLE, "qwen2.5:7b")
    monkeypatch.setattr(llm, "chat", no_network)
    app = show(V3, language)  # show() asserts the page raised nothing
    assert any(text.startswith("🤖") for text in page_text(app))


# --- the overview on the page: one line per problem, each escaped --------------------------------------------------

def answer_lines(app: AppTest) -> list[str]:
    """The assistant's answer as shown: its lines, which the page joins with Markdown's "  \n" line break."""
    return chat_text(app)[1].split("  \n")


def test_the_overview_shows_one_line_per_problem():
    lines = answer_lines(ask(show(V2), "ce probleme am?"))
    assert len(lines) == 6
    assert unescaped(lines[0]) == "Problemele găsite de scan, în ordinea în care le repari:"
    assert [unescaped(line)[:3] for line in lines[1:]] == ["1. ", "2. ", "3. ", "4. ", "5. "]
    assert unescaped(lines[1]).endswith("[192.168.1.40:554 CAMERA_STREAM_EXPOSED]")


def test_a_hostile_hostname_stays_escaped_on_every_line(tmp_path):
    from nmap_xml import host, port, write_scan

    hostile = "evil\n2. [x](http://y.z) *fake* <b>"
    path = write_scan(tmp_path, host("10.0.0.5", port(23, "telnet"), hostname=hostile),
                      host("10.0.0.6", port(21, "ftp"), hostname="ok"))
    lines = answer_lines(ask(show(path, "English"), "what problems do I have?"))
    assert len(lines) == 3  # the first line and two problems: the hostname's line break adds none
    for line in lines:
        assert line == md(unescaped(line))  # every Markdown character on the line is escaped
    assert "evil 2. [x](http://y.z) *fake* <b>" in unescaped(" ".join(lines))


def test_a_one_paragraph_answer_shows_as_before():
    from conetuga.analysis import analyse_file
    from conetuga.explain import answer_question

    app = ask(show(V3, "English"), QUESTION["English"])
    expected = answer_question(QUESTION["English"], analyse_file(V3), "en").text
    assert chat_text(app)[1] == md(expected)
