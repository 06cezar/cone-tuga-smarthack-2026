"""The Întreabă page (FE-B5): a chat about the scan picked on Acasă, answered by reply(). It names the current guide,
keeps the conversation for the session, escapes every text (the question too), and says what to do without a scan.
The page is run on its own with the scan Acasă would remember (ui/state.py), as in test_ui_devices_page.py."""
from pathlib import Path

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

ROOT = Path(__file__).resolve().parents[1]
SCANS = ROOT / "tests" / "fixtures" / "validation" / "scans"
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
