"""Simple mode (Tuga) for a 12-year-old or a grandparent (NFR-09): a card counts problems in words and gives at most
SIMPLE_STEPS steps. Advanced mode (Cone) still lists every device with its points. Acasă's checkup is in
tests/test_ui_checkup.py."""
from pathlib import Path

import pytest

from ui.cards import SIMPLE_STEPS, problem_count

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = str(Path(__file__).resolve().parents[1] / "ui" / "app.py")
TIMEOUT_SECONDS = 30  # a cold Streamlit import on a CI runner can take several seconds


@pytest.fixture(autouse=True)
def history_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("CONETUGA_HISTORY_DIR", str(tmp_path / "history"))


def run(advanced: bool = False):
    app = AppTest.from_file(APP, default_timeout=TIMEOUT_SECONDS).run()
    app.selectbox[0].set_value("V2_smart_home.xml").run()
    if advanced:
        app.toggle[0].set_value(True).run()
    assert not app.exception
    return app


def test_problems_are_counted_in_words():
    assert [problem_count(n, "ro") for n in (0, 1, 3)] == ["nicio problemă", "1 problemă", "3 probleme"]
    assert [problem_count(n, "en") for n in (0, 1, 3)] == ["no problems", "1 problem", "3 problems"]


def test_advanced_acasa_lists_every_device_with_its_points():
    labels = [section.label for section in run(advanced=True).expander]
    assert all("puncte" in label for label in labels)


def test_simple_cards_give_at_most_a_few_steps():
    app = run()
    step_lists = [m.value for m in app.markdown if m.value.startswith("**Ce să faci:**")]
    assert step_lists and all(len(block.splitlines()) - 1 <= SIMPLE_STEPS for block in step_lists)
