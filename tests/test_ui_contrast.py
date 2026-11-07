"""NFR-08, WCAG AA contrast: E's FE-E2 audit (axe-core) found Streamlit's caption grey, #828180 on the light theme's
white, at 3.88:1, under the 4.5:1 that 16 px text needs. So no page draws text with st.caption: it uses st.markdown,
which has the theme's full text colour. (Shell syntax colours failed the same way: the Scanare command is plain text.)"""
from pathlib import Path

UI = Path(__file__).resolve().parents[1] / "ui"


def test_no_page_draws_text_in_streamlits_low_contrast_caption_grey():
    offenders = [f"{path.relative_to(UI.parent)}:{number}"
                 for path in sorted(UI.rglob("*.py"))
                 for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
                 if ".caption(" in line.split("#", 1)[0]]
    assert offenders == []


def test_no_code_block_gets_shell_colours():
    offenders = [f"{path.relative_to(UI.parent)}:{number}"
                 for path in sorted(UI.rglob("*.py"))
                 for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
                 if "st.code(" in line and "language=None" not in line]
    assert offenders == []
