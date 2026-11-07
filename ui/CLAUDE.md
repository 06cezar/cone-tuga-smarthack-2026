# Rules for ui (stream D: the Streamlit app)

- The first screen answers "Which device is the most dangerous, and what should I do first?". A jury member must find
  it without help: that check is 20% of the grade.
- The top of the page says, in large text, "Cel mai periculos: <device>. Fă asta întâi: <step>" (and the English
  version); devices are sorted by risk; the score is a traffic light plus the number plus a sentence.
- It shows the standard score (our own score may sit beside it, clearly labelled), the devices with masked MACs, the
  findings with their explanation and fixes, and the history with before/after and the score trend.
- All user-facing text exists in Romanian and English, with a language switch.
- Accessibility (NFR-08): text of at least 16 px, colour never the only signal (icon + label), keyboard navigable,
  WCAG AA contrast.
- Banners, page titles and hostnames are escaped before display.
- The UI only calls the functions in `specs/contracts.md`; it never computes findings or scores itself.
