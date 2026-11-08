"""Which record of the history is the scan on screen, and which earlier one it is compared with (FR-10, FR-13).

Plain functions over load_history()'s records, with no Streamlit call, so Acasă (the report), Istoric (the banner and
the comparator) and the tests all pick the same two scans."""
from ui.view import same_network


def current_index(records, digest: str | None) -> int | None:
    """The position of the scan on screen (by its file's digest) in the history; the newest record when no scan was
    picked yet or it isn't stored (a broken file); None for an empty history."""
    if not records:
        return None
    return next((i for i, record in enumerate(records) if record.digest == digest), len(records) - 1)


def previous_index(records, index: int | None) -> int | None:
    """The newest earlier record that `same_network` accepts for records[index], or None: the history never compares
    two unrelated networks on its own (the person may still pick any scan in the comparator)."""
    if index is None:
        return None
    matches = [i for i in range(index) if same_network(records[i].result, records[index].result)]
    return matches[-1] if matches else None
