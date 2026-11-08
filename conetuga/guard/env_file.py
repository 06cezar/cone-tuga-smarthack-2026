"""The CONETUGA_* settings a person keeps in .env (gitignored, NFR-01): the chain's RPC URL, key and contract, written
once instead of exported in every terminal, on Linux and Windows alike. The CLI loads them into its environment; the
app's "Scanează acum" button reads the chain settings from here too, so a scan started from the page is anchored the
same way as one started from the terminal. A variable already exported wins; any other name in the file is ignored;
no value is ever printed; no package is needed."""
import os
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parents[2] / ".env"  # the repo's .env, gitignored: settings and secrets
ENV_FILE_VARIABLE = "CONETUGA_ENV_FILE"  # another file than ENV_FILE (the tests point it at a file that isn't there)
ENV_PREFIX = "CONETUGA_"  # the only names read from the file


def env_file_values() -> dict[str, str]:
    """The CONETUGA_* names and values in .env, or {} with no file. Lines look like `NAME=value`, optionally after
    `export `, with the value optionally in quotes and an optional ` # comment`; the first line for a name wins."""
    path = Path(os.environ.get(ENV_FILE_VARIABLE) or ENV_FILE)
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()  # -sig: Notepad starts the file with a BOM
    except OSError:
        return {}  # no .env: the environment alone decides
    values = {}
    for line in lines:
        name, separator, value = line.strip().removeprefix("export ").partition("=")
        name, value = name.strip(), value.strip()
        if not separator or not name.startswith(ENV_PREFIX) or name == ENV_FILE_VARIABLE:
            continue  # a blank line, a comment, or a name that isn't ours
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].rstrip()
        values.setdefault(name, value)
    return values


def load_env_file() -> None:
    """Puts the .env settings into this process's environment, under any variable already set (the CLI)."""
    for name, value in env_file_values().items():
        os.environ.setdefault(name, value)


def settings_with_env_file() -> dict[str, str]:
    """The environment as the CLI would see it after load_env_file, without changing this process's environment (the
    app): .env's values under the exported ones."""
    return {**env_file_values(), **os.environ}
