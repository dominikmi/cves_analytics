#!/usr/bin/env python3
"""Render ``config.yaml`` from ``.env`` and ``config/config.yaml.tmpl``.

Secrets and environment-specific values live in ``.env`` (gitignored).
This script substitutes ``${VAR}`` / ``${VAR:-default}`` placeholders and
writes ``config.yaml`` with mode 0600 — the file is mounted read-only
into the api container by docker/podman compose.

Stdlib-only so it runs on a bare host: ``python3 scripts/render_config.py``.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"
TEMPLATE_FILE = ROOT / "config" / "config.yaml.tmpl"
OUTPUT_FILE = ROOT / "config.yaml"

_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def load_dotenv(path: Path) -> dict[str, str]:
    """Parse a .env file into a dict. Ignores comments and blank lines."""
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def render(template: str, env: dict[str, str]) -> tuple[str, list[str]]:
    """Substitute placeholders; return (rendered text, unresolved vars)."""
    unresolved: list[str] = []

    def resolve(match: re.Match[str]) -> str:
        var, default = match.group(1), match.group(2)
        value = env.get(var, os.environ.get(var, default))
        if value is None:
            unresolved.append(var)
            return ""
        return value

    return _PLACEHOLDER.sub(resolve, template), unresolved


def main() -> int:
    env = load_dotenv(ENV_FILE)
    if not ENV_FILE.exists():
        print(
            f"warning: {ENV_FILE.name} not found — "
            "using process environment and template defaults only",
            file=sys.stderr,
        )

    rendered, unresolved = render(TEMPLATE_FILE.read_text(encoding="utf-8"), env)

    OUTPUT_FILE.write_text(rendered, encoding="utf-8")
    OUTPUT_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600 — contains secrets

    print(f"wrote {OUTPUT_FILE}")
    if unresolved:
        print(
            "unset variables (rendered empty): " + ", ".join(sorted(set(unresolved))),
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
