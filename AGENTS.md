# AGENTS.md

Python project managed with `uv`. See `~/.config/opencode/AGENTS.md` for global rules.

## Quick start

- Initialize: `uv init` / `uv venv` / `uv sync`
- Run code: `uv run <script>` or `uv run python -m <module>`
- Add dependency: `uv add <pkg>` (prod) or `uv add --group dev <pkg>` (dev)

## Verify before committing

1. `uv run ruff check .`
2. `uv run mypy src/` (or wherever code lives)
3. `uv run pytest`
