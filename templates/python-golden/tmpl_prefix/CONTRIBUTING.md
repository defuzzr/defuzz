# Contributing to the workspace

## Prerequisites

Install `uv` (the only required host tool):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Development Workflow

1. Sync the workspace environment:

   ```bash
   uv sync
   ```

2. Use `xtask` generators when adding packages or components:

   ```bash
   uv run xtask new-package <layer> <name> --description "..."
   uv run xtask new-component <package> <name> --wire \
     tmpl-prefix-server
   ```

3. Run the full quality gate before opening a pull request:

   ```bash
   uv run xtask ci
   ```

## Standards

- Follow the four-layer dependency direction
  (`foundation <= domain <= adapters <= apps`).
- Maintain 100% compliance with `ruff check .`, `ruff format --check .`,
  `mypy`, and `lint-imports`.
- Include unit or contract tests under `<package>/tests/` for all new
  behavior.
