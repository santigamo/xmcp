## Architecture

- `server.py` is the runtime entrypoint and exports pure helpers (`filter_openapi_spec`,
  `should_exclude_operation`, `collect_comma_params`, `parse_csv_env`) that should
  be unit tested directly.

## Project Learnings

### Key Conventions

- Packaging/tooling is managed in `pyproject.toml`; keep `requirements.txt` as a
  thin wrapper (`-e ".[dev]"`) for compatibility.
- Use `uv` for environment and dependency workflows (`uv venv`, `uv pip install`,
  `uv run`) instead of raw `pip`/`venv` where possible.
- Standard local/runtime Python version is `3.13` (currently `3.13.12`).
- Test discovery is intentionally scoped to `tests/` via
  `tool.pytest.ini_options.testpaths` to avoid collecting manual example scripts.
- Keep live/manual credentialed scripts under `examples/` so `pytest` stays
  deterministic in CI.

### Shared Utilities

- Reuse `tests/conftest.py::mock_openapi_spec` for OpenAPI filtering and parameter
  normalization tests instead of duplicating mock specs.
