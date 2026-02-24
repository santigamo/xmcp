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
- Runtime transport should stay `streamable-http` unless a sprint explicitly
  changes protocol requirements.
- Keep local default binding as `MCP_HOST=127.0.0.1`; Docker compose is
  responsible for overriding host binding to `0.0.0.0`.
- For OpenAPI-generated tools, set safety annotations through
  `FastMCP.from_openapi(..., mcp_component_fn=...)`; the callback receives
  `(route, component)`, so use `route.method` directly instead of building a
  method lookup map.
- Test discovery is intentionally scoped to `tests/` via
  `tool.pytest.ini_options.testpaths` to avoid collecting manual example scripts.
- Keep live/manual credentialed scripts under `examples/` so `pytest` stays
  deterministic in CI.

### Shared Utilities

- Reuse `tests/conftest.py::mock_openapi_spec` for OpenAPI filtering and parameter
  normalization tests instead of duplicating mock specs.
- Keep OAuth2 helper modules under `auth/` standalone and dependency-injected
  (for example, `auth/x_oauth2.py` accepts optional `httpx.AsyncClient`) so
  they are unit-testable without network access.
- `auth/token_store.py::FileTokenStore` uses atomic tempfile+rename writes;
  preserve this behavior when changing persistence logic.
- `auth/oauth_server.py::OAuthServer` owns OAuth remote endpoints and should be
  mounted via `oauth_server.mount_routes(mcp)` only in `X_AUTH_MODE=oauth2-remote`.
- oauth2-remote request auth relies on `CURRENT_MCP_BEARER_TOKEN` propagation:
  capture the inbound MCP Authorization header once, then inject the resolved X
  access token in outbound httpx request hooks.
