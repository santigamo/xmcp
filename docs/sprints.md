# xmcp — Sprint Plan

> **Note on `oauth2-local` mode**: The original plan describes three auth modes (`oauth1`, `oauth2-local`, `oauth2-remote`). This sprint plan intentionally drops `oauth2-local` to keep scope minimal. It can be added later if needed. The two supported modes are `oauth1` (existing behavior) and `oauth2-remote` (Claude.ai connector).

---

## Sprint 0: Project Foundation & Dev Tooling

**Goal**: Modern Python project structure, dev tooling, and the ability to run tests. No functional changes to the server — just the scaffolding everything else builds on.

**Demo**: `pip install -e ".[dev]" && pytest && ruff check .` all pass. Server still works as before.

### Tickets

#### S0-1: Create `pyproject.toml` with project metadata and dependencies

Move dependency declarations from `requirements.txt` into a proper `pyproject.toml`. Keep `requirements.txt` as a thin wrapper for backwards compat.

**Changes**:
- Create `pyproject.toml` with `[project]` section:
  - `name = "xmcp"`, `version = "0.1.0"`, `requires-python = ">=3.12"`
  - Core deps: `fastmcp>=2.5.0,<3.0`, `httpx`, `python-dotenv`, `requests-oauthlib`
  - Optional `[dev]` deps: `pytest`, `pytest-asyncio`, `pytest-httpx`, `ruff`
  - Optional `[grok]` deps: `xai-sdk`, `xdk` (moved from core — only needed by test client)
- `[tool.pytest.ini_options]` with `asyncio_mode = "auto"`
- `[tool.ruff]` with `line-length = 100`
- Update `requirements.txt` to just `-e ".[dev]"`
- Add `.tokens.json` to `.gitignore` (will be used by FileTokenStore in S3)

**Validation**: `pip install -e ".[dev]"` succeeds. `python -c "import fastmcp; import httpx"` works. `ruff check .` runs (may have findings — that's fine).

#### S0-2: Create `tests/` directory with `conftest.py` and a minimal smoke test

Set up the test infrastructure and prove it works with a trivial test.

**Changes**:
- Create `tests/__init__.py` (empty)
- Create `tests/conftest.py` with a comprehensive mock OpenAPI spec fixture containing:
  - A GET endpoint with `operationId` and tags
  - A POST endpoint with `operationId`
  - A DELETE endpoint with `operationId`
  - A streaming endpoint (path containing `/stream`)
  - A webhook endpoint (path containing `/webhooks`)
  - An endpoint with `x-twitter-streaming: true`
  - Parameters with `explode: false` and `type: array` in both `components.parameters` and inline
- Create `tests/test_smoke.py` with one test: `test_import_server` that imports `server` and asserts it exports `create_mcp`, `filter_openapi_spec`, `should_exclude_operation`, `collect_comma_params`, `parse_csv_env`.
- Move `test_grok_mcp.py` to `examples/test_grok_mcp.py` (it requires live credentials and shouldn't run in CI)

**Validation**: `pytest tests/test_smoke.py -v` passes.

#### S0-3: Add unit tests for `filter_openapi_spec()` and `should_exclude_operation()`

These are pure functions with no side effects — ideal first test targets. Use `monkeypatch.setenv` for all env-dependent tests to prevent test pollution.

**Changes**:
- Create `tests/test_filter_spec.py`
- Tests:
  - `test_excludes_streaming_path` — path containing `/stream` is excluded
  - `test_excludes_webhook_path` — path containing `/webhooks` is excluded
  - `test_excludes_streaming_tag` — operation tagged `stream` is excluded
  - `test_excludes_twitter_streaming_flag` — operation with `x-twitter-streaming: true` excluded
  - `test_keeps_normal_endpoint` — standard GET endpoint is kept
  - `test_allowlist_filters_operations` — `monkeypatch.setenv("X_API_TOOL_ALLOWLIST", ...)`, only allowlisted operation IDs remain
  - `test_denylist_removes_operations` — `monkeypatch.setenv("X_API_TOOL_DENYLIST", ...)`, denylisted operation IDs are removed
  - `test_tag_filter` — `monkeypatch.setenv("X_API_TOOL_TAGS", ...)`, only operations with matching tags remain
  - `test_empty_paths_removed` — paths with no remaining operations are pruned from output

**Validation**: `pytest tests/test_filter_spec.py -v` — all pass.

#### S0-4: Add unit tests for `collect_comma_params()` and `parse_csv_env()`

Test the query parameter normalization helpers.

**Changes**:
- Create `tests/test_comma_params.py`
- Tests:
  - `test_collect_comma_params_from_components` — finds params in `components.parameters`
  - `test_collect_comma_params_from_operations` — finds params inline in operations
  - `test_should_join_query_param_true` — array + query + explode:false → True
  - `test_should_join_query_param_false_not_array` — string param → False
  - `test_should_join_query_param_false_not_query` — path param → False
  - `test_parse_csv_env_basic` — `"a,b,c"` → `{"a","b","c"}`
  - `test_parse_csv_env_whitespace` — `" a , b "` → `{"a","b"}`
  - `test_parse_csv_env_empty` — unset env var → empty set

**Validation**: `pytest tests/test_comma_params.py -v` — all pass.

#### S0-5: Add `.github/workflows/ci.yml` for linting and testing

**Changes**:
- Create `.github/workflows/ci.yml`:
  - Trigger on `push` and `pull_request`
  - Job `test` on `ubuntu-latest`
  - Steps: checkout, setup-python 3.12, `pip install -e ".[dev]"`, `ruff check .`, `pytest`

**Validation**: Run `ruff check . && pytest` locally and confirm both pass. CI will be validated on first push.

---

## Sprint 1: Docker + Streamable HTTP Transport

**Goal**: The server runs inside a Docker container with the modern `streamable-http` transport. Local (non-Docker) mode still works.

**Demo**: `docker compose up --build` starts the server. `curl http://localhost:8000/mcp` returns a valid MCP response (or appropriate error for non-MCP request).

### Tickets

#### S1-1: Change transport from `http` to `streamable-http`

**Changes**:
- In `server.py` `main()`: change `transport="http"` → `transport="streamable-http"`

**⚠️ Risk**: Verify `streamable-http` is a valid transport value for the installed FastMCP version. If invalid, the correct value may be different (e.g., `sse` or just `http` with Streamable HTTP being the default). Check FastMCP source or test with `mcp.run(transport='streamable-http')` before committing.

**Validation**: Start server locally (`python server.py` with valid creds or mocked). Confirm it starts without `ValueError`. If possible, test with MCP Inspector.

#### S1-2: Configure Docker-friendly host binding

Keep default host as `127.0.0.1` (safe for local users). Docker compose sets `0.0.0.0` explicitly.

**Changes**:
- No change to default host in `server.py` (keep `127.0.0.1`)
- In `docker-compose.yml` (S1-4): set `MCP_HOST=0.0.0.0` via `environment`
- Document in `env.example`: comment explaining `MCP_HOST=0.0.0.0` is needed for Docker

**Validation**: Manual review — default is still `127.0.0.1` for local. Docker compose overrides to `0.0.0.0`.

#### S1-3: Create `Dockerfile`

**Changes**:
- Create `Dockerfile`:
  ```dockerfile
  FROM python:3.12-slim
  WORKDIR /app
  COPY . .
  RUN pip install --no-cache-dir .
  EXPOSE 8000
  CMD ["python", "server.py"]
  ```

**Validation**: `docker build -t xmcp .` succeeds without errors. Image size is reasonable (<200MB).

#### S1-4: Create `docker-compose.yml`

**Changes**:
- Create `docker-compose.yml`:
  ```yaml
  services:
    xmcp:
      build: .
      ports:
        - "8000:8000"
      env_file: .env
      environment:
        - MCP_HOST=0.0.0.0
  ```

**Validation**: `docker compose config` validates without errors. If creds available: `docker compose up --build` starts the server.

#### S1-5: Create `.dockerignore`

**Changes**:
- Create `.dockerignore`:
  ```
  .env
  .env.*
  .venv
  venv
  __pycache__
  .git
  .github
  docs
  tests
  .vscode
  .tokens.json
  *.pyc
  ```

**Validation**: `docker build -t xmcp .` — confirm `.env` and `.git` are not in the image (`docker run --rm xmcp ls -la` should not show `.env` or `.git`).

#### S1-6: Update `env.example` and `README.md` with Docker instructions

**Changes**:
- `env.example`: add comment about `MCP_HOST=0.0.0.0` for Docker
- `README.md`: add "Docker Deployment" section with `docker compose up` instructions

**Validation**: Manual review — instructions are accurate and complete.

---

## Sprint 2: Safety Annotations

**Goal**: Every auto-generated tool has correct MCP safety annotations based on its HTTP method. Required for Anthropic directory listing.

**Demo**: Start server, list tools via MCP Inspector → each tool shows `readOnlyHint`, `destructiveHint`, and `openWorldHint` annotations.

> **Important**: `mcp_component_fn` receives `(route: HTTPRoute, component)`, NOT just `(component)`. The `HTTPRoute` object has `.method` and `.path` attributes. This means we do NOT need `build_method_map()` — we can read the method directly from `route`.

### Tickets

#### S2-1: Implement annotation callback for `mcp_component_fn`

**Changes**:
- In `server.py`, add:
  - `from mcp.types import ToolAnnotations`
  - Import `OpenAPITool` from `fastmcp.server.openapi` (or equivalent)
  - `add_safety_annotations(route, component)` function:
    - Guard: `if not isinstance(component, OpenAPITool): return` (callback fires for all component types, not just tools)
    - Read `method = route.method.lower()`
    - GET/HEAD/OPTIONS → `ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True)`
    - DELETE → `ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True)`
    - POST/PUT/PATCH → `ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=True)`
    - Set `component.annotations = ...`

**Validation**: `tests/test_safety_annotations.py`:
- `test_annotation_get_readonly` — GET tool gets `readOnlyHint=True`
- `test_annotation_delete_destructive` — DELETE tool gets `destructiveHint=True`
- `test_annotation_post_write` — POST tool gets `readOnlyHint=False, destructiveHint=False`
- `test_annotation_skips_non_tool_components` — Resource components are not modified
- `test_annotation_unknown_method_defaults_to_write` — unknown method gets write annotations

#### S2-2: Integrate annotations into `create_mcp()`

**Changes**:
- In `create_mcp()`, pass `mcp_component_fn=add_safety_annotations` to `FastMCP.from_openapi()`
- Ensure `fastmcp>=2.5.0` in `pyproject.toml` (should already be from S0-1)

**Validation**: Integration test `tests/test_safety_annotations.py`:
- `test_annotations_integrated` — use a small mock spec, call the relevant code path, verify the returned FastMCP instance has tools with annotations set. (May need to mock the httpx client and OAuth.)

#### S2-3: (Optional) Add annotation overrides via JSON file

For ambiguous operations where the HTTP method doesn't reflect the real intent (e.g., `hideReply` is a PUT but is destructive).

**Changes**:
- Create `annotation_overrides.json` with manual overrides:
  ```json
  {
    "hideReply": { "readOnlyHint": false, "destructiveHint": true },
    "unfollow": { "readOnlyHint": false, "destructiveHint": true },
    "deletePost": { "readOnlyHint": false, "destructiveHint": true }
  }
  ```
- In the annotation callback: after applying method-based rule, load overrides (once at module level) and apply if the operation has an override
- Load overrides once at import time, not per-tool

**Validation**: `tests/test_safety_annotations.py`:
- `test_override_applied` — a POST operation marked as destructive via override gets `destructiveHint=True`
- `test_override_file_missing_is_ok` — server starts fine without the overrides file

---

## Sprint 3: OAuth 2.0 Client (X API Integration Layer)

**Goal**: A standalone OAuth 2.0 PKCE client module that can authenticate against X's OAuth 2.0 endpoints, exchange codes for tokens, and refresh expired tokens. This is the building block for the full OAuth proxy in Sprint 4.

**Demo**: Unit tests all pass. Each module can be imported and used independently. Run `pytest tests/test_x_oauth2.py tests/test_token_store.py tests/test_client_registry.py -v` — all green.

> **Note**: Sprint 2 and Sprint 3 are independent and can be worked on in parallel. Sprint 4 depends on both.

### Tickets

#### S3-1: Implement `auth/x_oauth2.py` — PKCE utilities

**Changes**:
- Create `auth/__init__.py` (empty)
- Create `auth/x_oauth2.py` with:
  - Constants: `X_AUTHORIZE_URL = "https://x.com/i/oauth2/authorize"`, `X_TOKEN_URL = "https://api.x.com/2/oauth2/token"`
  - `generate_code_verifier() -> str` — random 43-128 char URL-safe string (using `secrets.token_urlsafe`)
  - `generate_code_challenge(verifier: str) -> str` — SHA256 + base64url encode (no padding)
  - `build_authorization_url(client_id, redirect_uri, scopes, state, code_challenge) -> str` — builds URL with all required OAuth2 PKCE params

**Validation**: `tests/test_x_oauth2.py`:
- `test_code_verifier_length` — between 43 and 128 chars
- `test_code_verifier_url_safe` — only URL-safe characters
- `test_code_challenge_deterministic` — same verifier → same challenge
- `test_code_challenge_is_s256` — verify against known test vector (RFC 7636 Appendix B)
- `test_build_authorization_url_contains_required_params` — URL has `client_id`, `redirect_uri`, `response_type=code`, `code_challenge`, `code_challenge_method=S256`, `state`, `scope`

#### S3-2: Implement `auth/x_oauth2.py` — token exchange and refresh

All HTTP calls use `httpx.AsyncClient`. Accept an optional `client` parameter for dependency injection in tests.

**Changes**:
- Add to `auth/x_oauth2.py`:
  - `TokenResponse` dataclass: `access_token: str`, `refresh_token: str`, `expires_in: int`, `expires_at: float` (computed as `time.time() + expires_in`), `scope: str`
  - `is_expired() -> bool` — `time.time() >= self.expires_at`
  - `async exchange_code(client_id, client_secret, code, redirect_uri, code_verifier, *, client: httpx.AsyncClient | None = None) -> TokenResponse` — POST to `X_TOKEN_URL` with `grant_type=authorization_code`
  - `async refresh_token(client_id, client_secret, refresh_token, *, client: httpx.AsyncClient | None = None) -> TokenResponse` — POST to `X_TOKEN_URL` with `grant_type=refresh_token`

**Validation**: `tests/test_x_oauth2.py` (using `pytest-httpx` to mock HTTP):
- `test_exchange_code_success` — mock 200 response, verify TokenResponse fields
- `test_exchange_code_error` — mock 401, verify raises
- `test_refresh_token_success` — mock 200, verify new access_token returned
- `test_refresh_token_error` — mock 400, verify raises
- `test_is_expired_true` — token with past `expires_at` returns True
- `test_is_expired_false` — token with future `expires_at` returns False

#### S3-3: Implement `auth/token_store.py` — token storage abstraction

**Changes**:
- Create `auth/token_store.py` with:
  - `TokenData` dataclass: `x_access_token: str`, `x_refresh_token: str`, `expires_at: float`, `user_id: str | None = None`
  - Abstract base class `TokenStore` (using `abc.ABC`):
    - `async get(session_id: str) -> TokenData | None`
    - `async set(session_id: str, data: TokenData) -> None`
    - `async delete(session_id: str) -> None`
  - `MemoryTokenStore(TokenStore)` — dict-based, for tests
  - `FileTokenStore(TokenStore)` — JSON file-based, for dev/small deployments
    - File path configurable, default `.tokens.json`
    - Atomic writes via tempfile + rename

**Validation**: `tests/test_token_store.py`:
- `test_memory_store_set_get` — store and retrieve
- `test_memory_store_get_missing` — returns None
- `test_memory_store_delete` — removes entry
- `test_file_store_set_get` — store and retrieve (use `tmp_path` fixture)
- `test_file_store_persists` — new FileTokenStore instance pointing to same file, data still there
- `test_file_store_delete` — removes entry from file
- `test_file_store_missing_file` — get from non-existent file returns None

#### S3-4: Implement `auth/client_registry.py` — Dynamic Client Registration storage

**Changes**:
- Create `auth/client_registry.py` with:
  - `ClientInfo` dataclass: `client_id: str`, `client_secret: str`, `client_name: str`, `redirect_uris: list[str]`, `created_at: float`
  - `ClientRegistry` class:
    - `register(client_name: str, redirect_uris: list[str]) -> ClientInfo` — generates `client_id` (uuid4) and `client_secret` (secrets.token_urlsafe(32)), stores in memory
    - `get(client_id: str) -> ClientInfo | None`
    - `validate_redirect_uri(client_id: str, uri: str) -> bool`
  - In-memory storage (dict) — sufficient since there will be 1-2 clients max

**Validation**: `tests/test_client_registry.py`:
- `test_register_returns_client_info` — has id, secret, name, uris
- `test_register_unique_ids` — two registrations get different client_ids
- `test_get_existing_client` — returns stored ClientInfo
- `test_get_missing_client` — returns None
- `test_validate_redirect_uri_valid` — registered URI → True
- `test_validate_redirect_uri_invalid` — unregistered URI → False

---

## Sprint 4: OAuth 2.0 Authorization Server Proxy

**Goal**: The MCP server acts as an OAuth Authorization Server, handling the full Claude.ai ↔ xmcp ↔ X double-redirect flow. Multi-user: each Claude user authenticates with their own X account.

**Demo**: Start server in `oauth2-remote` mode. Use MCP Inspector (or curl) to walk through the OAuth flow: discover metadata → register client → authorize → callback → get token. The returned token can be used as a Bearer token on MCP requests.

> **Depends on**: Sprint 2 (annotations) AND Sprint 3 (OAuth2 client modules).

### Tickets

#### S4-1: Spike — determine how to propagate MCP-layer Bearer token to httpx event hooks

**⚠️ This is the single biggest technical risk in the project.** The auto-generated tools from `FastMCP.from_openapi()` make httpx calls. We need to inject the per-user X token into those calls. The httpx event hooks (currently used for OAuth1 signing) don't have access to the inbound MCP request context.

**Research**:
- Can we use `contextvars.ContextVar` to store the session token in a request-scoped context, then read it in the httpx event hook?
- Does FastMCP expose the incoming auth context (Bearer token) to the tool execution context?
- Is there middleware/lifecycle hooks in FastMCP where we can intercept the incoming request?
- Alternative: per-request httpx client (expensive but guaranteed to work)?

**Deliverable**: A short document (or code comment) describing the chosen approach with a proof-of-concept.

**Validation**: PoC code demonstrating that a Bearer token from an incoming MCP request can be read inside an httpx event hook. Write a test that confirms the ContextVar (or chosen mechanism) propagates correctly.

#### S4-2: Implement `/.well-known/oauth-authorization-server` metadata endpoint

Mount using FastMCP's `@mcp.custom_route()` decorator. Each handler receives a `starlette.requests.Request` and returns a `starlette.responses.JSONResponse` or `RedirectResponse`.

**Changes**:
- Create `auth/oauth_server.py` with an `OAuthServer` class that holds references to `ClientRegistry`, `TokenStore`, and config
- Implement `GET /.well-known/oauth-authorization-server` → returns JSON per RFC 8414:
  ```json
  {
    "issuer": "{PUBLIC_URL}",
    "authorization_endpoint": "{PUBLIC_URL}/authorize",
    "token_endpoint": "{PUBLIC_URL}/token",
    "registration_endpoint": "{PUBLIC_URL}/register",
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    "code_challenge_methods_supported": ["S256"],
    "scopes_supported": ["tweet.read", "tweet.write", "users.read", "offline.access"]
  }
  ```
- Read `X_MCP_PUBLIC_URL` from env

**Validation**: `tests/test_oauth_server.py`:
- `test_metadata_endpoint_returns_json` — correct content type
- `test_metadata_required_fields` — all RFC 8414 required fields present
- `test_metadata_uses_public_url` — issuer and endpoints use configured URL
- `test_metadata_supports_pkce_s256` — `code_challenge_methods_supported` includes `S256`

#### S4-3: Implement `POST /register` — Dynamic Client Registration (RFC 7591)

**Changes**:
- Add to `auth/oauth_server.py`:
  - `POST /register` handler (mounted via `@mcp.custom_route`)
  - Accepts `{ "client_name": "...", "redirect_uris": ["..."] }`
  - Validates `redirect_uris` against allowlist:
    - `https://claude.ai/api/mcp/auth_callback`
    - `http://localhost:*/callback` (for MCP Inspector / Claude Code)
  - Uses `ClientRegistry` from S3-4 to register
  - Returns 201 with `{ "client_id": "...", "client_secret": "...", "client_name": "...", "redirect_uris": [...] }`

**Validation**: `tests/test_oauth_server.py`:
- `test_register_success` — valid request returns 201 with client credentials
- `test_register_missing_redirect_uris` — returns 400
- `test_register_invalid_redirect_uri` — non-allowlisted URI returns 400
- `test_register_claude_callback_allowed` — Claude's callback accepted
- `test_register_localhost_callback_allowed` — localhost callback accepted

#### S4-4: Implement `GET /authorize` — authorization initiation (redirects to X)

**Changes**:
- Add to `auth/oauth_server.py`:
  - `GET /authorize` handler
  - Accepts query params: `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method`, `state`, `scope`
  - Validates client_id, redirect_uri, code_challenge_method
  - Stores pending auth state in `pending_auth: dict[str, PendingAuth]`:
    - `PendingAuth` dataclass: `client_id`, `redirect_uri`, `code_challenge`, `original_state`, `x_code_verifier`, `created_at`
    - TTL: entries older than 10 minutes are cleaned up on next access
  - Generates its own PKCE pair for X
  - Redirects (302) to `https://x.com/i/oauth2/authorize?...`

**Validation**: `tests/test_oauth_server.py`:
- `test_authorize_redirects_to_x` — response is 302, Location starts with X authorize URL
- `test_authorize_includes_pkce` — redirect URL has `code_challenge` and `code_challenge_method=S256`
- `test_authorize_stores_pending_state` — internal state store has the pending auth data
- `test_authorize_invalid_client_id` — returns 400
- `test_authorize_invalid_redirect_uri` — returns 400
- `test_pending_auth_expires` — entries older than 10 minutes are cleaned up

#### S4-5: Implement `GET /x/callback` — receive X auth code, redirect back to Claude

**Changes**:
- Add to `auth/oauth_server.py`:
  - `GET /x/callback` handler
  - Receives `code` and `state` from X
  - Looks up pending auth by `state`
  - Uses `x_oauth2.exchange_code()` to get X tokens
  - Stores X tokens in `TokenStore` keyed by new session_id
  - Generates authorization code for Claude: `secrets.token_urlsafe(32)`, stored in `pending_codes: dict[str, PendingCode]`
    - `PendingCode` dataclass: `session_id`, `client_id`, `code_challenge`, `redirect_uri`, `created_at`
    - Codes expire after 60 seconds (per OAuth2 spec)
  - Redirects (302) to `{original_redirect_uri}?code={our_code}&state={original_state}`

**Validation**: `tests/test_oauth_server.py`:
- `test_x_callback_exchanges_code` — mock X token endpoint, verify token exchange called
- `test_x_callback_stores_tokens` — tokens stored in TokenStore
- `test_x_callback_redirects_to_client` — 302 to original redirect_uri with code and state
- `test_x_callback_invalid_state` — unknown state returns 400
- `test_x_callback_x_error` — X returns error, appropriate error response

#### S4-6: Implement `POST /token` — token exchange (code → access_token)

**Changes**:
- Add to `auth/oauth_server.py`:
  - `POST /token` handler
  - Support both `client_secret_basic` (HTTP Basic Auth) and `client_secret_post` (in body) for client authentication
  - For `grant_type=authorization_code`:
    - Validates `code` exists in `pending_codes` and is not expired (60s)
    - Validates `client_id` matches
    - Verifies PKCE: `code_challenge == S256(code_verifier)`
    - Deletes code after use (single-use)
    - Generates session tokens: `access_token = secrets.token_urlsafe(32)`, `refresh_token = secrets.token_urlsafe(32)`
    - Returns `{ "access_token": "...", "token_type": "bearer", "expires_in": 7200, "refresh_token": "..." }`
  - For `grant_type=refresh_token`:
    - Validates `refresh_token` and `client_id`
    - Refreshes X tokens if needed (via `x_oauth2.refresh_token()`)
    - Generates new session tokens, returns them

**Validation**: `tests/test_oauth_server.py`:
- `test_token_exchange_success` — valid code + verifier returns tokens
- `test_token_exchange_invalid_code` — returns 400
- `test_token_exchange_expired_code` — code older than 60s returns 400
- `test_token_exchange_invalid_pkce` — wrong verifier returns 400
- `test_token_exchange_code_single_use` — second exchange with same code returns 400
- `test_token_exchange_client_secret_basic` — HTTP Basic Auth works
- `test_token_exchange_client_secret_post` — client_id/secret in body works
- `test_token_refresh_success` — valid refresh token returns new tokens
- `test_token_refresh_invalid` — invalid refresh token returns 400

#### S4-7: Add `X_AUTH_MODE` env var and auth mode routing in `server.py`

**Changes**:
- In `server.py`:
  - Read `X_AUTH_MODE` from env (default: `"oauth1"`)
  - When `oauth1`: existing behavior (browser OAuth1 flow at startup)
  - When `oauth2-remote`: skip OAuth1 flow, mount OAuth server endpoints via `@mcp.custom_route()`
  - Add `validate_env()` function: checks all required env vars for the selected auth mode at startup. Raises `RuntimeError` listing missing vars. Required for `oauth2-remote`: `X_OAUTH2_CLIENT_ID`, `X_OAUTH2_CLIENT_SECRET`, `X_MCP_PUBLIC_URL`.
- Import and initialize `OAuthServer`, `TokenStore`, `ClientRegistry`

**Validation**: `tests/test_auth_mode.py`:
- `test_default_auth_mode_is_oauth1` — no env var → oauth1
- `test_oauth2_remote_skips_browser_flow` — mock env, confirm `run_oauth1_flow` not called
- `test_oauth2_remote_mounts_endpoints` — verify OAuth endpoints are registered
- `test_validate_env_missing_vars` — missing required vars raises RuntimeError with clear message
- `test_validate_env_oauth1_minimal` — only consumer key/secret needed for oauth1

#### S4-8: Implement per-request auth middleware for `oauth2-remote` mode

Based on the approach determined in S4-1 spike.

**Changes**:
- In `server.py`, replace the OAuth1 signing middleware when in `oauth2-remote` mode:
  - Extract Bearer token from MCP request context (via ContextVar or chosen mechanism from S4-1)
  - Look up X tokens from TokenStore
  - If X token expired, refresh via `x_oauth2.refresh_token()`
  - Set `Authorization: Bearer {x_access_token}` on outgoing httpx request

**Validation**: `tests/test_auth_middleware.py`:
- `test_bearer_token_injected` — mock token store, verify X token appears in outgoing request
- `test_expired_token_refreshed` — expired token triggers refresh, new token used
- `test_missing_token_returns_401` — no Bearer token → 401 error
- `test_invalid_token_returns_401` — token not in store → 401 error

#### S4-9: Add CORS configuration for Claude.ai origins

**Changes**:
- Determine if FastMCP exposes the underlying Starlette app for `CORSMiddleware`. If yes, use `starlette.middleware.cors.CORSMiddleware`. If not, set CORS headers manually in each OAuth endpoint handler.
- Allowed origins:
  - `https://claude.ai`
  - `https://claude.com`
  - `https://www.anthropic.com`
  - `https://api.anthropic.com`
- Allow methods: GET, POST, OPTIONS
- Allow headers: Authorization, Content-Type
- Configurable via `X_CORS_ORIGINS` env var (comma-separated, appended to defaults)

**Validation**: `tests/test_cors.py`:
- `test_cors_allows_claude_origin` — request with `Origin: https://claude.ai` gets proper CORS headers
- `test_cors_blocks_unknown_origin` — request with random origin gets no CORS headers
- `test_cors_preflight_options` — OPTIONS request returns correct headers

#### S4-10: Update `env.example` with OAuth2 configuration

**Changes**:
- Add to `env.example`:
  ```
  # Auth mode: oauth1, oauth2-remote
  X_AUTH_MODE=oauth1

  # OAuth2 settings (required for oauth2-remote)
  X_OAUTH2_CLIENT_ID=
  X_OAUTH2_CLIENT_SECRET=
  X_OAUTH2_SCOPES=tweet.read tweet.write users.read offline.access

  # Remote OAuth server settings (required for oauth2-remote)
  X_MCP_PUBLIC_URL=
  X_TOKEN_STORE_PATH=.tokens.json
  X_CORS_ORIGINS=
  ```

**Validation**: Manual review — all new env vars documented. Existing env vars unchanged.

---

## Sprint 5: Production Readiness (Rate Limits, Health Check, Error Handling)

**Goal**: The server handles X API rate limits gracefully, has a health endpoint for monitoring, and returns user-friendly error messages. Deployable to Railway/Cloudflare.

**Demo**: Deploy to Railway. Hit rate limit → get clear error message with retry time. `GET /health` returns 200. Errors from X API are translated to helpful messages.

### Tickets

#### S5-1: Add `GET /health` endpoint

**Changes**:
- In `server.py`, mount via `@mcp.custom_route("/health", methods=["GET"])`:
  ```json
  { "status": "ok", "version": "0.1.0", "auth_mode": "oauth2-remote" }
  ```
- Works regardless of auth mode
- No authentication required

**Validation**: `tests/test_health.py`:
- `test_health_returns_200` — GET /health returns 200
- `test_health_response_format` — response has `status`, `version`, `auth_mode`

#### S5-2: Implement rate limit awareness from X API response headers

**Changes**:
- In `server.py`, add response event hook `handle_rate_limits()`:
  - Read `x-rate-limit-remaining` and `x-rate-limit-reset` from response headers
  - If status is 429 or `remaining == "0"`:
    - Calculate wait time from reset timestamp
    - Return structured error with: endpoint, limit info, seconds until reset, human-readable message
  - Log rate limit state at DEBUG level

**Validation**: `tests/test_rate_limits.py`:
- `test_rate_limit_429_returns_clear_error` — mock 429 response, verify error message includes wait time
- `test_rate_limit_remaining_zero` — response with `remaining=0` triggers warning
- `test_rate_limit_normal_passthrough` — response with remaining > 0 passes through unchanged
- `test_rate_limit_missing_headers` — response without rate limit headers passes through

#### S5-3: Implement retry with exponential backoff for 429 and 5xx

**⚠️ Important**: httpx event hooks cannot retry requests. Implement retry using a custom `httpx.AsyncBaseTransport` wrapper that intercepts responses and re-issues requests.

**Changes**:
- Create `RetryTransport(httpx.AsyncBaseTransport)` wrapper:
  - On 429: wait until `x-rate-limit-reset` time, then retry (max 1 retry)
  - On 5xx: retry with exponential backoff (max 2 retries, starting at 1s)
  - Configurable via `X_API_MAX_RETRIES` env var (default: 2)
  - Log each retry attempt
- Wrap the httpx client's transport with `RetryTransport`

**Validation**: `tests/test_retries.py`:
- `test_retry_on_429` — mock 429 then 200, verify second attempt succeeds
- `test_retry_on_500` — mock 500 then 200, verify retry works
- `test_no_retry_on_4xx` — mock 400, verify no retry
- `test_max_retries_exceeded` — mock persistent 500, verify gives up after max retries
- `test_retries_disabled` — set max retries to 0, verify no retry on 429

#### S5-4: Implement user-friendly error message transformation

Include original X API error details alongside the friendly message for debugging.

**Changes**:
- In `server.py`, add error transformation in response event hook:
  - Parse X API error responses (they have a specific JSON format)
  - Transform to structured response with both friendly message and original details:
    ```json
    {
      "message": "Rate limit exceeded. Please wait 45 seconds.",
      "x_error": { ... original X error ... },
      "x_transaction_id": "..."
    }
    ```
  - Friendly messages by status:
    - 401 → "Authentication failed. Your X account token may have expired."
    - 403 → "You don't have permission to perform this action."
    - 404 → "The requested resource was not found on X."
    - 429 → "Rate limit exceeded. Please wait {N} seconds."
    - 5xx → "X API is experiencing issues. Please try again later."
  - Log full error at WARNING level

**Validation**: `tests/test_error_messages.py`:
- `test_401_message` — clear auth failure message + original error preserved
- `test_403_message` — permission message
- `test_404_message` — not found message
- `test_429_message` — rate limit with wait time
- `test_500_message` — X API down message
- `test_200_no_transformation` — successful responses pass through untouched

---

## Sprint 6: Documentation & Deployment

**Goal**: Complete documentation, license, and deployment configs. The project is ready for public use and Anthropic directory submission.

**Demo**: Fresh clone → follow README → server running in Docker in under 5 minutes. All docs complete.

### Tickets

#### S6-1: Add `LICENSE` file (MIT)

**Changes**:
- Create `LICENSE` with MIT license text
- Add `license = "MIT"` to `pyproject.toml`

**Validation**: File exists, is valid MIT license, year and author are correct.

#### S6-2: Create `PRIVACY.md`

**Changes**:
- Create `PRIVACY.md` covering:
  - What data is stored (OAuth tokens only)
  - No tweet content or user data stored
  - How to revoke access (link to X app settings)
  - No third-party data sharing
  - Token retention policy

**Validation**: Manual review — covers all required privacy topics.

#### S6-3: Create `docs/DEPLOYMENT.md`

**Changes**:
- Create `docs/DEPLOYMENT.md` covering:
  - Local development setup
  - Docker deployment
  - Railway deployment (with env vars guide)
  - Cloudflare Containers deployment
  - Environment variable reference table (all env vars from all sprints)
  - HTTPS/TLS requirements for OAuth2 mode

**Validation**: Manual review — instructions are complete and follow a logical order.

#### S6-4: Create `docs/EXAMPLES.md` with 3+ usage examples

**Changes**:
- Create `docs/EXAMPLES.md` with at least 3 examples per Anthropic requirements:
  1. Search tweets: "Search for recent tweets about AI" → `searchPostsRecent`
  2. Post a tweet: "Post a tweet saying..." → `createPosts`
  3. Get user profile: "Show me @xdevelopers profile" → `getUsersByUsername` + `getUsersPosts`
  4. Manage bookmarks: "Bookmark this tweet" → `postUsersIdBookmarks`
  5. Search users: "Find users who work at Anthropic" → `searchUsers`
- Each example includes: user prompt, tools invoked, expected behavior

**Validation**: Manual review — examples are realistic and cover read/write/multi-tool scenarios.

#### S6-5: Create `docs/CLAUDE_CONNECTOR.md` — connecting as Claude.ai custom connector

**Changes**:
- Create `docs/CLAUDE_CONNECTOR.md` covering:
  - Prerequisites (deployed server with HTTPS, X Developer App with OAuth2)
  - Step-by-step: Settings → Connectors → Add Custom → enter URL
  - Expected OAuth flow walkthrough
  - Troubleshooting (CORS, callback URLs, token errors)

**Validation**: Manual review — follows the actual Claude.ai connector setup flow.

#### S6-6: Rewrite `README.md`

**Changes**:
- Rewrite `README.md`:
  - Badges: CI status, license, Python 3.12+
  - One-paragraph description
  - Quick start (3 paths: local, Docker, remote)
  - Features list
  - Architecture overview (how auto-generated tools work)
  - Tool categories summary
  - Configuration reference (link to full env var docs)
  - Links to docs/ files
  - Contributing section
  - License
  - Remove orphaned reference to `generate_authtoken.py`

**Validation**: Manual review — covers all essential topics, is scannable, has working links.

---

## Sprint Dependency Graph

```
S0 (Foundation)
 └─→ S1 (Docker + Transport)
      ├─→ S2 (Safety Annotations)  ─┐
      └─→ S3 (OAuth2 Client)       ─┤
                                     └─→ S4 (OAuth2 Server Proxy)
                                          └─→ S5 (Production Polish)
                                               └─→ S6 (Docs & Deploy)
```

S2 and S3 are **independent** — they can be worked on in parallel. S4 depends on both.

### State after each sprint

- **After S0**: Server works as before + has tests + CI
- **After S1**: Server works in Docker with modern transport
- **After S2**: All tools have safety annotations (Anthropic directory requirement)
- **After S3**: OAuth2 modules exist and are tested in isolation
- **After S4**: Full OAuth2 proxy flow works, multi-user ready for Claude.ai
- **After S5**: Rate limits, health checks, retries, friendly errors
- **After S6**: Fully documented, licensed, ready for Anthropic directory submission

---

## Deferred / Out of Scope

Items from `plan.md` intentionally deferred:

- **`oauth2-local` auth mode** — Dropped for simplicity. Can be added later.
- **Response caching for GET requests** — Deferred. Adds complexity for marginal benefit at this stage.
- **Redis/KV token store** — `FileTokenStore` is sufficient for initial deployment. Redis adapter can be added when scaling requires it.
