# X API FastMCP Server (OAuth2 Remote Only)

`xmcp` exposes the X API OpenAPI spec as MCP tools using FastMCP with
`streamable-http` transport. Authentication is OAuth 2.0 Authorization Code + PKCE
through built-in remote OAuth endpoints.

## Prerequisites

- Python `3.12+`
- `uv` installed
- X Developer OAuth2 app configured as a confidential client (web/bot style app)

## Required environment

Copy `env.example` to `.env` and set:

- `X_OAUTH2_CLIENT_ID`
- `X_OAUTH2_CLIENT_SECRET`
- `X_MCP_PUBLIC_URL` (public HTTPS URL of this server)

Recommended:

- `X_OAUTH2_SCOPES=tweet.read tweet.write users.read offline.access`
- `X_TOKEN_STORE_PATH=.tokens.json`
- `X_B3_FLAGS=1`
- `MCP_HOST=127.0.0.1`
- `MCP_PORT=8000`

Optional:

- `X_BEARER_TOKEN` — app-only Bearer Token for read-only GET requests (workaround for OAuth 402 bug)

`X_CORS_ORIGINS` is additive: default Claude/Anthropic origins are already allowed.

Startup validation is strict:

- `X_MCP_PUBLIC_URL` must be a valid `https://` URL
- `X_OAUTH2_SCOPES` must include `offline.access`

## X Developer portal setup

For your X app:

- OAuth2 app type must be confidential (with client secret)
- Redirect URI must include:
  - `https://<your-public-domain>/x/callback`
- Scopes should match `X_OAUTH2_SCOPES` and include `offline.access` for refresh

## Local setup

```bash
uv venv
uv pip install -e ".[dev]"
cp env.example .env
uv run python server.py
```

Default MCP endpoint: `http://127.0.0.1:8000/mcp`

## OAuth endpoints

The server mounts:

- `GET /.well-known/oauth-authorization-server`
- `POST /register`
- `GET /authorize`
- `GET /x/callback`
- `POST /token`
- `GET /health`

Quick checks:

```bash
curl -sS http://127.0.0.1:8000/health
curl -sS http://127.0.0.1:8000/.well-known/oauth-authorization-server
```

## Session tokens

`POST /token` returns opaque session tokens generated with `secrets.token_urlsafe`.

- `access_token` lifetime: `expires_in=7200` (2 hours)
- `refresh_token`: session-level token, separate from X refresh token
- refresh rotates session tokens and invalidates old ones
- session maps (`sessions_by_access`, `sessions_by_refresh`) are in memory
- pending auth/code state is in memory (`pending_auth`, `pending_codes`)
- restart invalidates active sessions and in-flight auth; users must re-authenticate
- X tokens are persisted in `TokenStore` (default file path `.tokens.json`)

## Refresh/re-auth behavior

- Tool calls with invalid or expired credentials return `401` (Unauthorized)
- Session refresh with revoked/expired X refresh token returns:
  - `401` with `error=invalid_grant`
  - error description instructing full re-authentication

## Docker

`docker-compose.yml` runs with `MCP_HOST=0.0.0.0` and persists token store to:

- `./.tokens.json:/app/.tokens.json`

Run:

```bash
docker compose up --build
```

## Quality checks

```bash
uv run ruff check .
uv run pytest
```

## OAuth2 smoke test

Run the remote OAuth endpoint smoke checks against a running server:

```bash
scripts/smoke_oauth_remote.sh
```

Optional custom base URL:

```bash
scripts/smoke_oauth_remote.sh http://127.0.0.1:8000
```

## Notes

- Runtime transport is fixed to `streamable-http`.
- OpenAPI streaming/webhook operations are filtered out.
- `X_API_TOOL_ALLOWLIST`, `X_API_TOOL_DENYLIST`, and `X_API_TOOL_TAGS` are applied at startup.
- Manual credentialed Grok script remains at `examples/test_grok_mcp.py`.
