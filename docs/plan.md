# xmcp Architecture Plan (OAuth2 Remote)

## Objective

Operate `xmcp` as a remote MCP server for X API with a single auth flow:

- OAuth2 Authorization Code + PKCE
- Remote callback at `X_MCP_PUBLIC_URL + /x/callback`
- Session tokens issued by `/token` and used by MCP clients

## Runtime flow

1. Client registers via `POST /register`.
2. Client starts auth via `GET /authorize` with PKCE.
3. User authenticates in X and returns to `/x/callback`.
4. Server redirects client callback with authorization code.
5. Client exchanges code at `POST /token`.
6. MCP tool call uses bearer session token.
7. Server resolves/refreshes X access token and calls X API.

## State and persistence

- Pending auth and pending code state are in-memory with TTLs.
- Session token indexes are in-memory.
- X tokens are persisted in `TokenStore` (`.tokens.json` by default).
- Restart requires re-authentication because session indexes are not reconstructed.

## Error semantics

- Missing/invalid session bearer in tool call: `401`.
- Revoked/expired X refresh token during tool call: `401` with re-auth required message.
- Revoked/expired X refresh token during `/token` refresh grant:
  - `401`
  - `error=invalid_grant`

## Acceptance checks

```bash
uv run ruff check .
uv run pytest
docker build -t xmcp .
docker compose up --build -d
curl -sS http://127.0.0.1:8000/health
curl -sS http://127.0.0.1:8000/.well-known/oauth-authorization-server
```
