# xmcp Sprint Summary (Current State)

This repository runs a single authentication model: OAuth2 remote server flow.

## Scope

- Runtime transport: `streamable-http`
- Auth runtime: OAuth2 Authorization Code + PKCE only
- OAuth routes mounted by default:
  - `/.well-known/oauth-authorization-server`
  - `/register`
  - `/authorize`
  - `/x/callback`
  - `/token`
- Request auth propagation:
  - capture inbound MCP bearer token
  - resolve and refresh X token via token store
  - inject outbound `Authorization: Bearer <x_access_token>`

## Current validation commands

```bash
uv run ruff check .
uv run pytest
```

## Deployment notes

- Set `X_MCP_PUBLIC_URL` to your public HTTPS host.
- Persist `X_TOKEN_STORE_PATH` in Docker/production (default `.tokens.json`).
- Session tokens and pending auth state are in memory and are reset on restart.
