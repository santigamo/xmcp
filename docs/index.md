# Documentation Index

- [Architecture](./architecture.md) - Runtime flow, auth model, state boundaries, and acceptance checks.
- [Development](../README.md#local-setup) - Local environment setup, quality checks, and smoke tests.
- [Deployment](../README.md#docker) - Container startup and token persistence notes.
- [Security](../SECURITY.md) - Vulnerability reporting and support policy.

## Operational Notes

- Redirect URI policy:
  - `https://claude.ai/api/mcp/auth_callback`
  - `http://localhost:<port>/callback` (localhost only, explicit port required)
- Session state (`pending_auth`, `pending_codes`, `sessions_by_access`, `sessions_by_refresh`) is in memory.
- X OAuth tokens are persisted via `TokenStore` (`.tokens.json` by default).

## Known limitations

- Session and pending OAuth state are in-memory and are invalidated on restart.
- Runtime transport is fixed to `streamable-http`.
- OpenAPI streaming/webhook operations are intentionally excluded.
