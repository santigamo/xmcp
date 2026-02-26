# Documentation Index

- [Architecture](./architecture.md) - Runtime flow, auth model, state boundaries, and acceptance checks.
- [Sprint Summary](./sprints.md) - Current scope and deployment notes.

## Operational Notes

- Redirect URI policy:
  - `https://claude.ai/api/mcp/auth_callback`
  - `http://localhost:<port>/callback` (localhost only, explicit port required)
- Session state (`pending_auth`, `pending_codes`, `sessions_by_access`, `sessions_by_refresh`) is in memory.
- X OAuth tokens are persisted via `TokenStore` (`.tokens.json` by default).
