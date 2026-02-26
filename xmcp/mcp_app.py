from __future__ import annotations

import time
from contextvars import ContextVar
from typing import TYPE_CHECKING

import httpx

from .constants import APP_VERSION, AUTH_MODE

if TYPE_CHECKING:
    from fastmcp import FastMCP


CURRENT_MCP_BEARER_TOKEN: ContextVar[str | None] = ContextVar(
    "current_mcp_bearer_token", default=None
)


class UnauthorizedRequestError(RuntimeError):
    def __init__(self, message: str = "Unauthorized request.") -> None:
        super().__init__(message)
        self.status_code = 401


def build_session_token_verifier(oauth_server, *, base_url: str, expires_in_seconds: int = 7200):
    from fastmcp.server.auth import AccessToken, TokenVerifier

    class _Verifier(TokenVerifier):
        def __init__(self, oauth_server, *, base_url: str, expires_in_seconds: int) -> None:
            super().__init__(base_url=base_url, required_scopes=[])
            self._oauth_server = oauth_server
            self._expires_in_seconds = expires_in_seconds

        async def verify_token(self, token: str) -> AccessToken | None:
            try:
                payload = self._oauth_server.decode_session_token(token)
            except Exception:
                return None

            iat = payload.get("iat", 0)
            expires_at = int(iat + self._expires_in_seconds)
            if time.time() >= expires_at:
                return None

            return AccessToken(
                token=token,
                client_id=payload.get("cid", ""),
                scopes=[],
                expires_at=expires_at,
            )

    return _Verifier(oauth_server, base_url=base_url, expires_in_seconds=expires_in_seconds)


def extract_bearer_token(authorization_header: str | None) -> str | None:
    if not authorization_header:
        return None
    scheme, _, token = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def capture_mcp_bearer_token_from_context() -> str | None:
    from fastmcp.server.dependencies import get_http_headers

    headers = get_http_headers(include_all=True)
    token = extract_bearer_token(headers.get("authorization"))
    CURRENT_MCP_BEARER_TOKEN.set(token)
    return token


async def inject_oauth2_access_token(
    request: httpx.Request,
    oauth_server,
) -> None:
    session_access_token = CURRENT_MCP_BEARER_TOKEN.get()
    if not session_access_token:
        raise UnauthorizedRequestError("Missing Bearer token in MCP request context (401).")
    try:
        x_access_token = await oauth_server.resolve_x_access_token(session_access_token)
    except Exception as error:
        raise UnauthorizedRequestError(
            f"Invalid or expired session token (401): {error}"
        ) from error

    request.headers["Authorization"] = f"Bearer {x_access_token}"


def mount_health_route(mcp: "FastMCP") -> None:
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response

    @mcp.custom_route("/health", methods=["GET"])
    async def health_route(request: Request) -> Response:
        del request
        return JSONResponse(
            {
                "status": "ok",
                "version": APP_VERSION,
                "auth_mode": AUTH_MODE,
            }
        )
