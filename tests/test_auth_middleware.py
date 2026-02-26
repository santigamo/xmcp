import time

import httpx
import pytest

import server
from auth import signed_token
from auth.client_registry import ClientRegistry
from auth.oauth_server import OAuthServer
from fastmcp.server.auth import AccessToken


def _make_oauth(**kwargs):
    return OAuthServer(
        public_url="https://xmcp.example.com",
        x_client_id="x-client",
        x_client_secret="x-secret",
        client_registry=ClientRegistry(),
        **kwargs,
    )


def _mint_access_token(oauth, *, x_access_token="x-access", x_expires_at=None, client_id="c1"):
    if x_expires_at is None:
        x_expires_at = time.time() + 7200
    access, _ = oauth._mint_session_tokens(
        x_access_token=x_access_token,
        x_refresh_token="x-refresh",
        x_expires_at=x_expires_at,
        client_id=client_id,
    )
    return access


@pytest.mark.asyncio
async def test_contextvar_propagates_bearer_from_http_context(monkeypatch) -> None:
    monkeypatch.setattr(
        "fastmcp.server.dependencies.get_http_headers",
        lambda include_all=False: {"authorization": "Bearer session-access"},
    )

    token = server.capture_mcp_bearer_token_from_context()

    assert token == "session-access"
    assert server.CURRENT_MCP_BEARER_TOKEN.get() == "session-access"


@pytest.mark.asyncio
async def test_bearer_token_injected() -> None:
    oauth = _make_oauth()
    access = _mint_access_token(oauth)
    server.CURRENT_MCP_BEARER_TOKEN.set(access)

    request = httpx.Request("GET", "https://api.x.com/2/users/me")
    await server.inject_oauth2_access_token(request, oauth)

    assert request.headers["Authorization"] == "Bearer x-access"


@pytest.mark.asyncio
async def test_expired_x_token_raises() -> None:
    oauth = _make_oauth()
    access = _mint_access_token(oauth, x_expires_at=time.time() - 1)
    server.CURRENT_MCP_BEARER_TOKEN.set(access)

    request = httpx.Request("GET", "https://api.x.com/2/users/me")
    with pytest.raises(server.UnauthorizedRequestError) as error:
        await server.inject_oauth2_access_token(request, oauth)

    assert error.value.status_code == 401


@pytest.mark.asyncio
async def test_missing_token_returns_401() -> None:
    oauth = _make_oauth()
    server.CURRENT_MCP_BEARER_TOKEN.set(None)

    request = httpx.Request("GET", "https://api.x.com/2/users/me")
    with pytest.raises(server.UnauthorizedRequestError) as error:
        await server.inject_oauth2_access_token(request, oauth)

    assert error.value.status_code == 401


@pytest.mark.asyncio
async def test_invalid_token_returns_401() -> None:
    oauth = _make_oauth()
    server.CURRENT_MCP_BEARER_TOKEN.set("unknown-token")

    request = httpx.Request("GET", "https://api.x.com/2/users/me")
    with pytest.raises(server.UnauthorizedRequestError) as error:
        await server.inject_oauth2_access_token(request, oauth)

    assert error.value.status_code == 401


# --- build_session_token_verifier tests ---


@pytest.mark.asyncio
async def test_session_verifier_returns_access_token() -> None:
    oauth = _make_oauth()
    access = _mint_access_token(oauth, client_id="c1")
    verifier = server.build_session_token_verifier(
        oauth, base_url="https://xmcp.example.com"
    )
    result = await verifier.verify_token(access)
    assert isinstance(result, AccessToken)
    assert result.token == access
    assert result.client_id == "c1"


@pytest.mark.asyncio
async def test_session_verifier_rejects_unknown_token() -> None:
    oauth = _make_oauth()
    verifier = server.build_session_token_verifier(
        oauth, base_url="https://xmcp.example.com"
    )
    result = await verifier.verify_token("unknown-token")
    assert result is None


@pytest.mark.asyncio
async def test_session_verifier_rejects_expired_token() -> None:
    oauth = _make_oauth()
    # Mint a token with old iat
    token = signed_token.encode(
        {
            "xat": "x",
            "xrt": "xr",
            "xexp": time.time() + 7200,
            "cid": "c2",
            "typ": "a",
            "iat": time.time() - 9999,
        },
        oauth._session_key,
    )
    verifier = server.build_session_token_verifier(
        oauth, base_url="https://xmcp.example.com", expires_in_seconds=1
    )
    result = await verifier.verify_token(token)
    assert result is None
