import time

import httpx
import pytest

import server
from auth.client_registry import ClientRegistry
from auth.oauth_server import OAuthServer, SessionToken
from auth.token_store import MemoryTokenStore, TokenData
from auth.x_oauth2 import TokenResponse


@pytest.fixture
def oauth_server_instance():
    async def refresh_token_fn(**kwargs):
        del kwargs
        return TokenResponse(
            access_token="x-access-refreshed",
            refresh_token="x-refresh-refreshed",
            expires_in=7200,
            expires_at=time.time() + 7200,
            scope="tweet.read",
        )

    oauth = OAuthServer(
        public_url="https://xmcp.example.com",
        x_client_id="x-client",
        x_client_secret="x-secret",
        token_store=MemoryTokenStore(),
        client_registry=ClientRegistry(),
        refresh_token_fn=refresh_token_fn,
    )

    oauth.sessions_by_access["session-access"] = SessionToken(
        session_id="session-1",
        client_id="client-1",
        refresh_token="session-refresh",
        created_at=time.time(),
    )

    return oauth


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
async def test_bearer_token_injected(oauth_server_instance) -> None:
    await oauth_server_instance.token_store.set(
        "session-1",
        TokenData(
            x_access_token="x-access",
            x_refresh_token="x-refresh",
            expires_at=time.time() + 7200,
        ),
    )
    server.CURRENT_MCP_BEARER_TOKEN.set("session-access")

    request = httpx.Request("GET", "https://api.x.com/2/users/me")
    await server.inject_oauth2_access_token(request, oauth_server_instance, b3_flags="1")

    assert request.headers["Authorization"] == "Bearer x-access"


@pytest.mark.asyncio
async def test_expired_token_refreshed(oauth_server_instance) -> None:
    await oauth_server_instance.token_store.set(
        "session-1",
        TokenData(
            x_access_token="stale",
            x_refresh_token="x-refresh",
            expires_at=time.time() - 1,
        ),
    )
    server.CURRENT_MCP_BEARER_TOKEN.set("session-access")

    request = httpx.Request("GET", "https://api.x.com/2/users/me")
    await server.inject_oauth2_access_token(request, oauth_server_instance, b3_flags="1")

    assert request.headers["Authorization"] == "Bearer x-access-refreshed"


@pytest.mark.asyncio
async def test_missing_token_returns_401(oauth_server_instance) -> None:
    server.CURRENT_MCP_BEARER_TOKEN.set(None)

    request = httpx.Request("GET", "https://api.x.com/2/users/me")
    with pytest.raises(server.UnauthorizedRequestError) as error:
        await server.inject_oauth2_access_token(request, oauth_server_instance, b3_flags="1")

    assert error.value.status_code == 401


@pytest.mark.asyncio
async def test_invalid_token_returns_401(oauth_server_instance) -> None:
    server.CURRENT_MCP_BEARER_TOKEN.set("unknown-token")

    request = httpx.Request("GET", "https://api.x.com/2/users/me")
    with pytest.raises(server.UnauthorizedRequestError) as error:
        await server.inject_oauth2_access_token(request, oauth_server_instance, b3_flags="1")

    assert error.value.status_code == 401
