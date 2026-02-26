import time

import httpx
import pytest

import server
from auth.client_registry import ClientRegistry
from auth.oauth_server import OAuthServer, SessionToken
from auth.token_store import MemoryTokenStore, TokenData
from auth.x_oauth2 import TokenResponse
from fastmcp.server.auth import AccessToken


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
    await server.inject_oauth2_access_token(request, oauth_server_instance)

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
    await server.inject_oauth2_access_token(request, oauth_server_instance)

    assert request.headers["Authorization"] == "Bearer x-access-refreshed"


@pytest.mark.asyncio
async def test_missing_token_returns_401(oauth_server_instance) -> None:
    server.CURRENT_MCP_BEARER_TOKEN.set(None)

    request = httpx.Request("GET", "https://api.x.com/2/users/me")
    with pytest.raises(server.UnauthorizedRequestError) as error:
        await server.inject_oauth2_access_token(request, oauth_server_instance)

    assert error.value.status_code == 401


@pytest.mark.asyncio
async def test_invalid_token_returns_401(oauth_server_instance) -> None:
    server.CURRENT_MCP_BEARER_TOKEN.set("unknown-token")

    request = httpx.Request("GET", "https://api.x.com/2/users/me")
    with pytest.raises(server.UnauthorizedRequestError) as error:
        await server.inject_oauth2_access_token(request, oauth_server_instance)

    assert error.value.status_code == 401


@pytest.mark.asyncio
async def test_refresh_failure_returns_401() -> None:
    async def refresh_token_fn(**kwargs):
        del kwargs
        raise RuntimeError("invalid_grant")

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
    await oauth.token_store.set(
        "session-1",
        TokenData(
            x_access_token="stale",
            x_refresh_token="x-refresh",
            expires_at=time.time() - 1,
        ),
    )
    server.CURRENT_MCP_BEARER_TOKEN.set("session-access")

    request = httpx.Request("GET", "https://api.x.com/2/users/me")
    with pytest.raises(server.UnauthorizedRequestError) as error:
        await server.inject_oauth2_access_token(request, oauth)

    assert error.value.status_code == 401
    assert "re-auth required" in str(error.value)


# --- build_session_token_verifier tests ---


@pytest.fixture
def verifier_oauth():
    oauth = OAuthServer(
        public_url="https://xmcp.example.com",
        x_client_id="x-client",
        x_client_secret="x-secret",
        token_store=MemoryTokenStore(),
        client_registry=ClientRegistry(),
    )
    oauth.sessions_by_access["valid-token"] = SessionToken(
        session_id="s1",
        client_id="c1",
        refresh_token="r1",
        created_at=time.time(),
    )
    return oauth


@pytest.mark.asyncio
async def test_session_verifier_returns_access_token(verifier_oauth) -> None:
    verifier = server.build_session_token_verifier(
        verifier_oauth, base_url="https://xmcp.example.com"
    )
    result = await verifier.verify_token("valid-token")
    assert isinstance(result, AccessToken)
    assert result.token == "valid-token"
    assert result.client_id == "c1"


@pytest.mark.asyncio
async def test_session_verifier_rejects_unknown_token(verifier_oauth) -> None:
    verifier = server.build_session_token_verifier(
        verifier_oauth, base_url="https://xmcp.example.com"
    )
    result = await verifier.verify_token("unknown-token")
    assert result is None


@pytest.mark.asyncio
async def test_session_verifier_rejects_expired_token(verifier_oauth) -> None:
    verifier_oauth.sessions_by_access["expired-token"] = SessionToken(
        session_id="s2",
        client_id="c2",
        refresh_token="r2",
        created_at=time.time() - 9999,
    )
    verifier = server.build_session_token_verifier(
        verifier_oauth, base_url="https://xmcp.example.com", expires_in_seconds=1
    )
    result = await verifier.verify_token("expired-token")
    assert result is None
