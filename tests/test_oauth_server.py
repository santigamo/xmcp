import base64
import time
import urllib.parse

from fastmcp import FastMCP
from starlette.testclient import TestClient

from auth.client_registry import ClientRegistry
from auth.oauth_server import OAuthServer, PendingAuth
from auth.token_store import MemoryTokenStore, TokenData
from auth.x_oauth2 import X_AUTHORIZE_URL, TokenResponse, generate_code_challenge


def _build_oauth_server(*, exchange_code_fn=None, refresh_token_fn=None):
    async def _default_exchange(**kwargs):
        del kwargs
        return TokenResponse(
            access_token="x-access-token",
            refresh_token="x-refresh-token",
            expires_in=7200,
            expires_at=time.time() + 7200,
            scope="tweet.read",
        )

    async def _default_refresh(**kwargs):
        del kwargs
        return TokenResponse(
            access_token="x-access-token-refreshed",
            refresh_token="x-refresh-token-refreshed",
            expires_in=7200,
            expires_at=time.time() + 7200,
            scope="tweet.read",
        )

    store = MemoryTokenStore()
    registry = ClientRegistry()
    oauth = OAuthServer(
        public_url="https://xmcp.example.com",
        x_client_id="x-client",
        x_client_secret="x-secret",
        token_store=store,
        client_registry=registry,
        exchange_code_fn=exchange_code_fn or _default_exchange,
        refresh_token_fn=refresh_token_fn or _default_refresh,
    )

    mcp = FastMCP(name="test")
    oauth.mount_routes(mcp)
    app = mcp.http_app(path="/mcp", transport="streamable-http")
    return oauth, TestClient(app), registry, store


def _prepare_authorization_code(test_client, oauth: OAuthServer, registry: ClientRegistry):
    client = registry.register(
        client_name="Claude",
        redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
    )

    code_verifier = "verifier-123"
    authorize_response = test_client.get(
        "/authorize",
        params={
            "client_id": client.client_id,
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "code_challenge": generate_code_challenge(code_verifier),
            "code_challenge_method": "S256",
            "state": "original-state",
            "scope": "tweet.read users.read",
        },
        follow_redirects=False,
    )
    x_location = authorize_response.headers["location"]
    x_query = urllib.parse.parse_qs(urllib.parse.urlparse(x_location).query)
    x_state = x_query["state"][0]

    callback_response = test_client.get(
        "/x/callback",
        params={"code": "x-code-123", "state": x_state},
        follow_redirects=False,
    )
    client_redirect = callback_response.headers["location"]
    client_query = urllib.parse.parse_qs(urllib.parse.urlparse(client_redirect).query)

    return {
        "client": client,
        "code_verifier": code_verifier,
        "authorization_code": client_query["code"][0],
    }


def test_metadata_endpoint_returns_json() -> None:
    _, test_client, _, _ = _build_oauth_server()

    response = test_client.get("/.well-known/oauth-authorization-server")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")


def test_metadata_required_fields() -> None:
    _, test_client, _, _ = _build_oauth_server()

    payload = test_client.get("/.well-known/oauth-authorization-server").json()

    required = {
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "registration_endpoint",
        "response_types_supported",
        "grant_types_supported",
        "token_endpoint_auth_methods_supported",
        "code_challenge_methods_supported",
        "scopes_supported",
    }
    assert required.issubset(payload.keys())


def test_metadata_uses_public_url() -> None:
    _, test_client, _, _ = _build_oauth_server()

    payload = test_client.get("/.well-known/oauth-authorization-server").json()

    assert payload["issuer"] == "https://xmcp.example.com"
    assert payload["authorization_endpoint"] == "https://xmcp.example.com/authorize"
    assert payload["token_endpoint"] == "https://xmcp.example.com/token"


def test_metadata_supports_pkce_s256() -> None:
    _, test_client, _, _ = _build_oauth_server()

    payload = test_client.get("/.well-known/oauth-authorization-server").json()

    assert "S256" in payload["code_challenge_methods_supported"]


def test_register_success() -> None:
    _, test_client, _, _ = _build_oauth_server()

    response = test_client.post(
        "/register",
        json={
            "client_name": "Claude",
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["client_id"]
    assert payload["client_secret"]
    assert payload["client_name"] == "Claude"


def test_register_missing_redirect_uris() -> None:
    _, test_client, _, _ = _build_oauth_server()

    response = test_client.post("/register", json={"client_name": "Claude"})

    assert response.status_code == 400


def test_register_invalid_redirect_uri() -> None:
    _, test_client, _, _ = _build_oauth_server()

    response = test_client.post(
        "/register",
        json={"client_name": "Claude", "redirect_uris": ["https://example.com/callback"]},
    )

    assert response.status_code == 400


def test_register_claude_callback_allowed() -> None:
    _, test_client, _, _ = _build_oauth_server()

    response = test_client.post(
        "/register",
        json={
            "client_name": "Claude",
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
        },
    )

    assert response.status_code == 201


def test_register_localhost_callback_allowed() -> None:
    _, test_client, _, _ = _build_oauth_server()

    response = test_client.post(
        "/register",
        json={"client_name": "Inspector", "redirect_uris": ["http://localhost:6274/callback"]},
    )

    assert response.status_code == 201


def test_authorize_redirects_to_x() -> None:
    oauth, test_client, registry, _ = _build_oauth_server()
    client = registry.register("Claude", ["https://claude.ai/api/mcp/auth_callback"])

    response = test_client.get(
        "/authorize",
        params={
            "client_id": client.client_id,
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "code_challenge": generate_code_challenge("abc"),
            "code_challenge_method": "S256",
            "state": "state-123",
            "scope": "tweet.read",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"].startswith(X_AUTHORIZE_URL)
    assert oauth.pending_auth


def test_authorize_includes_pkce() -> None:
    _, test_client, registry, _ = _build_oauth_server()
    client = registry.register("Claude", ["https://claude.ai/api/mcp/auth_callback"])

    response = test_client.get(
        "/authorize",
        params={
            "client_id": client.client_id,
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "code_challenge": generate_code_challenge("abc"),
            "code_challenge_method": "S256",
            "state": "state-123",
            "scope": "tweet.read",
        },
        follow_redirects=False,
    )

    query = urllib.parse.parse_qs(urllib.parse.urlparse(response.headers["location"]).query)
    assert "code_challenge" in query
    assert query["code_challenge_method"] == ["S256"]


def test_authorize_stores_pending_state() -> None:
    oauth, test_client, registry, _ = _build_oauth_server()
    client = registry.register("Claude", ["https://claude.ai/api/mcp/auth_callback"])

    response = test_client.get(
        "/authorize",
        params={
            "client_id": client.client_id,
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "code_challenge": generate_code_challenge("abc"),
            "code_challenge_method": "S256",
            "state": "state-123",
            "scope": "tweet.read",
        },
        follow_redirects=False,
    )

    x_state = urllib.parse.parse_qs(urllib.parse.urlparse(response.headers["location"]).query)["state"][0]
    pending = oauth.pending_auth[x_state]
    assert pending.client_id == client.client_id
    assert pending.original_state == "state-123"


def test_authorize_invalid_client_id() -> None:
    _, test_client, _, _ = _build_oauth_server()

    response = test_client.get(
        "/authorize",
        params={
            "client_id": "unknown",
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "code_challenge": generate_code_challenge("abc"),
            "code_challenge_method": "S256",
            "state": "state-123",
            "scope": "tweet.read",
        },
    )

    assert response.status_code == 400


def test_authorize_invalid_redirect_uri() -> None:
    _, test_client, registry, _ = _build_oauth_server()
    client = registry.register("Claude", ["https://claude.ai/api/mcp/auth_callback"])

    response = test_client.get(
        "/authorize",
        params={
            "client_id": client.client_id,
            "redirect_uri": "https://example.com/callback",
            "code_challenge": generate_code_challenge("abc"),
            "code_challenge_method": "S256",
            "state": "state-123",
            "scope": "tweet.read",
        },
    )

    assert response.status_code == 400


def test_pending_auth_expires() -> None:
    oauth, test_client, registry, _ = _build_oauth_server()
    oauth.pending_auth["expired"] = PendingAuth(
        client_id="stale",
        redirect_uri="https://claude.ai/api/mcp/auth_callback",
        code_challenge="stale",
        original_state="stale",
        x_code_verifier="stale",
        created_at=time.time() - 9999,
    )
    client = registry.register("Claude", ["https://claude.ai/api/mcp/auth_callback"])

    response = test_client.get(
        "/authorize",
        params={
            "client_id": client.client_id,
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "code_challenge": generate_code_challenge("abc"),
            "code_challenge_method": "S256",
            "state": "state-123",
            "scope": "tweet.read",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "expired" not in oauth.pending_auth


def test_x_callback_exchanges_code() -> None:
    seen = {}

    async def exchange_code_fn(**kwargs):
        seen.update(kwargs)
        return TokenResponse(
            access_token="x-access-token",
            refresh_token="x-refresh-token",
            expires_in=7200,
            expires_at=time.time() + 7200,
            scope="tweet.read",
        )

    oauth, test_client, registry, _ = _build_oauth_server(exchange_code_fn=exchange_code_fn)
    client = registry.register("Claude", ["https://claude.ai/api/mcp/auth_callback"])

    response = test_client.get(
        "/authorize",
        params={
            "client_id": client.client_id,
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "code_challenge": generate_code_challenge("abc"),
            "code_challenge_method": "S256",
            "state": "state-123",
            "scope": "tweet.read",
        },
        follow_redirects=False,
    )
    x_state = urllib.parse.parse_qs(urllib.parse.urlparse(response.headers["location"]).query)["state"][0]

    callback = test_client.get(
        "/x/callback",
        params={"code": "x-code-123", "state": x_state},
        follow_redirects=False,
    )

    assert callback.status_code == 302
    assert seen["code"] == "x-code-123"


def test_x_callback_stores_tokens() -> None:
    oauth, test_client, registry, store = _build_oauth_server()
    client = registry.register("Claude", ["https://claude.ai/api/mcp/auth_callback"])

    response = test_client.get(
        "/authorize",
        params={
            "client_id": client.client_id,
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "code_challenge": generate_code_challenge("abc"),
            "code_challenge_method": "S256",
            "state": "state-123",
            "scope": "tweet.read",
        },
        follow_redirects=False,
    )
    x_state = urllib.parse.parse_qs(urllib.parse.urlparse(response.headers["location"]).query)["state"][0]

    callback = test_client.get(
        "/x/callback",
        params={"code": "x-code-123", "state": x_state},
        follow_redirects=False,
    )

    assert callback.status_code == 302
    pending_code = next(iter(oauth.pending_codes.values()))

    token_data = store._tokens[pending_code.session_id]
    assert token_data.x_access_token == "x-access-token"


def test_x_callback_redirects_to_client() -> None:
    _, test_client, registry, _ = _build_oauth_server()
    client = registry.register("Claude", ["https://claude.ai/api/mcp/auth_callback"])

    response = test_client.get(
        "/authorize",
        params={
            "client_id": client.client_id,
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "code_challenge": generate_code_challenge("abc"),
            "code_challenge_method": "S256",
            "state": "client-state",
            "scope": "tweet.read",
        },
        follow_redirects=False,
    )
    x_state = urllib.parse.parse_qs(urllib.parse.urlparse(response.headers["location"]).query)["state"][0]

    callback = test_client.get(
        "/x/callback",
        params={"code": "x-code-123", "state": x_state},
        follow_redirects=False,
    )

    redirected = urllib.parse.urlparse(callback.headers["location"])
    query = urllib.parse.parse_qs(redirected.query)
    assert redirected.scheme == "https"
    assert redirected.netloc == "claude.ai"
    assert query["code"]
    assert query["state"] == ["client-state"]


def test_x_callback_invalid_state() -> None:
    _, test_client, _, _ = _build_oauth_server()

    callback = test_client.get(
        "/x/callback",
        params={"code": "x-code-123", "state": "missing"},
    )

    assert callback.status_code == 400


def test_x_callback_x_error() -> None:
    async def exchange_code_fn(**kwargs):
        del kwargs
        raise RuntimeError("boom")

    _, test_client, registry, _ = _build_oauth_server(exchange_code_fn=exchange_code_fn)
    client = registry.register("Claude", ["https://claude.ai/api/mcp/auth_callback"])

    response = test_client.get(
        "/authorize",
        params={
            "client_id": client.client_id,
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "code_challenge": generate_code_challenge("abc"),
            "code_challenge_method": "S256",
            "state": "state-123",
            "scope": "tweet.read",
        },
        follow_redirects=False,
    )
    x_state = urllib.parse.parse_qs(urllib.parse.urlparse(response.headers["location"]).query)["state"][0]

    callback = test_client.get(
        "/x/callback",
        params={"code": "x-code-123", "state": x_state},
    )

    assert callback.status_code == 502


def test_token_exchange_success() -> None:
    oauth, test_client, registry, _ = _build_oauth_server()
    auth = _prepare_authorization_code(test_client, oauth, registry)

    response = test_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": auth["client"].client_id,
            "client_secret": auth["client"].client_secret,
            "code": auth["authorization_code"],
            "code_verifier": auth["code_verifier"],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["access_token"]
    assert payload["refresh_token"]


def test_token_exchange_invalid_code() -> None:
    _, test_client, registry, _ = _build_oauth_server()
    client = registry.register("Claude", ["https://claude.ai/api/mcp/auth_callback"])

    response = test_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "code": "missing",
            "code_verifier": "verifier",
        },
    )

    assert response.status_code == 400


def test_token_exchange_expired_code() -> None:
    oauth, test_client, registry, _ = _build_oauth_server()
    auth = _prepare_authorization_code(test_client, oauth, registry)
    oauth.pending_codes[auth["authorization_code"]].created_at = time.time() - 120

    response = test_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": auth["client"].client_id,
            "client_secret": auth["client"].client_secret,
            "code": auth["authorization_code"],
            "code_verifier": auth["code_verifier"],
        },
    )

    assert response.status_code == 400


def test_token_exchange_invalid_pkce() -> None:
    oauth, test_client, registry, _ = _build_oauth_server()
    auth = _prepare_authorization_code(test_client, oauth, registry)

    response = test_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": auth["client"].client_id,
            "client_secret": auth["client"].client_secret,
            "code": auth["authorization_code"],
            "code_verifier": "wrong-verifier",
        },
    )

    assert response.status_code == 400


def test_token_exchange_code_single_use() -> None:
    oauth, test_client, registry, _ = _build_oauth_server()
    auth = _prepare_authorization_code(test_client, oauth, registry)

    first = test_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": auth["client"].client_id,
            "client_secret": auth["client"].client_secret,
            "code": auth["authorization_code"],
            "code_verifier": auth["code_verifier"],
        },
    )
    second = test_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": auth["client"].client_id,
            "client_secret": auth["client"].client_secret,
            "code": auth["authorization_code"],
            "code_verifier": auth["code_verifier"],
        },
    )

    assert first.status_code == 200
    assert second.status_code == 400


def test_token_exchange_client_secret_basic() -> None:
    oauth, test_client, registry, _ = _build_oauth_server()
    auth = _prepare_authorization_code(test_client, oauth, registry)
    creds = f"{auth['client'].client_id}:{auth['client'].client_secret}".encode()

    response = test_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": auth["authorization_code"],
            "code_verifier": auth["code_verifier"],
        },
        headers={"Authorization": f"Basic {base64.b64encode(creds).decode()}"},
    )

    assert response.status_code == 200


def test_token_exchange_client_secret_post() -> None:
    oauth, test_client, registry, _ = _build_oauth_server()
    auth = _prepare_authorization_code(test_client, oauth, registry)

    response = test_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": auth["client"].client_id,
            "client_secret": auth["client"].client_secret,
            "code": auth["authorization_code"],
            "code_verifier": auth["code_verifier"],
        },
    )

    assert response.status_code == 200


def test_token_refresh_success() -> None:
    oauth, test_client, registry, store = _build_oauth_server()
    auth = _prepare_authorization_code(test_client, oauth, registry)

    exchanged = test_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": auth["client"].client_id,
            "client_secret": auth["client"].client_secret,
            "code": auth["authorization_code"],
            "code_verifier": auth["code_verifier"],
        },
    )
    refresh_token = exchanged.json()["refresh_token"]

    session_access = exchanged.json()["access_token"]
    session = oauth.sessions_by_access[session_access]
    store._tokens[session.session_id] = TokenData(
        x_access_token="expired",
        x_refresh_token="refresh-x",
        expires_at=time.time() - 1,
    )

    refreshed = test_client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": auth["client"].client_id,
            "client_secret": auth["client"].client_secret,
            "refresh_token": refresh_token,
        },
    )

    assert refreshed.status_code == 200
    payload = refreshed.json()
    assert payload["access_token"] != session_access


def test_token_refresh_invalid() -> None:
    _, test_client, registry, _ = _build_oauth_server()
    client = registry.register("Claude", ["https://claude.ai/api/mcp/auth_callback"])

    response = test_client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "refresh_token": "missing",
        },
    )

    assert response.status_code == 400


def test_token_refresh_revoked_x_token_requires_reauth() -> None:
    async def refresh_token_fn(**kwargs):
        del kwargs
        raise RuntimeError("invalid_grant")

    oauth, test_client, registry, store = _build_oauth_server(refresh_token_fn=refresh_token_fn)
    auth = _prepare_authorization_code(test_client, oauth, registry)

    exchanged = test_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": auth["client"].client_id,
            "client_secret": auth["client"].client_secret,
            "code": auth["authorization_code"],
            "code_verifier": auth["code_verifier"],
        },
    )
    session_access = exchanged.json()["access_token"]
    session_refresh = exchanged.json()["refresh_token"]
    session = oauth.sessions_by_access[session_access]
    store._tokens[session.session_id] = TokenData(
        x_access_token="expired",
        x_refresh_token="refresh-x",
        expires_at=time.time() - 1,
    )

    refreshed = test_client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": auth["client"].client_id,
            "client_secret": auth["client"].client_secret,
            "refresh_token": session_refresh,
        },
    )

    assert refreshed.status_code == 401
    payload = refreshed.json()
    assert payload["error"] == "invalid_grant"
    assert "re-auth required" in payload["error_description"]
