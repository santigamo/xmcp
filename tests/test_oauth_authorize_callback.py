import time
import urllib.parse

from auth.models import PendingAuth
from auth.x_oauth2 import X_AUTHORIZE_URL, TokenResponse, generate_code_challenge
from tests.oauth_helpers import _build_oauth_server


def test_authorize_redirects_to_x() -> None:
    oauth, test_client, registry = _build_oauth_server()
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
    _, test_client, registry = _build_oauth_server()
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
    oauth, test_client, registry = _build_oauth_server()
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

    x_state = urllib.parse.parse_qs(urllib.parse.urlparse(response.headers["location"]).query)[
        "state"
    ][0]
    pending = oauth.pending_auth[x_state]
    assert pending.client_id == client.client_id
    assert pending.original_state == "state-123"


def test_authorize_invalid_client_id() -> None:
    _, test_client, _ = _build_oauth_server()

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
    _, test_client, registry = _build_oauth_server()
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
    oauth, test_client, registry = _build_oauth_server()
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

    _, test_client, registry = _build_oauth_server(exchange_code_fn=exchange_code_fn)
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
    x_state = urllib.parse.parse_qs(urllib.parse.urlparse(response.headers["location"]).query)[
        "state"
    ][0]

    callback = test_client.get(
        "/x/callback",
        params={"code": "x-code-123", "state": x_state},
        follow_redirects=False,
    )

    assert callback.status_code == 302
    assert seen["code"] == "x-code-123"


def test_x_callback_embeds_tokens_in_pending_code() -> None:
    oauth, test_client, registry = _build_oauth_server()
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
    x_state = urllib.parse.parse_qs(urllib.parse.urlparse(response.headers["location"]).query)[
        "state"
    ][0]

    callback = test_client.get(
        "/x/callback",
        params={"code": "x-code-123", "state": x_state},
        follow_redirects=False,
    )

    assert callback.status_code == 302
    pending_code = next(iter(oauth.pending_codes.values()))
    assert pending_code.x_access_token == "x-access-token"


def test_x_callback_redirects_to_client() -> None:
    _, test_client, registry = _build_oauth_server()
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
    x_state = urllib.parse.parse_qs(urllib.parse.urlparse(response.headers["location"]).query)[
        "state"
    ][0]

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
    _, test_client, _ = _build_oauth_server()

    callback = test_client.get(
        "/x/callback",
        params={"code": "x-code-123", "state": "missing"},
    )

    assert callback.status_code == 400


def test_x_callback_x_error() -> None:
    async def exchange_code_fn(**kwargs):
        del kwargs
        raise RuntimeError("boom")

    _, test_client, registry = _build_oauth_server(exchange_code_fn=exchange_code_fn)
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
    x_state = urllib.parse.parse_qs(urllib.parse.urlparse(response.headers["location"]).query)[
        "state"
    ][0]

    callback = test_client.get(
        "/x/callback",
        params={"code": "x-code-123", "state": x_state},
    )

    assert callback.status_code == 502
