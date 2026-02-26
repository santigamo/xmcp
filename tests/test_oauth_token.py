import base64
import time

from auth import signed_token
from tests.oauth_helpers import _build_oauth_server, _prepare_authorization_code


def test_token_exchange_success() -> None:
    oauth, test_client, registry = _build_oauth_server()
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
    _, test_client, registry = _build_oauth_server()
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
    oauth, test_client, registry = _build_oauth_server()
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
    oauth, test_client, registry = _build_oauth_server()
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
    oauth, test_client, registry = _build_oauth_server()
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
    oauth, test_client, registry = _build_oauth_server()
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
    oauth, test_client, registry = _build_oauth_server()
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


def test_token_exchange_embeds_x_tokens() -> None:
    """Session tokens contain the X access/refresh tokens."""
    oauth, test_client, registry = _build_oauth_server()
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

    payload = signed_token.decode(response.json()["access_token"], oauth._session_key)
    assert payload["xat"] == "x-access-token"
    assert payload["xrt"] == "x-refresh-token"
    assert payload["typ"] == "a"


def test_token_refresh_success() -> None:
    oauth, test_client, registry = _build_oauth_server()
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
    old_access = exchanged.json()["access_token"]

    # Forge a refresh token with expired X tokens to trigger X refresh
    expired_refresh = signed_token.encode(
        {
            "xat": "expired",
            "xrt": "x-refresh-token",
            "xexp": time.time() - 1,
            "cid": auth["client"].client_id,
            "typ": "r",
            "iat": time.time(),
        },
        oauth._session_key,
    )

    refreshed = test_client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": auth["client"].client_id,
            "client_secret": auth["client"].client_secret,
            "refresh_token": expired_refresh,
        },
    )

    assert refreshed.status_code == 200
    payload = refreshed.json()
    assert payload["access_token"] != old_access
    # Verify the new token has refreshed X tokens
    decoded = signed_token.decode(payload["access_token"], oauth._session_key)
    assert decoded["xat"] == "x-access-token-refreshed"


def test_token_refresh_invalid() -> None:
    _, test_client, registry = _build_oauth_server()
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

    oauth, test_client, registry = _build_oauth_server(refresh_token_fn=refresh_token_fn)
    auth = _prepare_authorization_code(test_client, oauth, registry)

    # Forge a refresh token with expired X tokens
    expired_refresh = signed_token.encode(
        {
            "xat": "expired",
            "xrt": "x-refresh-revoked",
            "xexp": time.time() - 1,
            "cid": auth["client"].client_id,
            "typ": "r",
            "iat": time.time(),
        },
        oauth._session_key,
    )

    refreshed = test_client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": auth["client"].client_id,
            "client_secret": auth["client"].client_secret,
            "refresh_token": expired_refresh,
        },
    )

    assert refreshed.status_code == 401
    payload = refreshed.json()
    assert payload["error"] == "invalid_grant"
    assert "re-auth required" in payload["error_description"]
