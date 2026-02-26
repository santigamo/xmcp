import urllib.parse

from auth.x_oauth2 import generate_code_challenge
from tests.oauth_helpers import _build_oauth_server


def _do_callback(test_client, registry):
    """Run authorize + x/callback flow, return the callback response."""
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
    x_state = urllib.parse.parse_qs(
        urllib.parse.urlparse(response.headers["location"]).query
    )["state"][0]
    return test_client.get(
        "/x/callback",
        params={"code": "x-code-123", "state": x_state},
        follow_redirects=False,
    )


def test_allowed_user_id_matching() -> None:
    async def fetch_user_id_fn(access_token):
        return "12345"

    _, test_client, registry, _ = _build_oauth_server(
        allowed_user_id="12345",
        fetch_user_id_fn=fetch_user_id_fn,
    )
    callback = _do_callback(test_client, registry)
    assert callback.status_code == 302


def test_allowed_user_id_rejected() -> None:
    async def fetch_user_id_fn(access_token):
        return "99999"

    _, test_client, registry, _ = _build_oauth_server(
        allowed_user_id="12345",
        fetch_user_id_fn=fetch_user_id_fn,
    )
    callback = _do_callback(test_client, registry)
    assert callback.status_code == 403


def test_allowed_user_id_fetch_fails() -> None:
    async def fetch_user_id_fn(access_token):
        raise RuntimeError("network error")

    _, test_client, registry, _ = _build_oauth_server(
        allowed_user_id="12345",
        fetch_user_id_fn=fetch_user_id_fn,
    )
    callback = _do_callback(test_client, registry)
    assert callback.status_code == 502


def test_no_allowed_user_id_skips_check() -> None:
    """When X_ALLOWED_USER_ID is not set, no user check is performed."""
    _, test_client, registry, _ = _build_oauth_server(allowed_user_id=None)
    callback = _do_callback(test_client, registry)
    assert callback.status_code == 302
