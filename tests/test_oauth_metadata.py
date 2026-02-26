from tests.oauth_helpers import _build_oauth_server


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
