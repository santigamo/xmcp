from tests.oauth_helpers import _build_oauth_server


def test_register_success() -> None:
    _, test_client, _ = _build_oauth_server()

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
    _, test_client, _ = _build_oauth_server()

    response = test_client.post("/register", json={"client_name": "Claude"})

    assert response.status_code == 400


def test_register_invalid_redirect_uri() -> None:
    _, test_client, _ = _build_oauth_server()

    response = test_client.post(
        "/register",
        json={"client_name": "Claude", "redirect_uris": ["https://example.com/callback"]},
    )

    assert response.status_code == 400


def test_register_claude_callback_allowed() -> None:
    _, test_client, _ = _build_oauth_server()

    response = test_client.post(
        "/register",
        json={
            "client_name": "Claude",
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
        },
    )

    assert response.status_code == 201


def test_register_localhost_callback_allowed() -> None:
    _, test_client, _ = _build_oauth_server()

    response = test_client.post(
        "/register",
        json={"client_name": "Inspector", "redirect_uris": ["http://localhost:6274/callback"]},
    )

    assert response.status_code == 201
