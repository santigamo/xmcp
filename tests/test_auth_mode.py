import server


_MINIMAL_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "X API", "version": "1.0.0"},
    "paths": {
        "/2/users/me": {
            "get": {
                "operationId": "getUsersMe",
                "responses": {"200": {"description": "ok"}},
            }
        }
    },
}


def _prepare_common_monkeypatches(monkeypatch) -> None:
    monkeypatch.setattr(server, "load_env", lambda: None)
    monkeypatch.setattr(server, "setup_logging", lambda: False)
    monkeypatch.setattr(server, "load_openapi_spec", lambda: _MINIMAL_SPEC)
    monkeypatch.setattr(server, "print_tool_list", lambda _spec: None)
    monkeypatch.delenv("X_API_TOOL_ALLOWLIST", raising=False)
    monkeypatch.delenv("X_API_TOOL_DENYLIST", raising=False)
    monkeypatch.delenv("X_API_TOOL_TAGS", raising=False)
    monkeypatch.setenv("X_OAUTH2_CLIENT_ID", "x-client")
    monkeypatch.setenv("X_OAUTH2_CLIENT_SECRET", "x-secret")
    monkeypatch.setenv("X_MCP_PUBLIC_URL", "https://xmcp.example.com")


def test_create_mcp_mounts_oauth_routes_by_default(monkeypatch) -> None:
    _prepare_common_monkeypatches(monkeypatch)

    mcp = server.create_mcp()

    assert hasattr(mcp, "_oauth_server")
    paths = {route.path for route in mcp._additional_http_routes}
    assert "/.well-known/oauth-authorization-server" in paths
    assert "/register" in paths
    assert "/authorize" in paths
    assert "/x/callback" in paths
    assert "/token" in paths


def test_create_mcp_enables_fastmcp_auth(monkeypatch) -> None:
    _prepare_common_monkeypatches(monkeypatch)

    mcp = server.create_mcp()

    assert mcp.auth is not None


def test_validate_env_missing_vars(monkeypatch) -> None:
    monkeypatch.delenv("X_OAUTH2_CLIENT_ID", raising=False)
    monkeypatch.delenv("X_OAUTH2_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("X_MCP_PUBLIC_URL", raising=False)

    try:
        server.validate_env()
        assert False, "Expected RuntimeError for missing oauth2 env vars"
    except RuntimeError as error:
        message = str(error)
        assert "X_OAUTH2_CLIENT_ID" in message
        assert "X_OAUTH2_CLIENT_SECRET" in message
        assert "X_MCP_PUBLIC_URL" in message


def test_validate_env_accepts_required_oauth2_vars(monkeypatch) -> None:
    monkeypatch.setenv("X_OAUTH2_CLIENT_ID", "x-client")
    monkeypatch.setenv("X_OAUTH2_CLIENT_SECRET", "x-secret")
    monkeypatch.setenv("X_MCP_PUBLIC_URL", "https://xmcp.example.com")

    server.validate_env()


def test_validate_env_requires_https_public_url(monkeypatch) -> None:
    monkeypatch.setenv("X_OAUTH2_CLIENT_ID", "x-client")
    monkeypatch.setenv("X_OAUTH2_CLIENT_SECRET", "x-secret")
    monkeypatch.setenv("X_MCP_PUBLIC_URL", "http://xmcp.example.com")

    try:
        server.validate_env()
        assert False, "Expected RuntimeError when X_MCP_PUBLIC_URL is not https."
    except RuntimeError as error:
        assert "HTTPS" in str(error)


def test_validate_env_requires_offline_access_scope(monkeypatch) -> None:
    monkeypatch.setenv("X_OAUTH2_CLIENT_ID", "x-client")
    monkeypatch.setenv("X_OAUTH2_CLIENT_SECRET", "x-secret")
    monkeypatch.setenv("X_MCP_PUBLIC_URL", "https://xmcp.example.com")
    monkeypatch.setenv("X_OAUTH2_SCOPES", "tweet.read users.read")

    try:
        server.validate_env()
        assert False, "Expected RuntimeError when offline.access is missing."
    except RuntimeError as error:
        assert "offline.access" in str(error)
