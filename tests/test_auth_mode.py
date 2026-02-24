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


class _DummyOAuth1Client:
    def sign(self, url: str, http_method: str, body=None, headers=None):
        return url, headers or {}, body


def _prepare_common_monkeypatches(monkeypatch) -> None:
    monkeypatch.setattr(server, "load_env", lambda: None)
    monkeypatch.setattr(server, "setup_logging", lambda: False)
    monkeypatch.setattr(server, "load_openapi_spec", lambda: _MINIMAL_SPEC)
    monkeypatch.setattr(server, "print_tool_list", lambda _spec: None)
    monkeypatch.delenv("X_API_TOOL_ALLOWLIST", raising=False)
    monkeypatch.delenv("X_API_TOOL_DENYLIST", raising=False)
    monkeypatch.delenv("X_API_TOOL_TAGS", raising=False)


def test_default_auth_mode_is_oauth1(monkeypatch) -> None:
    monkeypatch.delenv("X_AUTH_MODE", raising=False)

    assert server.get_auth_mode() == "oauth1"


def test_oauth2_remote_skips_browser_flow(monkeypatch) -> None:
    _prepare_common_monkeypatches(monkeypatch)
    monkeypatch.setenv("X_AUTH_MODE", "oauth2-remote")
    monkeypatch.setenv("X_OAUTH2_CLIENT_ID", "x-client")
    monkeypatch.setenv("X_OAUTH2_CLIENT_SECRET", "x-secret")
    monkeypatch.setenv("X_MCP_PUBLIC_URL", "https://xmcp.example.com")

    def _fail_if_called():
        raise AssertionError("OAuth1 flow should not run in oauth2-remote mode")

    monkeypatch.setattr(server, "build_oauth1_client", _fail_if_called)

    mcp = server.create_mcp()

    assert hasattr(mcp, "_oauth_server")


def test_oauth2_remote_mounts_endpoints(monkeypatch) -> None:
    _prepare_common_monkeypatches(monkeypatch)
    monkeypatch.setenv("X_AUTH_MODE", "oauth2-remote")
    monkeypatch.setenv("X_OAUTH2_CLIENT_ID", "x-client")
    monkeypatch.setenv("X_OAUTH2_CLIENT_SECRET", "x-secret")
    monkeypatch.setenv("X_MCP_PUBLIC_URL", "https://xmcp.example.com")

    mcp = server.create_mcp()

    paths = {route.path for route in mcp._additional_http_routes}
    assert "/.well-known/oauth-authorization-server" in paths
    assert "/register" in paths
    assert "/authorize" in paths
    assert "/x/callback" in paths
    assert "/token" in paths


def test_validate_env_missing_vars(monkeypatch) -> None:
    monkeypatch.delenv("X_OAUTH2_CLIENT_ID", raising=False)
    monkeypatch.delenv("X_OAUTH2_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("X_MCP_PUBLIC_URL", raising=False)

    try:
        server.validate_env("oauth2-remote")
        assert False, "Expected RuntimeError for missing oauth2 env vars"
    except RuntimeError as error:
        message = str(error)
        assert "X_OAUTH2_CLIENT_ID" in message
        assert "X_OAUTH2_CLIENT_SECRET" in message
        assert "X_MCP_PUBLIC_URL" in message


def test_validate_env_oauth1_minimal(monkeypatch) -> None:
    monkeypatch.setenv("X_OAUTH_CONSUMER_KEY", "key")
    monkeypatch.setenv("X_OAUTH_CONSUMER_SECRET", "secret")
    monkeypatch.delenv("X_BEARER_TOKEN", raising=False)

    server.validate_env("oauth1")


def test_oauth1_mode_still_builds_oauth_client(monkeypatch) -> None:
    _prepare_common_monkeypatches(monkeypatch)
    monkeypatch.setenv("X_AUTH_MODE", "oauth1")
    monkeypatch.setenv("X_OAUTH_CONSUMER_KEY", "key")
    monkeypatch.setenv("X_OAUTH_CONSUMER_SECRET", "secret")
    monkeypatch.setattr(server, "build_oauth1_client", lambda: _DummyOAuth1Client())

    mcp = server.create_mcp()

    assert not hasattr(mcp, "_oauth_server")
