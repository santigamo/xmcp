import asyncio

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


def _build_health_client(monkeypatch):
    monkeypatch.setattr(server, "load_env", lambda: None)
    monkeypatch.setattr(server, "setup_logging", lambda: False)
    monkeypatch.setattr(server, "load_openapi_spec", lambda: _MINIMAL_SPEC)
    monkeypatch.setattr(server, "print_tool_list", lambda _spec: None)
    monkeypatch.setenv("X_AUTH_MODE", "oauth2-remote")
    monkeypatch.setenv("X_OAUTH2_CLIENT_ID", "x-client")
    monkeypatch.setenv("X_OAUTH2_CLIENT_SECRET", "x-secret")
    monkeypatch.setenv("X_MCP_PUBLIC_URL", "https://xmcp.example.com")
    mcp = server.create_mcp()
    app = mcp.http_app(path="/mcp", transport="streamable-http")

    from starlette.testclient import TestClient

    return mcp, TestClient(app)


def test_health_returns_200(monkeypatch) -> None:
    mcp, client = _build_health_client(monkeypatch)

    try:
        response = client.get("/health")
        assert response.status_code == 200
    finally:
        asyncio.run(mcp._client.aclose())


def test_health_response_format(monkeypatch) -> None:
    mcp, client = _build_health_client(monkeypatch)

    try:
        payload = client.get("/health").json()
        assert payload["status"] == "ok"
        assert payload["version"] == "0.1.0"
        assert payload["auth_mode"] == "oauth2-remote"
    finally:
        asyncio.run(mcp._client.aclose())
