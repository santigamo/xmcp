from fastmcp import FastMCP
from starlette.testclient import TestClient

from auth.client_registry import ClientRegistry
from auth.oauth_server import OAuthServer


def _build_client() -> TestClient:
    oauth = OAuthServer(
        public_url="https://xmcp.example.com",
        x_client_id="x-client",
        x_client_secret="x-secret",
        client_registry=ClientRegistry(),
    )
    mcp = FastMCP(name="test")
    oauth.mount_routes(mcp)
    app = mcp.http_app(path="/mcp", transport="streamable-http")
    return TestClient(app)


def test_cors_allows_claude_origin() -> None:
    client = _build_client()

    response = client.get(
        "/.well-known/oauth-authorization-server",
        headers={"Origin": "https://claude.ai"},
    )

    assert response.headers["access-control-allow-origin"] == "https://claude.ai"


def test_cors_blocks_unknown_origin() -> None:
    client = _build_client()

    response = client.get(
        "/.well-known/oauth-authorization-server",
        headers={"Origin": "https://unknown.example"},
    )

    assert "access-control-allow-origin" not in response.headers


def test_cors_preflight_options() -> None:
    client = _build_client()

    response = client.options(
        "/token",
        headers={
            "Origin": "https://claude.ai",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization, Content-Type",
        },
    )

    assert response.status_code == 204
    assert response.headers["access-control-allow-origin"] == "https://claude.ai"
    assert response.headers["access-control-allow-methods"] == "GET, POST, OPTIONS"
