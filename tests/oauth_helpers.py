import time
import urllib.parse

from fastmcp import FastMCP
from starlette.testclient import TestClient

from auth.client_registry import ClientRegistry
from auth.oauth_server import OAuthServer
from auth.token_store import MemoryTokenStore
from auth.x_oauth2 import TokenResponse, generate_code_challenge


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
