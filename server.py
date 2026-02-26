from __future__ import annotations

import os
from typing import TYPE_CHECKING

import httpx
from pydantic import AnyHttpUrl

from xmcp import openapi as openapi_helpers
from xmcp.constants import (
    ANNOTATION_OVERRIDE_KEYS as _ANNOTATION_OVERRIDE_KEYS,
    ANNOTATION_OVERRIDES_FILE as _ANNOTATION_OVERRIDES_FILE,
    APP_VERSION as _APP_VERSION,
    AUTH_MODE as _AUTH_MODE,
    HTTP_METHODS as _HTTP_METHODS,
    LOGGER,
)
from xmcp.env import (
    _get_env_int,
    is_truthy as _is_truthy,
    load_env,
    parse_csv_env,
    setup_logging,
    validate_env,
)
from xmcp.http import (
    RetryTransport,
    _friendly_error_message as __friendly_error_message,
    _seconds_until_reset as __seconds_until_reset,
    handle_rate_limits,
    transform_error_response,
)
from xmcp.mcp_app import (
    CURRENT_MCP_BEARER_TOKEN as _CURRENT_MCP_BEARER_TOKEN,
    UnauthorizedRequestError as _UnauthorizedRequestError,
    build_session_token_verifier,
    capture_mcp_bearer_token_from_context,
    extract_bearer_token as _extract_bearer_token,
    inject_oauth2_access_token,
    mount_health_route,
)
from xmcp.openapi import (
    collect_comma_params,
    filter_openapi_spec,
    load_annotation_overrides as _load_annotation_overrides,
    load_openapi_spec,
    print_tool_list,
    should_exclude_operation as _should_exclude_operation,
    should_join_query_param as _should_join_query_param,
)

if TYPE_CHECKING:
    from fastmcp import FastMCP


APP_VERSION = _APP_VERSION
AUTH_MODE = _AUTH_MODE
ANNOTATION_OVERRIDE_KEYS = _ANNOTATION_OVERRIDE_KEYS
ANNOTATION_OVERRIDES_FILE = _ANNOTATION_OVERRIDES_FILE
HTTP_METHODS = _HTTP_METHODS
CURRENT_MCP_BEARER_TOKEN = _CURRENT_MCP_BEARER_TOKEN
UnauthorizedRequestError = _UnauthorizedRequestError
extract_bearer_token = _extract_bearer_token
load_annotation_overrides = _load_annotation_overrides
should_exclude_operation = _should_exclude_operation
should_join_query_param = _should_join_query_param
is_truthy = _is_truthy
_friendly_error_message = __friendly_error_message
_seconds_until_reset = __seconds_until_reset

ANNOTATION_OVERRIDES = dict(openapi_helpers.ANNOTATION_OVERRIDES)


def add_safety_annotations(route, component) -> None:
    openapi_helpers.add_safety_annotations(
        route,
        component,
        overrides=ANNOTATION_OVERRIDES,
    )


def create_mcp() -> "FastMCP":
    from fastmcp import FastMCP
    from auth.client_registry import ClientRegistry
    from auth.oauth_server import OAuthServer
    from auth.token_store import FileTokenStore
    from fastmcp.server.auth import RemoteAuthProvider

    load_env()
    debug_enabled = setup_logging()
    validate_env()

    base_url = os.getenv("X_API_BASE_URL", "https://api.x.com")
    timeout = float(os.getenv("X_API_TIMEOUT", "30"))
    max_retries = _get_env_int("X_API_MAX_RETRIES", 2)

    token_store = FileTokenStore(os.getenv("X_TOKEN_STORE_PATH", ".tokens.json"))
    client_registry = ClientRegistry()
    scopes = os.getenv(
        "X_OAUTH2_SCOPES",
        "tweet.read tweet.write users.read offline.access",
    ).split()
    cors_origins = parse_csv_env("X_CORS_ORIGINS")
    oauth_server = OAuthServer(
        public_url=os.getenv("X_MCP_PUBLIC_URL", ""),
        x_client_id=os.getenv("X_OAUTH2_CLIENT_ID", ""),
        x_client_secret=os.getenv("X_OAUTH2_CLIENT_SECRET", ""),
        token_store=token_store,
        client_registry=client_registry,
        scopes=scopes,
        cors_origins=cors_origins,
    )

    public_url = AnyHttpUrl(os.getenv("X_MCP_PUBLIC_URL", "").strip())
    session_verifier = build_session_token_verifier(oauth_server, base_url=str(public_url))
    auth_provider = RemoteAuthProvider(
        token_verifier=session_verifier,
        authorization_servers=[public_url],
        base_url=public_url,
        resource_name="xmcp",
    )

    spec = load_openapi_spec()
    filtered_spec = filter_openapi_spec(spec)
    comma_params = collect_comma_params(filtered_spec)
    print_tool_list(filtered_spec)

    async def normalize_query_params(request: httpx.Request) -> None:
        if not comma_params:
            return
        params = list(request.url.params.multi_items())
        grouped: dict[str, list[str]] = {}
        ordered: list[str] = []
        normalized: list[tuple[str, str]] = []

        for key, value in params:
            if key in comma_params:
                if key not in grouped:
                    ordered.append(key)
                grouped.setdefault(key, []).append(value)
            else:
                normalized.append((key, value))

        if not grouped:
            return

        for key in ordered:
            values: list[str] = []
            for raw in grouped[key]:
                for part in raw.split(","):
                    part = part.strip()
                    if part and part not in values:
                        values.append(part)
            if values:
                normalized.append((key, ",".join(values)))

        request.url = request.url.copy_with(params=normalized)

    b3_flags = os.getenv("X_B3_FLAGS", "1")
    bearer_token = os.getenv("X_BEARER_TOKEN", "").strip() or None
    if bearer_token:
        LOGGER.warning(
            "X_BEARER_TOKEN is set — read-only requests (GET/HEAD/OPTIONS) will use "
            "app-only Bearer Token instead of OAuth 2.0 user context. "
            "This is a workaround for the X API 402 bug. "
            "Remove X_BEARER_TOKEN once X fixes the issue."
        )

    async def capture_mcp_bearer_token(request: httpx.Request) -> None:
        del request
        capture_mcp_bearer_token_from_context()

    async def sign_request(request: httpx.Request) -> None:
        request.headers["X-B3-Flags"] = b3_flags
        if bearer_token and request.method in ("GET", "HEAD", "OPTIONS"):
            request.headers["Authorization"] = f"Bearer {bearer_token}"
            return
        await inject_oauth2_access_token(request, oauth_server)

    async def log_request(request: httpx.Request) -> None:
        if not debug_enabled:
            return
        LOGGER.info("X API request %s %s", request.method, request.url)

    async def log_response(response: httpx.Response) -> None:
        if not debug_enabled:
            return
        LOGGER.info(
            "X API response %s %s -> %s",
            response.request.method,
            response.request.url,
            response.status_code,
        )
        if response.status_code >= 400:
            transaction_id = response.headers.get("x-transaction-id")
            if transaction_id:
                LOGGER.warning("X API x-transaction-id: %s", transaction_id)
            body = await response.aread()
            text = body.decode("utf-8", errors="replace")
            if len(text) > 1000:
                text = text[:1000] + "...<truncated>"
            LOGGER.warning("X API error body: %s", text)

    request_hooks: list = [
        normalize_query_params,
        capture_mcp_bearer_token,
        sign_request,
        log_request,
    ]

    base_transport = httpx.AsyncHTTPTransport()
    retry_transport = RetryTransport(
        base_transport,
        max_retries=max_retries,
        logger=LOGGER,
    )
    client = httpx.AsyncClient(
        base_url=base_url,
        headers={},
        timeout=timeout,
        transport=retry_transport,
        event_hooks={
            "request": request_hooks,
            "response": [handle_rate_limits, transform_error_response, log_response],
        },
    )
    mcp = FastMCP.from_openapi(
        openapi_spec=filtered_spec,
        client=client,
        mcp_component_fn=add_safety_annotations,
        name="X API MCP",
        auth=auth_provider,
    )
    oauth_server.mount_routes(mcp)
    setattr(mcp, "_oauth_server", oauth_server)
    mount_health_route(mcp)
    return mcp


def main() -> None:
    host = os.getenv("MCP_HOST", "127.0.0.1")
    port = int(os.getenv("MCP_PORT", "8000"))
    mcp = create_mcp()
    mcp.run(transport="streamable-http", host=host, port=port)


if __name__ == "__main__":
    main()
