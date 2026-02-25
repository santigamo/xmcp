from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import time
from contextvars import ContextVar
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx
from mcp.types import ToolAnnotations
from pydantic import AnyHttpUrl

if TYPE_CHECKING:
    from fastmcp import FastMCP

HTTP_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "options",
    "head",
    "trace",
}

LOGGER = logging.getLogger("xmcp.x_api")
ANNOTATION_OVERRIDE_KEYS = {"readOnlyHint", "destructiveHint", "openWorldHint"}
ANNOTATION_OVERRIDES_FILE = Path(__file__).resolve().parent / "annotation_overrides.json"
APP_VERSION = "0.1.0"
AUTH_MODE = "oauth2-remote"
# S4-1 PoC: this ContextVar carries the incoming MCP Bearer token into outbound
# httpx request hooks, so oauth2-remote mode can inject per-session X tokens.
CURRENT_MCP_BEARER_TOKEN: ContextVar[str | None] = ContextVar(
    "current_mcp_bearer_token", default=None
)


class UnauthorizedRequestError(RuntimeError):
    def __init__(self, message: str = "Unauthorized request.") -> None:
        super().__init__(message)
        self.status_code = 401


def build_session_token_verifier(
    oauth_server, *, base_url: str, expires_in_seconds: int = 7200
):
    """Build a FastMCP TokenVerifier for xmcp session access tokens.

    When FastMCP HTTP auth is enabled, /mcp returns real HTTP 401 responses with
    WWW-Authenticate metadata before processing MCP requests. This is required
    for clients (like Claude) to kick off the OAuth flow.
    """
    from fastmcp.server.auth import AccessToken, TokenVerifier

    class _Verifier(TokenVerifier):
        def __init__(self, oauth_server, *, base_url: str, expires_in_seconds: int) -> None:
            super().__init__(base_url=base_url, required_scopes=[])
            self._oauth_server = oauth_server
            self._expires_in_seconds = expires_in_seconds

        async def verify_token(self, token: str) -> AccessToken | None:
            session = self._oauth_server.sessions_by_access.get(token)
            if session is None:
                return None

            expires_at = int(session.created_at + self._expires_in_seconds)
            if time.time() >= expires_at:
                return None

            return AccessToken(
                token=token,
                client_id=session.client_id,
                scopes=[],
                expires_at=expires_at,
            )

    return _Verifier(oauth_server, base_url=base_url, expires_in_seconds=expires_in_seconds)


class RetryTransport(httpx.AsyncBaseTransport):
    def __init__(
        self,
        transport: httpx.AsyncBaseTransport,
        *,
        max_retries: int = 2,
        sleep=asyncio.sleep,
        logger: logging.Logger | None = None,
    ) -> None:
        self._transport = transport
        self._max_retries = max(0, max_retries)
        self._sleep = sleep
        self._logger = logger or LOGGER

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = request.content
        retries = 0

        while True:
            next_request = httpx.Request(
                method=request.method,
                url=request.url,
                headers=request.headers,
                content=body,
                extensions=request.extensions,
            )
            response = await self._transport.handle_async_request(next_request)

            if self._max_retries == 0:
                return response

            if response.status_code == 429 and retries < min(self._max_retries, 1):
                wait_seconds = _seconds_until_reset(
                    response.headers.get("x-rate-limit-reset")
                )
                if wait_seconds is None:
                    wait_seconds = 1
                self._logger.warning(
                    "Retrying 429 after %ss (%s %s)",
                    wait_seconds,
                    request.method,
                    request.url,
                )
                await response.aclose()
                await self._sleep(wait_seconds)
                retries += 1
                continue

            if 500 <= response.status_code < 600 and retries < self._max_retries:
                backoff_seconds = 2**retries
                self._logger.warning(
                    "Retrying %s after %ss (%s %s)",
                    response.status_code,
                    backoff_seconds,
                    request.method,
                    request.url,
                )
                await response.aclose()
                await self._sleep(backoff_seconds)
                retries += 1
                continue

            return response

    async def aclose(self) -> None:
        await self._transport.aclose()


def is_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_csv_env(key: str) -> set[str]:
    raw = os.getenv(key, "")
    if not raw.strip():
        return set()
    return {item.strip() for item in raw.split(",") if item.strip()}


def should_join_query_param(param: dict) -> bool:
    if param.get("in") != "query":
        return False
    schema = param.get("schema", {})
    if schema.get("type") != "array":
        return False
    return param.get("explode") is False


def collect_comma_params(spec: dict) -> set[str]:
    comma_params: set[str] = set()
    components = spec.get("components", {}).get("parameters", {})
    for param in components.values():
        if isinstance(param, dict) and should_join_query_param(param):
            name = param.get("name")
            if isinstance(name, str):
                comma_params.add(name)

    for item in spec.get("paths", {}).values():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            for param in operation.get("parameters", []):
                if not isinstance(param, dict) or "$ref" in param:
                    continue
                if should_join_query_param(param):
                    name = param.get("name")
                    if isinstance(name, str):
                        comma_params.add(name)

    return comma_params


def load_openapi_spec() -> dict:
    url = "https://api.twitter.com/2/openapi.json"
    LOGGER.info("Fetching OpenAPI spec from %s", url)
    response = httpx.get(url, timeout=30)
    response.raise_for_status()
    return response.json()


def load_annotation_overrides(path: Path) -> dict[str, dict[str, bool]]:
    if not path.exists():
        return {}

    try:
        raw_overrides = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise RuntimeError(f"Invalid JSON in annotation overrides file: {path}") from error

    if not isinstance(raw_overrides, dict):
        raise RuntimeError("Annotation overrides must be a JSON object.")

    overrides: dict[str, dict[str, bool]] = {}
    for operation_id, hint_values in raw_overrides.items():
        if not isinstance(operation_id, str):
            raise RuntimeError("Annotation override operation IDs must be strings.")
        if not isinstance(hint_values, dict):
            raise RuntimeError(
                f"Annotation override for {operation_id!r} must be a JSON object."
            )

        normalized_hints: dict[str, bool] = {}
        for hint_key, hint_value in hint_values.items():
            if hint_key not in ANNOTATION_OVERRIDE_KEYS:
                continue
            if not isinstance(hint_value, bool):
                raise RuntimeError(
                    f"Annotation override {operation_id!r}.{hint_key} must be a boolean."
                )
            normalized_hints[hint_key] = hint_value

        if normalized_hints:
            overrides[operation_id] = normalized_hints

    return overrides


ANNOTATION_OVERRIDES = load_annotation_overrides(ANNOTATION_OVERRIDES_FILE)


def _method_default_annotations(method: str) -> ToolAnnotations:
    if method in {"get", "head", "options"}:
        return ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            openWorldHint=True,
        )
    if method == "delete":
        return ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            openWorldHint=True,
        )
    return ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        openWorldHint=True,
    )


def add_safety_annotations(route, component) -> None:
    from fastmcp.server.openapi import OpenAPITool

    if not isinstance(component, OpenAPITool):
        return

    method = str(route.method).lower()
    annotations = _method_default_annotations(method)

    operation_id = getattr(route, "operation_id", None)
    if isinstance(operation_id, str):
        override = ANNOTATION_OVERRIDES.get(operation_id, {})
        if override:
            annotations = ToolAnnotations(
                readOnlyHint=override.get("readOnlyHint", annotations.readOnlyHint),
                destructiveHint=override.get(
                    "destructiveHint", annotations.destructiveHint
                ),
                openWorldHint=override.get("openWorldHint", annotations.openWorldHint),
            )

    component.annotations = annotations


def _get_env_int(key: str, default: int) -> int:
    raw = os.getenv(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise RuntimeError(f"{key} must be an integer value.")


def load_env() -> None:
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(env_path, override=True)


def validate_env() -> None:
    required = (
        "X_OAUTH2_CLIENT_ID",
        "X_OAUTH2_CLIENT_SECRET",
        "X_MCP_PUBLIC_URL",
    )
    missing = [key for key in required if not os.getenv(key, "").strip()]
    if missing:
        raise RuntimeError(
            f"Missing required environment variables for {AUTH_MODE}: {', '.join(missing)}"
        )

    public_url = os.getenv("X_MCP_PUBLIC_URL", "").strip()
    parsed_public_url = urlparse(public_url)
    if parsed_public_url.scheme != "https" or not parsed_public_url.netloc:
        raise RuntimeError(
            "X_MCP_PUBLIC_URL must be a valid public HTTPS URL (for example: "
            "https://xmcp.example.com)."
        )

    scopes = os.getenv(
        "X_OAUTH2_SCOPES",
        "tweet.read tweet.write users.read offline.access",
    ).split()
    if "offline.access" not in scopes:
        LOGGER.warning(
            "X_OAUTH2_SCOPES is missing offline.access; refresh tokens will not be issued."
        )
        raise RuntimeError("X_OAUTH2_SCOPES must include offline.access.")


def setup_logging() -> bool:
    debug_enabled = is_truthy(os.getenv("X_API_DEBUG", "1"))
    if debug_enabled:
        logging.basicConfig(level=logging.INFO)
        LOGGER.setLevel(logging.INFO)
    return debug_enabled


def extract_bearer_token(authorization_header: str | None) -> str | None:
    if not authorization_header:
        return None
    scheme, _, token = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def capture_mcp_bearer_token_from_context() -> str | None:
    from fastmcp.server.dependencies import get_http_headers

    headers = get_http_headers(include_all=True)
    token = extract_bearer_token(headers.get("authorization"))
    CURRENT_MCP_BEARER_TOKEN.set(token)
    return token


async def inject_oauth2_access_token(
    request: httpx.Request,
    oauth_server,
    *,
    b3_flags: str,
) -> None:
    request.headers["X-B3-Flags"] = b3_flags
    session_access_token = CURRENT_MCP_BEARER_TOKEN.get()
    if not session_access_token:
        raise UnauthorizedRequestError(
            "Missing Bearer token in MCP request context (401)."
        )
    try:
        x_access_token = await oauth_server.resolve_x_access_token(session_access_token)
    except Exception as error:
        raise UnauthorizedRequestError(f"Invalid or expired session token (401): {error}") from error

    request.headers["Authorization"] = f"Bearer {x_access_token}"


def _seconds_until_reset(
    reset_header: str | None, *, now: float | None = None
) -> int | None:
    if reset_header is None:
        return None
    try:
        reset_epoch = int(reset_header)
    except ValueError:
        return None

    current = time.time() if now is None else now
    return max(0, reset_epoch - int(current))


def _friendly_error_message(status_code: int, wait_seconds: int | None = None) -> str:
    if status_code == 401:
        return "Authentication failed. Your X account token may have expired."
    if status_code == 403:
        return "You don't have permission to perform this action."
    if status_code == 404:
        return "The requested resource was not found on X."
    if status_code == 429:
        wait = 0 if wait_seconds is None else wait_seconds
        return f"Rate limit exceeded. Please wait {wait} seconds."
    if status_code >= 500:
        return "X API is experiencing issues. Please try again later."
    return f"X API request failed with status {status_code}."


async def handle_rate_limits(response: httpx.Response) -> None:
    remaining = response.headers.get("x-rate-limit-remaining")
    reset = response.headers.get("x-rate-limit-reset")
    wait_seconds = _seconds_until_reset(reset)
    endpoint = str(response.request.url)

    if remaining is not None or reset is not None:
        LOGGER.debug(
            "Rate limit state endpoint=%s remaining=%s reset=%s wait=%s",
            endpoint,
            remaining,
            reset,
            wait_seconds,
        )

    if response.status_code == 429 or remaining == "0":
        if response.status_code == 429:
            response.extensions["xmcp_wait_seconds"] = wait_seconds
        LOGGER.warning(
            "Rate limit warning endpoint=%s status=%s remaining=%s wait=%s",
            endpoint,
            response.status_code,
            remaining,
            wait_seconds,
        )


async def transform_error_response(response: httpx.Response) -> None:
    if response.status_code < 400:
        return

    wait_seconds = response.extensions.get("xmcp_wait_seconds")
    try:
        raw_error = response.json()
    except Exception:
        body = await response.aread()
        raw_error = {"raw": body.decode("utf-8", errors="replace")}

    payload = {
        "message": _friendly_error_message(response.status_code, wait_seconds),
        "x_error": raw_error,
        "x_transaction_id": response.headers.get("x-transaction-id"),
    }
    transformed = json.dumps(payload).encode("utf-8")
    response._content = transformed  # type: ignore[attr-defined]
    response.headers["content-type"] = "application/json"
    response.headers["content-length"] = str(len(transformed))

    LOGGER.warning(
        "Transformed X API error status=%s endpoint=%s payload=%s",
        response.status_code,
        response.request.url,
        payload,
    )


def should_exclude_operation(path: str, operation: dict) -> bool:
    if "/webhooks" in path or "/stream" in path:
        return True

    tags = [tag.lower() for tag in operation.get("tags", []) if isinstance(tag, str)]
    if "stream" in tags or "webhooks" in tags:
        return True

    if operation.get("x-twitter-streaming") is True:
        return True

    return False


def filter_openapi_spec(spec: dict) -> dict:
    filtered = copy.deepcopy(spec)
    paths = filtered.get("paths", {})
    new_paths = {}
    allow_tags = {tag.lower() for tag in parse_csv_env("X_API_TOOL_TAGS")}
    allow_ops = parse_csv_env("X_API_TOOL_ALLOWLIST")
    deny_ops = parse_csv_env("X_API_TOOL_DENYLIST")

    for path, item in paths.items():
        if not isinstance(item, dict):
            continue

        new_item = {}
        for key, value in item.items():
            if key.lower() in HTTP_METHODS:
                if should_exclude_operation(path, value):
                    continue
                operation_id = value.get("operationId")
                operation_tags = [
                    tag.lower()
                    for tag in value.get("tags", [])
                    if isinstance(tag, str)
                ]
                if allow_tags and not (set(operation_tags) & allow_tags):
                    continue
                if allow_ops and operation_id not in allow_ops:
                    continue
                if deny_ops and operation_id in deny_ops:
                    continue
                new_item[key] = value
            else:
                new_item[key] = value

        if any(method.lower() in HTTP_METHODS for method in new_item.keys()):
            new_paths[path] = new_item

    filtered["paths"] = new_paths
    return filtered


def print_tool_list(spec: dict) -> None:
    tools: list[str] = []
    for path, item in spec.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            op_id = operation.get("operationId")
            if op_id:
                tools.append(op_id)
            else:
                tools.append(f"{method.upper()} {path}")

    tools.sort()
    print(f"Loaded {len(tools)} tools from OpenAPI:")
    for tool in tools:
        print(f"- {tool}")


def mount_health_route(mcp: "FastMCP") -> None:
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response

    @mcp.custom_route("/health", methods=["GET"])
    async def health_route(request: Request) -> Response:
        del request
        return JSONResponse(
            {
                "status": "ok",
                "version": APP_VERSION,
                "auth_mode": AUTH_MODE,
            }
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

    async def capture_mcp_bearer_token(request: httpx.Request) -> None:
        del request
        capture_mcp_bearer_token_from_context()

    async def sign_oauth2_request(request: httpx.Request) -> None:
        await inject_oauth2_access_token(request, oauth_server, b3_flags=b3_flags)

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
        sign_oauth2_request,
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
