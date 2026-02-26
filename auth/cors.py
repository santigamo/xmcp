from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

DEFAULT_CORS_ORIGINS = {
    "https://claude.ai",
    "https://claude.com",
    "https://www.anthropic.com",
    "https://api.anthropic.com",
}


def _is_allowed_origin(origin: str | None, allowed_origins: set[str]) -> bool:
    return bool(origin and origin in allowed_origins)


def apply_cors_response(
    request: Request,
    response: Response,
    allowed_origins: set[str],
) -> Response:
    origin = request.headers.get("origin")
    if _is_allowed_origin(origin, allowed_origins):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Vary"] = "Origin"
    return response


def cors_preflight_response(request: Request, allowed_origins: set[str]) -> Response:
    return apply_cors_response(request, Response(status_code=204), allowed_origins)


def mount_preflight_route(mcp, path: str, allowed_origins: set[str]) -> None:
    @mcp.custom_route(path, methods=["OPTIONS"])
    async def preflight_route(request: Request) -> Response:
        return cors_preflight_response(request, allowed_origins)


def cors_error_response(
    request: Request,
    allowed_origins: set[str],
    code: str,
    description: str,
    status_code: int,
) -> Response:
    return apply_cors_response(
        request,
        JSONResponse(
            {"error": code, "error_description": description},
            status_code=status_code,
        ),
        allowed_origins,
    )
