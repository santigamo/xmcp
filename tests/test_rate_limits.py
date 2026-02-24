import time

import httpx
import pytest

import server


@pytest.mark.asyncio
async def test_rate_limit_429_returns_clear_error() -> None:
    now = int(time.time())
    request = httpx.Request("GET", "https://api.x.com/2/posts")
    response = httpx.Response(
        429,
        request=request,
        headers={
            "x-rate-limit-remaining": "0",
            "x-rate-limit-reset": str(now + 45),
            "x-transaction-id": "txn-1",
        },
        json={"title": "Too Many Requests"},
    )

    await server.handle_rate_limits(response)
    await server.transform_error_response(response)

    payload = response.json()
    assert "Please wait" in payload["message"]
    assert payload["x_error"] == {"title": "Too Many Requests"}
    assert payload["x_transaction_id"] == "txn-1"


@pytest.mark.asyncio
async def test_rate_limit_remaining_zero() -> None:
    request = httpx.Request("GET", "https://api.x.com/2/posts")
    response = httpx.Response(
        200,
        request=request,
        headers={
            "x-rate-limit-remaining": "0",
            "x-rate-limit-reset": str(int(time.time()) + 30),
        },
        json={"ok": True},
    )

    await server.handle_rate_limits(response)

    assert "xmcp_wait_seconds" not in response.extensions


@pytest.mark.asyncio
async def test_rate_limit_normal_passthrough() -> None:
    request = httpx.Request("GET", "https://api.x.com/2/posts")
    response = httpx.Response(
        200,
        request=request,
        headers={
            "x-rate-limit-remaining": "10",
            "x-rate-limit-reset": str(int(time.time()) + 30),
        },
        json={"ok": True},
    )

    await server.handle_rate_limits(response)
    await server.transform_error_response(response)

    assert response.json() == {"ok": True}


@pytest.mark.asyncio
async def test_rate_limit_missing_headers() -> None:
    request = httpx.Request("GET", "https://api.x.com/2/posts")
    response = httpx.Response(200, request=request, json={"ok": True})

    await server.handle_rate_limits(response)

    assert response.status_code == 200
