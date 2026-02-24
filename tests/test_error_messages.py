import httpx
import pytest

import server


@pytest.mark.asyncio
async def test_401_message() -> None:
    response = httpx.Response(
        401,
        request=httpx.Request("GET", "https://api.x.com/2/users/me"),
        headers={"x-transaction-id": "txn-401"},
        json={"detail": "unauthorized"},
    )

    await server.transform_error_response(response)
    payload = response.json()

    assert payload["message"] == "Authentication failed. Your X account token may have expired."
    assert payload["x_error"] == {"detail": "unauthorized"}
    assert payload["x_transaction_id"] == "txn-401"


@pytest.mark.asyncio
async def test_403_message() -> None:
    response = httpx.Response(
        403,
        request=httpx.Request("GET", "https://api.x.com/2/users/me"),
        json={"detail": "forbidden"},
    )

    await server.transform_error_response(response)

    assert response.json()["message"] == "You don't have permission to perform this action."


@pytest.mark.asyncio
async def test_404_message() -> None:
    response = httpx.Response(
        404,
        request=httpx.Request("GET", "https://api.x.com/2/users/me"),
        json={"detail": "not found"},
    )

    await server.transform_error_response(response)

    assert response.json()["message"] == "The requested resource was not found on X."


@pytest.mark.asyncio
async def test_429_message() -> None:
    response = httpx.Response(
        429,
        request=httpx.Request("GET", "https://api.x.com/2/users/me"),
        json={"detail": "ratelimited"},
    )
    response.extensions["xmcp_wait_seconds"] = 45

    await server.transform_error_response(response)

    assert response.json()["message"] == "Rate limit exceeded. Please wait 45 seconds."


@pytest.mark.asyncio
async def test_500_message() -> None:
    response = httpx.Response(
        500,
        request=httpx.Request("GET", "https://api.x.com/2/users/me"),
        text="upstream unavailable",
    )

    await server.transform_error_response(response)

    assert response.json()["message"] == "X API is experiencing issues. Please try again later."


@pytest.mark.asyncio
async def test_200_no_transformation() -> None:
    response = httpx.Response(
        200,
        request=httpx.Request("GET", "https://api.x.com/2/users/me"),
        json={"ok": True},
    )

    await server.transform_error_response(response)

    assert response.json() == {"ok": True}
