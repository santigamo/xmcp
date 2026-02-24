import httpx
import pytest

from server import RetryTransport


class SleepRecorder:
    def __init__(self) -> None:
        self.calls: list[int] = []

    async def __call__(self, seconds: int) -> None:
        self.calls.append(seconds)


def _make_handler(statuses: list[int], headers_by_attempt: list[dict[str, str]] | None = None):
    attempt = {"count": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        index = attempt["count"]
        attempt["count"] += 1
        status = statuses[min(index, len(statuses) - 1)]
        headers = {}
        if headers_by_attempt is not None and index < len(headers_by_attempt):
            headers = headers_by_attempt[index]
        return httpx.Response(status, request=request, headers=headers, json={"status": status})

    return handler, attempt


@pytest.mark.asyncio
async def test_retry_on_429() -> None:
    handler, attempt = _make_handler(
        [429, 200],
        headers_by_attempt=[{"x-rate-limit-reset": "9999999999"}, {}],
    )
    sleep = SleepRecorder()
    transport = RetryTransport(httpx.MockTransport(handler), max_retries=2, sleep=sleep)

    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get("https://api.x.com/2/posts")

    assert response.status_code == 200
    assert attempt["count"] == 2
    assert len(sleep.calls) == 1


@pytest.mark.asyncio
async def test_retry_on_500() -> None:
    handler, attempt = _make_handler([500, 200])
    sleep = SleepRecorder()
    transport = RetryTransport(httpx.MockTransport(handler), max_retries=2, sleep=sleep)

    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get("https://api.x.com/2/posts")

    assert response.status_code == 200
    assert attempt["count"] == 2
    assert sleep.calls == [1]


@pytest.mark.asyncio
async def test_no_retry_on_4xx() -> None:
    handler, attempt = _make_handler([400, 200])
    sleep = SleepRecorder()
    transport = RetryTransport(httpx.MockTransport(handler), max_retries=2, sleep=sleep)

    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get("https://api.x.com/2/posts")

    assert response.status_code == 400
    assert attempt["count"] == 1
    assert sleep.calls == []


@pytest.mark.asyncio
async def test_max_retries_exceeded() -> None:
    handler, attempt = _make_handler([500, 500, 500, 500])
    sleep = SleepRecorder()
    transport = RetryTransport(httpx.MockTransport(handler), max_retries=2, sleep=sleep)

    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get("https://api.x.com/2/posts")

    assert response.status_code == 500
    assert attempt["count"] == 3
    assert sleep.calls == [1, 2]


@pytest.mark.asyncio
async def test_retries_disabled() -> None:
    handler, attempt = _make_handler(
        [429, 200],
        headers_by_attempt=[{"x-rate-limit-reset": "9999999999"}, {}],
    )
    sleep = SleepRecorder()
    transport = RetryTransport(httpx.MockTransport(handler), max_retries=0, sleep=sleep)

    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get("https://api.x.com/2/posts")

    assert response.status_code == 429
    assert attempt["count"] == 1
    assert sleep.calls == []
