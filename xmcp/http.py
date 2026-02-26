from __future__ import annotations

import asyncio
import json
import logging
import time

import httpx

from .constants import LOGGER


def _seconds_until_reset(reset_header: str | None, *, now: float | None = None) -> int | None:
    if reset_header is None:
        return None
    try:
        reset_epoch = int(reset_header)
    except ValueError:
        return None

    current = time.time() if now is None else now
    return max(0, reset_epoch - int(current))


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
                wait_seconds = _seconds_until_reset(response.headers.get("x-rate-limit-reset"))
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
