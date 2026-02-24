import string
import time
import urllib.parse

import pytest

from auth.x_oauth2 import (
    X_TOKEN_URL,
    TokenResponse,
    build_authorization_url,
    exchange_code,
    generate_code_challenge,
    generate_code_verifier,
    refresh_token,
)


def test_code_verifier_length() -> None:
    verifier = generate_code_verifier()

    assert 43 <= len(verifier) <= 128


def test_code_verifier_url_safe() -> None:
    verifier = generate_code_verifier()
    allowed = set(string.ascii_letters + string.digits + "-_")

    assert all(char in allowed for char in verifier)


def test_code_challenge_deterministic() -> None:
    verifier = "deterministic-verifier"

    assert generate_code_challenge(verifier) == generate_code_challenge(verifier)


def test_code_challenge_is_s256() -> None:
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    assert generate_code_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_build_authorization_url_contains_required_params() -> None:
    url = build_authorization_url(
        client_id="client123",
        redirect_uri="https://example.com/callback",
        scopes=["tweet.read", "users.read"],
        state="state123",
        code_challenge="challenge123",
    )

    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)

    assert query["client_id"] == ["client123"]
    assert query["redirect_uri"] == ["https://example.com/callback"]
    assert query["response_type"] == ["code"]
    assert query["code_challenge"] == ["challenge123"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] == ["state123"]
    assert query["scope"] == ["tweet.read users.read"]


@pytest.mark.asyncio
async def test_exchange_code_success(httpx_mock) -> None:
    httpx_mock.add_response(
        url=X_TOKEN_URL,
        method="POST",
        json={
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "expires_in": 7200,
            "scope": "tweet.read",
        },
    )

    token = await exchange_code(
        client_id="id",
        client_secret="secret",
        code="code123",
        redirect_uri="https://example.com/callback",
        code_verifier="verifier123",
    )

    assert token.access_token == "access-1"
    assert token.refresh_token == "refresh-1"
    assert token.expires_in == 7200
    assert token.scope == "tweet.read"
    assert token.expires_at > time.time()


@pytest.mark.asyncio
async def test_exchange_code_error(httpx_mock) -> None:
    httpx_mock.add_response(url=X_TOKEN_URL, method="POST", status_code=401, text="unauthorized")

    with pytest.raises(RuntimeError, match="Token request failed"):
        await exchange_code(
            client_id="id",
            client_secret="secret",
            code="bad-code",
            redirect_uri="https://example.com/callback",
            code_verifier="verifier123",
        )


@pytest.mark.asyncio
async def test_refresh_token_success(httpx_mock) -> None:
    httpx_mock.add_response(
        url=X_TOKEN_URL,
        method="POST",
        json={
            "access_token": "access-2",
            "refresh_token": "refresh-2",
            "expires_in": 3600,
            "scope": "tweet.read users.read",
        },
    )

    token = await refresh_token(
        client_id="id",
        client_secret="secret",
        refresh_token="refresh-1",
    )

    assert token.access_token == "access-2"
    assert token.refresh_token == "refresh-2"
    assert token.expires_in == 3600


@pytest.mark.asyncio
async def test_refresh_token_error(httpx_mock) -> None:
    httpx_mock.add_response(url=X_TOKEN_URL, method="POST", status_code=400, text="bad request")

    with pytest.raises(RuntimeError, match="Token request failed"):
        await refresh_token(
            client_id="id",
            client_secret="secret",
            refresh_token="invalid",
        )


def test_is_expired_true() -> None:
    token = TokenResponse(
        access_token="a",
        refresh_token="r",
        expires_in=10,
        expires_at=time.time() - 1,
        scope="tweet.read",
    )

    assert token.is_expired() is True


def test_is_expired_false() -> None:
    token = TokenResponse(
        access_token="a",
        refresh_token="r",
        expires_in=10,
        expires_at=time.time() + 3600,
        scope="tweet.read",
    )

    assert token.is_expired() is False
