from __future__ import annotations

import base64
import hashlib
import secrets
import time
import urllib.parse
from dataclasses import dataclass

import httpx

X_AUTHORIZE_URL = "https://x.com/i/oauth2/authorize"
X_TOKEN_URL = "https://api.x.com/2/oauth2/token"


@dataclass
class TokenResponse:
    access_token: str
    refresh_token: str
    expires_in: int
    expires_at: float
    scope: str

    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

    @classmethod
    def from_payload(cls, payload: dict) -> "TokenResponse":
        access_token = payload.get("access_token")
        refresh_token = payload.get("refresh_token")
        expires_in = payload.get("expires_in")
        scope = payload.get("scope", "")

        if not isinstance(access_token, str) or not access_token:
            raise RuntimeError("Token response missing access_token.")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise RuntimeError("Token response missing refresh_token.")
        if not isinstance(expires_in, int):
            raise RuntimeError("Token response missing expires_in.")
        if not isinstance(scope, str):
            raise RuntimeError("Token response scope must be a string.")

        return cls(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=expires_in,
            expires_at=time.time() + expires_in,
            scope=scope,
        )


def generate_code_verifier() -> str:
    while True:
        verifier = secrets.token_urlsafe(64)
        if 43 <= len(verifier) <= 128:
            return verifier


def generate_code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def build_authorization_url(
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    state: str,
    code_challenge: str,
) -> str:
    query = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "scope": " ".join(scopes),
    }
    return f"{X_AUTHORIZE_URL}?{urllib.parse.urlencode(query)}"


async def _token_request(
    payload: dict[str, str],
    *,
    client: httpx.AsyncClient | None = None,
) -> TokenResponse:
    own_client = client is None
    http_client = client or httpx.AsyncClient()

    try:
        response = await http_client.post(X_TOKEN_URL, data=payload)
        response.raise_for_status()
    except httpx.HTTPStatusError as error:
        detail = error.response.text
        raise RuntimeError(
            f"Token request failed with status {error.response.status_code}: {detail}"
        ) from error
    finally:
        if own_client:
            await http_client.aclose()

    return TokenResponse.from_payload(response.json())


async def exchange_code(
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> TokenResponse:
    return await _token_request(
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
        client=client,
    )


async def refresh_token(
    client_id: str,
    client_secret: str,
    refresh_token: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> TokenResponse:
    return await _token_request(
        {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
        },
        client=client,
    )
