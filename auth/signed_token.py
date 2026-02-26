from __future__ import annotations

import base64
import hashlib
import hmac
import json


def derive_key(client_secret: str) -> str:
    """Derive a stable signing key from the X OAuth2 client secret."""
    return hashlib.sha256(f"xmcp:{client_secret}".encode()).hexdigest()


def encode(payload: dict, key: str) -> str:
    data = json.dumps(payload, separators=(",", ":")).encode()
    data_b64 = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
    sig = hmac.new(key.encode(), data, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{data_b64}.{sig_b64}"


def decode(token: str, key: str) -> dict:
    parts = token.split(".", 1)
    if len(parts) != 2:
        raise RuntimeError("Invalid token format.")
    data_b64, sig_b64 = parts
    data = base64.urlsafe_b64decode(data_b64 + "==")
    expected_sig = hmac.new(key.encode(), data, hashlib.sha256).digest()
    actual_sig = base64.urlsafe_b64decode(sig_b64 + "==")
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise RuntimeError("Token signature verification failed.")
    return json.loads(data)
