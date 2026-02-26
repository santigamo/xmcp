from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PendingAuth:
    client_id: str
    redirect_uri: str
    code_challenge: str
    original_state: str
    x_code_verifier: str
    created_at: float


@dataclass
class PendingCode:
    client_id: str
    code_challenge: str
    redirect_uri: str
    x_access_token: str
    x_refresh_token: str
    x_expires_at: float
    created_at: float
