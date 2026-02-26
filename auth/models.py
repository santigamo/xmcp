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
    session_id: str
    client_id: str
    code_challenge: str
    redirect_uri: str
    created_at: float


@dataclass
class SessionToken:
    session_id: str
    client_id: str
    refresh_token: str
    created_at: float
