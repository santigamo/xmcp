from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass


@dataclass
class ClientInfo:
    client_id: str
    client_secret: str
    client_name: str
    redirect_uris: list[str]
    created_at: float


class ClientRegistry:
    def __init__(self) -> None:
        self._clients: dict[str, ClientInfo] = {}

    def register(self, client_name: str, redirect_uris: list[str]) -> ClientInfo:
        client = ClientInfo(
            client_id=str(uuid.uuid4()),
            client_secret=secrets.token_urlsafe(32),
            client_name=client_name,
            redirect_uris=redirect_uris,
            created_at=time.time(),
        )
        self._clients[client.client_id] = client
        return client

    def get(self, client_id: str) -> ClientInfo | None:
        return self._clients.get(client_id)

    def validate_redirect_uri(self, client_id: str, uri: str) -> bool:
        client = self.get(client_id)
        if client is None:
            return False
        return uri in client.redirect_uris
