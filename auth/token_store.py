from __future__ import annotations

import json
import os
import tempfile
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class TokenData:
    x_access_token: str
    x_refresh_token: str
    expires_at: float
    user_id: str | None = None


class TokenStore(ABC):
    @abstractmethod
    async def get(self, session_id: str) -> TokenData | None:
        raise NotImplementedError

    @abstractmethod
    async def set(self, session_id: str, data: TokenData) -> None:
        raise NotImplementedError

    @abstractmethod
    async def delete(self, session_id: str) -> None:
        raise NotImplementedError


class MemoryTokenStore(TokenStore):
    def __init__(self) -> None:
        self._tokens: dict[str, TokenData] = {}

    async def get(self, session_id: str) -> TokenData | None:
        return self._tokens.get(session_id)

    async def set(self, session_id: str, data: TokenData) -> None:
        self._tokens[session_id] = data

    async def delete(self, session_id: str) -> None:
        self._tokens.pop(session_id, None)


class FileTokenStore(TokenStore):
    def __init__(self, path: str | Path = ".tokens.json") -> None:
        self._path = Path(path)

    async def get(self, session_id: str) -> TokenData | None:
        all_tokens = self._read_all()
        payload = all_tokens.get(session_id)
        if payload is None:
            return None
        return TokenData(**payload)

    async def set(self, session_id: str, data: TokenData) -> None:
        all_tokens = self._read_all()
        all_tokens[session_id] = asdict(data)
        self._write_all(all_tokens)

    async def delete(self, session_id: str) -> None:
        all_tokens = self._read_all()
        all_tokens.pop(session_id, None)
        self._write_all(all_tokens)

    def _read_all(self) -> dict[str, dict]:
        if not self._path.exists():
            return {}

        raw = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise RuntimeError("Token store file is invalid; expected top-level JSON object.")
        return raw

    def _write_all(self, payload: dict[str, dict]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)

        fd, tmp_name = tempfile.mkstemp(
            prefix=f"{self._path.name}.",
            suffix=".tmp",
            dir=self._path.parent,
        )
        tmp_path = Path(tmp_name)

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
            os.replace(tmp_path, self._path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()
