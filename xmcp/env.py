from __future__ import annotations

import logging
import os
from pathlib import Path
from urllib.parse import urlparse

from .constants import AUTH_MODE, LOGGER


def is_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_csv_env(key: str) -> set[str]:
    raw = os.getenv(key, "")
    if not raw.strip():
        return set()
    return {item.strip() for item in raw.split(",") if item.strip()}


def _get_env_int(key: str, default: int) -> int:
    raw = os.getenv(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise RuntimeError(f"{key} must be an integer value.")


def load_env() -> None:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(env_path, override=True)


def validate_env() -> None:
    required = (
        "X_OAUTH2_CLIENT_ID",
        "X_OAUTH2_CLIENT_SECRET",
        "X_MCP_PUBLIC_URL",
    )
    missing = [key for key in required if not os.getenv(key, "").strip()]
    if missing:
        raise RuntimeError(
            f"Missing required environment variables for {AUTH_MODE}: {', '.join(missing)}"
        )

    public_url = os.getenv("X_MCP_PUBLIC_URL", "").strip()
    parsed_public_url = urlparse(public_url)
    if parsed_public_url.scheme != "https" or not parsed_public_url.netloc:
        raise RuntimeError(
            "X_MCP_PUBLIC_URL must be a valid public HTTPS URL (for example: "
            "https://xmcp.example.com)."
        )

    scopes = os.getenv(
        "X_OAUTH2_SCOPES",
        "tweet.read tweet.write users.read offline.access",
    ).split()
    if "offline.access" not in scopes:
        LOGGER.warning(
            "X_OAUTH2_SCOPES is missing offline.access; refresh tokens will not be issued."
        )
        raise RuntimeError("X_OAUTH2_SCOPES must include offline.access.")


def setup_logging() -> bool:
    debug_enabled = is_truthy(os.getenv("X_API_DEBUG", "1"))
    if debug_enabled:
        logging.basicConfig(level=logging.INFO)
        LOGGER.setLevel(logging.INFO)
    return debug_enabled
