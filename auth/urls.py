from __future__ import annotations

import urllib.parse


def is_allowed_redirect_uri(uri: str) -> bool:
    if uri == "https://claude.ai/api/mcp/auth_callback":
        return True

    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "http":
        return False
    if parsed.hostname != "localhost":
        return False
    if not parsed.port:
        return False
    return parsed.path == "/callback"


def append_query_params(url: str, params: dict[str, str]) -> str:
    parsed = urllib.parse.urlparse(url)
    existing = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for key, value in params.items():
        existing[key] = [value]

    new_query = urllib.parse.urlencode(existing, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))
