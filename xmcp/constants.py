from __future__ import annotations

import logging
from pathlib import Path

HTTP_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "options",
    "head",
    "trace",
}

LOGGER = logging.getLogger("xmcp.x_api")
APP_VERSION = "0.1.0"
AUTH_MODE = "oauth2-remote"

ANNOTATION_OVERRIDE_KEYS = {"readOnlyHint", "destructiveHint", "openWorldHint"}
ANNOTATION_OVERRIDES_FILE = Path(__file__).resolve().parent.parent / "annotation_overrides.json"
