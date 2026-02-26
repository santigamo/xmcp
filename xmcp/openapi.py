from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx
from mcp.types import ToolAnnotations

from .constants import (
    ANNOTATION_OVERRIDE_KEYS,
    ANNOTATION_OVERRIDES_FILE,
    HTTP_METHODS,
    LOGGER,
)
from .env import parse_csv_env


def should_join_query_param(param: dict) -> bool:
    if param.get("in") != "query":
        return False
    schema = param.get("schema", {})
    if schema.get("type") != "array":
        return False
    return param.get("explode") is False


def collect_comma_params(spec: dict) -> set[str]:
    comma_params: set[str] = set()
    components = spec.get("components", {}).get("parameters", {})
    for param in components.values():
        if isinstance(param, dict) and should_join_query_param(param):
            name = param.get("name")
            if isinstance(name, str):
                comma_params.add(name)

    for item in spec.get("paths", {}).values():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            for param in operation.get("parameters", []):
                if not isinstance(param, dict) or "$ref" in param:
                    continue
                if should_join_query_param(param):
                    name = param.get("name")
                    if isinstance(name, str):
                        comma_params.add(name)

    return comma_params


def load_openapi_spec() -> dict:
    url = "https://api.twitter.com/2/openapi.json"
    LOGGER.info("Fetching OpenAPI spec from %s", url)
    response = httpx.get(url, timeout=30)
    response.raise_for_status()
    return response.json()


def load_annotation_overrides(path: Path) -> dict[str, dict[str, bool]]:
    if not path.exists():
        return {}

    try:
        raw_overrides = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise RuntimeError(f"Invalid JSON in annotation overrides file: {path}") from error

    if not isinstance(raw_overrides, dict):
        raise RuntimeError("Annotation overrides must be a JSON object.")

    overrides: dict[str, dict[str, bool]] = {}
    for operation_id, hint_values in raw_overrides.items():
        if not isinstance(operation_id, str):
            raise RuntimeError("Annotation override operation IDs must be strings.")
        if not isinstance(hint_values, dict):
            raise RuntimeError(f"Annotation override for {operation_id!r} must be a JSON object.")

        normalized_hints: dict[str, bool] = {}
        for hint_key, hint_value in hint_values.items():
            if hint_key not in ANNOTATION_OVERRIDE_KEYS:
                continue
            if not isinstance(hint_value, bool):
                raise RuntimeError(
                    f"Annotation override {operation_id!r}.{hint_key} must be a boolean."
                )
            normalized_hints[hint_key] = hint_value

        if normalized_hints:
            overrides[operation_id] = normalized_hints

    return overrides


ANNOTATION_OVERRIDES = load_annotation_overrides(ANNOTATION_OVERRIDES_FILE)


def _method_default_annotations(method: str) -> ToolAnnotations:
    if method in {"get", "head", "options"}:
        return ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            openWorldHint=True,
        )
    if method == "delete":
        return ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            openWorldHint=True,
        )
    return ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        openWorldHint=True,
    )


def add_safety_annotations(
    route, component, *, overrides: dict[str, dict[str, bool]] | None = None
) -> None:
    from fastmcp.server.openapi import OpenAPITool

    if not isinstance(component, OpenAPITool):
        return

    method = str(route.method).lower()
    annotations = _method_default_annotations(method)

    override_map = ANNOTATION_OVERRIDES if overrides is None else overrides
    operation_id = getattr(route, "operation_id", None)
    if isinstance(operation_id, str):
        override = override_map.get(operation_id, {})
        if override:
            annotations = ToolAnnotations(
                readOnlyHint=override.get("readOnlyHint", annotations.readOnlyHint),
                destructiveHint=override.get("destructiveHint", annotations.destructiveHint),
                openWorldHint=override.get("openWorldHint", annotations.openWorldHint),
            )

    component.annotations = annotations


def should_exclude_operation(path: str, operation: dict) -> bool:
    if "/webhooks" in path or "/stream" in path:
        return True

    tags = [tag.lower() for tag in operation.get("tags", []) if isinstance(tag, str)]
    if "stream" in tags or "webhooks" in tags:
        return True

    if operation.get("x-twitter-streaming") is True:
        return True

    return False


def filter_openapi_spec(spec: dict) -> dict:
    filtered = copy.deepcopy(spec)
    paths = filtered.get("paths", {})
    new_paths = {}
    allow_tags = {tag.lower() for tag in parse_csv_env("X_API_TOOL_TAGS")}
    allow_ops = parse_csv_env("X_API_TOOL_ALLOWLIST")
    deny_ops = parse_csv_env("X_API_TOOL_DENYLIST")

    for path, item in paths.items():
        if not isinstance(item, dict):
            continue

        new_item = {}
        for key, value in item.items():
            if key.lower() in HTTP_METHODS:
                if should_exclude_operation(path, value):
                    continue
                operation_id = value.get("operationId")
                operation_tags = [
                    tag.lower() for tag in value.get("tags", []) if isinstance(tag, str)
                ]
                if allow_tags and not (set(operation_tags) & allow_tags):
                    continue
                if allow_ops and operation_id not in allow_ops:
                    continue
                if deny_ops and operation_id in deny_ops:
                    continue
                new_item[key] = value
            else:
                new_item[key] = value

        if any(method.lower() in HTTP_METHODS for method in new_item.keys()):
            new_paths[path] = new_item

    filtered["paths"] = new_paths
    return filtered


def print_tool_list(spec: dict) -> None:
    tools: list[str] = []
    for path, item in spec.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            op_id = operation.get("operationId")
            if op_id:
                tools.append(op_id)
            else:
                tools.append(f"{method.upper()} {path}")

    tools.sort()
    print(f"Loaded {len(tools)} tools from OpenAPI:")
    for tool in tools:
        print(f"- {tool}")
