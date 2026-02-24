from server import HTTP_METHODS, filter_openapi_spec


ENV_FILTER_KEYS = ("X_API_TOOL_TAGS", "X_API_TOOL_ALLOWLIST", "X_API_TOOL_DENYLIST")


def _operation_ids(spec: dict) -> set[str]:
    operation_ids: set[str] = set()
    for item in spec.get("paths", {}).values():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            operation_id = operation.get("operationId")
            if isinstance(operation_id, str):
                operation_ids.add(operation_id)
    return operation_ids


def _clear_filters(monkeypatch) -> None:
    for key in ENV_FILTER_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_excludes_streaming_path(mock_openapi_spec, monkeypatch) -> None:
    _clear_filters(monkeypatch)
    filtered = filter_openapi_spec(mock_openapi_spec)

    assert "/2/posts/stream/sample" not in filtered["paths"]


def test_excludes_webhook_path(mock_openapi_spec, monkeypatch) -> None:
    _clear_filters(monkeypatch)
    filtered = filter_openapi_spec(mock_openapi_spec)

    assert "/2/webhooks/events" not in filtered["paths"]


def test_excludes_streaming_tag(mock_openapi_spec, monkeypatch) -> None:
    _clear_filters(monkeypatch)
    filtered = filter_openapi_spec(mock_openapi_spec)

    assert "/2/tweets/live" not in filtered["paths"]


def test_excludes_twitter_streaming_flag(mock_openapi_spec, monkeypatch) -> None:
    _clear_filters(monkeypatch)
    filtered = filter_openapi_spec(mock_openapi_spec)

    assert "/2/tweets/sampled" not in filtered["paths"]


def test_keeps_normal_endpoint(mock_openapi_spec, monkeypatch) -> None:
    _clear_filters(monkeypatch)
    filtered = filter_openapi_spec(mock_openapi_spec)

    assert "getUsersByUsername" in _operation_ids(filtered)


def test_allowlist_filters_operations(mock_openapi_spec, monkeypatch) -> None:
    _clear_filters(monkeypatch)
    monkeypatch.setenv("X_API_TOOL_ALLOWLIST", "getUsersByUsername,createPosts")

    filtered = filter_openapi_spec(mock_openapi_spec)

    assert _operation_ids(filtered) == {"getUsersByUsername", "createPosts"}


def test_denylist_removes_operations(mock_openapi_spec, monkeypatch) -> None:
    _clear_filters(monkeypatch)
    monkeypatch.setenv("X_API_TOOL_DENYLIST", "deletePosts")

    filtered = filter_openapi_spec(mock_openapi_spec)

    assert "deletePosts" not in _operation_ids(filtered)


def test_tag_filter(mock_openapi_spec, monkeypatch) -> None:
    _clear_filters(monkeypatch)
    monkeypatch.setenv("X_API_TOOL_TAGS", "users")

    filtered = filter_openapi_spec(mock_openapi_spec)

    assert _operation_ids(filtered) == {"getUsersByUsername"}


def test_empty_paths_removed(mock_openapi_spec, monkeypatch) -> None:
    _clear_filters(monkeypatch)
    monkeypatch.setenv("X_API_TOOL_ALLOWLIST", "getUsersByUsername")

    filtered = filter_openapi_spec(mock_openapi_spec)

    assert set(filtered["paths"].keys()) == {"/2/users/by/username/{username}"}
