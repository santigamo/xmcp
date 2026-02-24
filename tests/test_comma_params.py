from server import collect_comma_params, parse_csv_env, should_join_query_param


def test_collect_comma_params_from_components(mock_openapi_spec) -> None:
    comma_params = collect_comma_params(mock_openapi_spec)

    assert "component_ids" in comma_params


def test_collect_comma_params_from_operations(mock_openapi_spec) -> None:
    comma_params = collect_comma_params(mock_openapi_spec)

    assert "inline_ids" in comma_params


def test_should_join_query_param_true() -> None:
    assert (
        should_join_query_param(
            {
                "name": "ids",
                "in": "query",
                "schema": {"type": "array", "items": {"type": "string"}},
                "explode": False,
            }
        )
        is True
    )


def test_should_join_query_param_false_not_array() -> None:
    assert (
        should_join_query_param(
            {
                "name": "ids",
                "in": "query",
                "schema": {"type": "string"},
                "explode": False,
            }
        )
        is False
    )


def test_should_join_query_param_false_not_query() -> None:
    assert (
        should_join_query_param(
            {
                "name": "ids",
                "in": "path",
                "schema": {"type": "array", "items": {"type": "string"}},
                "explode": False,
            }
        )
        is False
    )


def test_parse_csv_env_basic(monkeypatch) -> None:
    monkeypatch.setenv("X_TEST_CSV", "a,b,c")

    assert parse_csv_env("X_TEST_CSV") == {"a", "b", "c"}


def test_parse_csv_env_whitespace(monkeypatch) -> None:
    monkeypatch.setenv("X_TEST_CSV", " a , b ")

    assert parse_csv_env("X_TEST_CSV") == {"a", "b"}


def test_parse_csv_env_empty(monkeypatch) -> None:
    monkeypatch.delenv("X_TEST_CSV", raising=False)

    assert parse_csv_env("X_TEST_CSV") == set()
