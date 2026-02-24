import server


EXPECTED_EXPORTS = (
    "create_mcp",
    "filter_openapi_spec",
    "should_exclude_operation",
    "collect_comma_params",
    "parse_csv_env",
)


def test_import_server() -> None:
    for name in EXPECTED_EXPORTS:
        assert hasattr(server, name)
