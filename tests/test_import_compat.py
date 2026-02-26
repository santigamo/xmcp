import server


EXPECTED_SERVER_EXPORTS = (
    "APP_VERSION",
    "AUTH_MODE",
    "HTTP_METHODS",
    "ANNOTATION_OVERRIDES",
    "CURRENT_MCP_BEARER_TOKEN",
    "UnauthorizedRequestError",
    "RetryTransport",
    "parse_csv_env",
    "collect_comma_params",
    "should_join_query_param",
    "should_exclude_operation",
    "filter_openapi_spec",
    "load_openapi_spec",
    "load_annotation_overrides",
    "add_safety_annotations",
    "build_session_token_verifier",
    "capture_mcp_bearer_token_from_context",
    "inject_oauth2_access_token",
    "handle_rate_limits",
    "transform_error_response",
    "load_env",
    "setup_logging",
    "validate_env",
    "print_tool_list",
    "create_mcp",
    "main",
)


def test_server_export_surface() -> None:
    missing = [name for name in EXPECTED_SERVER_EXPORTS if not hasattr(server, name)]
    assert missing == []
