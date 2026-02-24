import asyncio
from types import SimpleNamespace

import fastmcp.server.openapi as openapi_module

import server


class _DummyOAuth1Client:
    def sign(self, url: str, http_method: str, body=None, headers=None):
        return url, headers or {}, body


def _patch_dummy_openapi_tool(monkeypatch):
    class DummyOpenAPITool:
        def __init__(self) -> None:
            self.annotations = None

    monkeypatch.setattr(openapi_module, "OpenAPITool", DummyOpenAPITool)
    return DummyOpenAPITool


def test_annotation_get_readonly(monkeypatch) -> None:
    DummyOpenAPITool = _patch_dummy_openapi_tool(monkeypatch)
    monkeypatch.setattr(server, "ANNOTATION_OVERRIDES", {})

    tool = DummyOpenAPITool()
    route = SimpleNamespace(method="GET", operation_id="getUsersByUsername")

    server.add_safety_annotations(route, tool)

    assert tool.annotations.readOnlyHint is True
    assert tool.annotations.destructiveHint is False
    assert tool.annotations.openWorldHint is True


def test_annotation_delete_destructive(monkeypatch) -> None:
    DummyOpenAPITool = _patch_dummy_openapi_tool(monkeypatch)
    monkeypatch.setattr(server, "ANNOTATION_OVERRIDES", {})

    tool = DummyOpenAPITool()
    route = SimpleNamespace(method="DELETE", operation_id="deletePosts")

    server.add_safety_annotations(route, tool)

    assert tool.annotations.readOnlyHint is False
    assert tool.annotations.destructiveHint is True
    assert tool.annotations.openWorldHint is True


def test_annotation_post_write(monkeypatch) -> None:
    DummyOpenAPITool = _patch_dummy_openapi_tool(monkeypatch)
    monkeypatch.setattr(server, "ANNOTATION_OVERRIDES", {})

    tool = DummyOpenAPITool()
    route = SimpleNamespace(method="POST", operation_id="createPosts")

    server.add_safety_annotations(route, tool)

    assert tool.annotations.readOnlyHint is False
    assert tool.annotations.destructiveHint is False
    assert tool.annotations.openWorldHint is True


def test_annotation_skips_non_tool_components(monkeypatch) -> None:
    _patch_dummy_openapi_tool(monkeypatch)
    component = SimpleNamespace(annotations="unchanged")

    route = SimpleNamespace(method="GET", operation_id="getUsersMe")
    server.add_safety_annotations(route, component)

    assert component.annotations == "unchanged"


def test_annotation_unknown_method_defaults_to_write(monkeypatch) -> None:
    DummyOpenAPITool = _patch_dummy_openapi_tool(monkeypatch)
    monkeypatch.setattr(server, "ANNOTATION_OVERRIDES", {})

    tool = DummyOpenAPITool()
    route = SimpleNamespace(method="TRACE", operation_id="traceUsers")

    server.add_safety_annotations(route, tool)

    assert tool.annotations.readOnlyHint is False
    assert tool.annotations.destructiveHint is False
    assert tool.annotations.openWorldHint is True


def test_override_applied(monkeypatch) -> None:
    DummyOpenAPITool = _patch_dummy_openapi_tool(monkeypatch)
    monkeypatch.setattr(
        server,
        "ANNOTATION_OVERRIDES",
        {"hideReply": {"destructiveHint": True}},
    )

    tool = DummyOpenAPITool()
    route = SimpleNamespace(method="POST", operation_id="hideReply")

    server.add_safety_annotations(route, tool)

    assert tool.annotations.readOnlyHint is False
    assert tool.annotations.destructiveHint is True
    assert tool.annotations.openWorldHint is True


def test_override_file_missing_is_ok(tmp_path) -> None:
    missing_file = tmp_path / "annotation_overrides.json"

    assert server.load_annotation_overrides(missing_file) == {}


def test_annotations_integrated(monkeypatch) -> None:
    monkeypatch.setattr(server, "load_env", lambda: None)
    monkeypatch.setattr(server, "setup_logging", lambda: False)
    monkeypatch.setattr(server, "build_oauth1_client", lambda: _DummyOAuth1Client())
    monkeypatch.setattr(server, "print_tool_list", lambda _spec: None)
    monkeypatch.setattr(server, "ANNOTATION_OVERRIDES", {})
    monkeypatch.delenv("X_API_TOOL_ALLOWLIST", raising=False)
    monkeypatch.delenv("X_API_TOOL_DENYLIST", raising=False)
    monkeypatch.delenv("X_API_TOOL_TAGS", raising=False)

    minimal_spec = {
        "openapi": "3.0.0",
        "info": {"title": "X API", "version": "1.0.0"},
        "paths": {
            "/2/users/me": {
                "get": {
                    "operationId": "getUsersMe",
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/2/posts": {
                "post": {
                    "operationId": "createPosts",
                    "responses": {"201": {"description": "created"}},
                }
            },
            "/2/posts/{id}": {
                "delete": {
                    "operationId": "deletePosts",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            },
        },
    }
    monkeypatch.setattr(server, "load_openapi_spec", lambda: minimal_spec)

    mcp = server.create_mcp()

    try:
        tools = mcp._tool_manager._tools

        assert tools["getUsersMe"].annotations.readOnlyHint is True
        assert tools["getUsersMe"].annotations.destructiveHint is False
        assert tools["getUsersMe"].annotations.openWorldHint is True
        assert tools["createPosts"].annotations.readOnlyHint is False
        assert tools["createPosts"].annotations.destructiveHint is False
        assert tools["createPosts"].annotations.openWorldHint is True
        assert tools["deletePosts"].annotations.readOnlyHint is False
        assert tools["deletePosts"].annotations.destructiveHint is True
        assert tools["deletePosts"].annotations.openWorldHint is True
    finally:
        asyncio.run(mcp._client.aclose())
