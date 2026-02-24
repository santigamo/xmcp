import server


class _DummyMCP:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def run(self, **kwargs) -> None:
        self.calls.append(kwargs)


def test_main_uses_streamable_http_with_local_defaults(monkeypatch) -> None:
    dummy_mcp = _DummyMCP()
    monkeypatch.setattr(server, "create_mcp", lambda: dummy_mcp)
    monkeypatch.delenv("MCP_HOST", raising=False)
    monkeypatch.delenv("MCP_PORT", raising=False)

    server.main()

    assert dummy_mcp.calls == [
        {"transport": "streamable-http", "host": "127.0.0.1", "port": 8000}
    ]


def test_main_reads_host_and_port_from_env(monkeypatch) -> None:
    dummy_mcp = _DummyMCP()
    monkeypatch.setattr(server, "create_mcp", lambda: dummy_mcp)
    monkeypatch.setenv("MCP_HOST", "0.0.0.0")
    monkeypatch.setenv("MCP_PORT", "9100")

    server.main()

    assert dummy_mcp.calls == [
        {"transport": "streamable-http", "host": "0.0.0.0", "port": 9100}
    ]
