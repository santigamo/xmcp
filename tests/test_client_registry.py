from auth.client_registry import ClientRegistry


def test_register_returns_client_info() -> None:
    registry = ClientRegistry()

    client = registry.register(
        client_name="Claude",
        redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
    )

    assert client.client_id
    assert client.client_secret
    assert client.client_name == "Claude"
    assert client.redirect_uris == ["https://claude.ai/api/mcp/auth_callback"]


def test_register_unique_ids() -> None:
    registry = ClientRegistry()

    first = registry.register("A", ["https://a/callback"])
    second = registry.register("B", ["https://b/callback"])

    assert first.client_id != second.client_id


def test_get_existing_client() -> None:
    registry = ClientRegistry()
    client = registry.register("A", ["https://a/callback"])

    assert registry.get(client.client_id) == client


def test_get_missing_client() -> None:
    registry = ClientRegistry()

    assert registry.get("missing") is None


def test_validate_redirect_uri_valid() -> None:
    registry = ClientRegistry()
    client = registry.register("A", ["https://a/callback"])

    assert registry.validate_redirect_uri(client.client_id, "https://a/callback") is True


def test_validate_redirect_uri_invalid() -> None:
    registry = ClientRegistry()
    client = registry.register("A", ["https://a/callback"])

    assert registry.validate_redirect_uri(client.client_id, "https://other/callback") is False
