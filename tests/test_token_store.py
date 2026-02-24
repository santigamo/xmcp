import pytest

from auth.token_store import FileTokenStore, MemoryTokenStore, TokenData


@pytest.mark.asyncio
async def test_memory_store_set_get() -> None:
    store = MemoryTokenStore()
    payload = TokenData("access", "refresh", 1234.0, "user-1")

    await store.set("session-1", payload)

    assert await store.get("session-1") == payload


@pytest.mark.asyncio
async def test_memory_store_get_missing() -> None:
    store = MemoryTokenStore()

    assert await store.get("missing") is None


@pytest.mark.asyncio
async def test_memory_store_delete() -> None:
    store = MemoryTokenStore()
    await store.set("session-1", TokenData("access", "refresh", 1234.0))

    await store.delete("session-1")

    assert await store.get("session-1") is None


@pytest.mark.asyncio
async def test_file_store_set_get(tmp_path) -> None:
    path = tmp_path / "tokens.json"
    store = FileTokenStore(path)
    payload = TokenData("access", "refresh", 1234.0, "user-1")

    await store.set("session-1", payload)

    assert await store.get("session-1") == payload


@pytest.mark.asyncio
async def test_file_store_persists(tmp_path) -> None:
    path = tmp_path / "tokens.json"
    first_store = FileTokenStore(path)
    payload = TokenData("access", "refresh", 1234.0, "user-1")

    await first_store.set("session-1", payload)

    second_store = FileTokenStore(path)
    assert await second_store.get("session-1") == payload


@pytest.mark.asyncio
async def test_file_store_delete(tmp_path) -> None:
    path = tmp_path / "tokens.json"
    store = FileTokenStore(path)
    await store.set("session-1", TokenData("access", "refresh", 1234.0))

    await store.delete("session-1")

    assert await store.get("session-1") is None


@pytest.mark.asyncio
async def test_file_store_missing_file(tmp_path) -> None:
    store = FileTokenStore(tmp_path / "missing.json")

    assert await store.get("session-1") is None
