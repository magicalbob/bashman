import inspect
import pytest

from bashman.server.database.base import DatabaseInterface


def test_abstract_methods_and_coroutines():
    """The interface should expose the expected abstract async methods."""
    expected = {
        "initialize",
        "close",
        "store_user_info",
        "create_package",
        "get_package",
        "get_package_content",
        "get_package_with_content",
        "list_packages",
        "update_package",
        "delete_package",
        "search_packages",
        "get_package_versions",
        "get_package_count",
        "get_trending_packages",
        "record_download",
    }

    # ABC should list exactly these abstract methods
    assert set(DatabaseInterface.__abstractmethods__) == expected

    # Every method must be an async coroutine function
    for name in expected:
        fn = getattr(DatabaseInterface, name)
        assert inspect.iscoroutinefunction(fn), f"{name} must be async"


def test_cannot_instantiate_partial_implementation():
    """A subclass that doesn't implement all abstract methods must not instantiate."""

    class Partial(DatabaseInterface):
        async def initialize(self) -> None:  # implements only two
            pass

        async def close(self) -> None:
            pass

    with pytest.raises(TypeError):
        Partial()


class DummyDB(DatabaseInterface):
    """
    Minimal concrete implementation that:
      1) calls super().<method>(...) to execute the base 'pass' lines (for coverage)
      2) returns simple sentinel values so the tests can run end-to-end
    """

    def __init__(self):
        self.calls = []

    async def initialize(self) -> None:
        self.calls.append("initialize")
        await super().initialize()

    async def close(self) -> None:
        self.calls.append("close")
        await super().close()

    async def store_user_info(self, nickname: str, public_key: str) -> None:
        self.calls.append(("store_user_info", nickname, public_key))
        await super().store_user_info(nickname, public_key)

    async def create_package(self, package, content: bytes) -> str:
        self.calls.append(("create_package", package, content))
        await super().create_package(package, content)
        return "pkg-1"

    async def get_package(self, name: str, version: str | None = None):
        self.calls.append(("get_package", name, version))
        await super().get_package(name, version)
        return None  # Optional[PackageMetadata]

    async def get_package_content(self, name: str, version: str | None = None) -> bytes | None:
        self.calls.append(("get_package_content", name, version))
        await super().get_package_content(name, version)
        return b""  # Optional[bytes]

    async def get_package_with_content(self, name: str, version: str | None = None):
        self.calls.append(("get_package_with_content", name, version))
        await super().get_package_with_content(name, version)
        return None  # Optional[Tuple[PackageMetadata, bytes]]

    async def list_packages(
        self, limit: int = 100, offset: int = 0, status: str | None = None
    ):
        self.calls.append(("list_packages", limit, offset, status))
        await super().list_packages(limit, offset, status)
        return []  # List[PackageMetadata]

    async def update_package(self, name: str, version: str, updates: dict[str, object]) -> bool:
        self.calls.append(("update_package", name, version, updates))
        await super().update_package(name, version, updates)
        return True

    async def delete_package(self, name: str, version: str) -> bool:
        self.calls.append(("delete_package", name, version))
        await super().delete_package(name, version)
        return True

    async def search_packages(self, query: str, limit: int = 50):
        self.calls.append(("search_packages", query, limit))
        await super().search_packages(query, limit)
        return []  # List[PackageMetadata]

    async def get_package_versions(self, name: str) -> list[str]:
        self.calls.append(("get_package_versions", name))
        await super().get_package_versions(name)
        return ["1.0.0"]

    async def get_package_count(self) -> int:
        self.calls.append(("get_package_count",))
        await super().get_package_count()
        return 0

    async def get_trending_packages(self, days: int = 7, limit: int = 10):
        self.calls.append(("get_trending_packages", days, limit))
        await super().get_trending_packages(days, limit)
        return []  # List[PackageMetadata]

    async def record_download(
        self, package_id: int, user_agent: str | None = None, ip_address: str | None = None
    ) -> None:
        self.calls.append(("record_download", package_id, user_agent, ip_address))
        await super().record_download(package_id, user_agent, ip_address)


@pytest.mark.asyncio
async def test_super_calls_exercise_all_base_pass_lines():
    """Call every method once to execute the base 'pass' statements for coverage."""
    db = DummyDB()

    # Call everything; we don't rely on concrete models here—type hints aren't enforced at runtime.
    await db.initialize()
    await db.store_user_info("nick", "ssh-ed25519 AAA...")

    # Use simple sentinel values; base methods are no-ops, we just want to execute them.
    pkg_id = await db.create_package(None, b"echo hi")
    assert pkg_id == "pkg-1"

    assert await db.get_package("foo") is None
    assert await db.get_package("foo", version="1.0.0") is None

    assert await db.get_package_content("foo") == b""
    assert await db.get_package_content("foo", version="1.0.0") == b""

    assert await db.get_package_with_content("foo") is None

    assert await db.list_packages() == []
    assert await db.list_packages(limit=5, offset=10, status="published") == []

    assert await db.update_package("foo", "1.0.0", {"description": "x"})
    assert await db.delete_package("foo", "1.0.0")

    assert await db.search_packages("foo") == []
    assert await db.get_package_versions("foo") == ["1.0.0"]
    assert await db.get_package_count() == 0
    assert await db.get_trending_packages() == []

    await db.record_download(1, user_agent="pytest", ip_address="127.0.0.1")
    await db.close()

    # Sanity: we touched each method
    called = {c[0] if isinstance(c, tuple) else c for c in db.calls}
    expected_called = {
        "initialize",
        "close",
        "store_user_info",
        "create_package",
        "get_package",
        "get_package_content",
        "get_package_with_content",
        "list_packages",
        "update_package",
        "delete_package",
        "search_packages",
        "get_package_versions",
        "get_package_count",
        "get_trending_packages",
        "record_download",
    }
    assert expected_called.issubset(called)
