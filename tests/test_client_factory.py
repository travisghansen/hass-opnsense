"""Tests for firmware-based OPNsense client factory routing."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from custom_components.opnsense import client_factory as factory_mod


def test_coerce_query_counts_variants() -> None:
    """_coerce_query_counts should normalize tuple/list/mapping/scalar forms."""
    assert factory_mod._coerce_query_counts([1, 2, 3]) == (1, 2)
    assert factory_mod._coerce_query_counts([9]) == (9, 0)
    assert factory_mod._coerce_query_counts([]) == (0, 0)
    assert factory_mod._coerce_query_counts({"rest_api_count": "7", "xmlrpc_count": 8}) == (7, 8)
    assert factory_mod._coerce_query_counts({"rest": 4, "xmlrpc": "5"}) == (4, 5)
    assert factory_mod._coerce_query_counts("11") == (11, 0)
    assert factory_mod._coerce_query_counts("not-a-number") == (0, 0)
    assert factory_mod._coerce_query_counts(object()) == (0, 0)


@pytest.mark.asyncio
async def test_add_query_count_compat_noop_when_get_query_counts_exists() -> None:
    """Compatibility shim should preserve tuple results from get_query_counts."""

    class _Client:
        async def get_query_counts(self) -> tuple[int, int]:
            """Return already-normalized query counters for compatibility testing."""
            return (1, 2)

    client = _Client()
    patched: Any = factory_mod._add_query_count_compat(client)
    assert await patched.get_query_counts() == (1, 2)


@pytest.mark.asyncio
async def test_add_query_count_compat_normalizes_existing_get_query_counts() -> None:
    """Compatibility shim should normalize scalar return types from get_query_counts."""

    class _Client:
        async def get_query_counts(self) -> int:
            """Return scalar query counter to test normalization behavior."""
            return 7

    client = _Client()
    patched: Any = factory_mod._add_query_count_compat(client)
    assert await patched.get_query_counts() == (7, 0)


@pytest.mark.asyncio
async def test_add_plugin_compat_noop_when_plugin_methods_exist() -> None:
    """Plugin compatibility shim should not override existing plugin methods."""

    class _Client:
        async def is_plugin_installed(self) -> bool:
            """Return installed state so shim does not override existing method."""
            return True

        async def is_plugin_deprecated(self) -> bool:
            """Return deprecated state so shim does not override existing method."""
            return True

    client = _Client()
    patched: Any = factory_mod._add_plugin_compat(client)
    assert await patched.is_plugin_installed() is True
    assert await patched.is_plugin_deprecated() is True


@pytest.mark.asyncio
async def test_add_plugin_compat_uses_is_named_plugin_installed() -> None:
    """Plugin compatibility shim should use is_named_plugin_installed when available."""

    class _Client:
        async def is_named_plugin_installed(self, plugin_name: str) -> bool:
            """Return whether requested plugin name matches the test plugin.

            Args:
                plugin_name: Plugin name checked by the compatibility shim.

            Returns:
                bool: `True` when requested plugin is `os-homeassistant-maxit`.
            """
            return plugin_name == "os-homeassistant-maxit"

    client = _Client()
    patched: Any = factory_mod._add_plugin_compat(client)
    assert await patched.is_plugin_installed() is True
    assert await patched.is_plugin_deprecated() is False


@pytest.mark.asyncio
async def test_add_plugin_compat_uses_installed_plugins_collection() -> None:
    """Plugin compatibility shim should detect plugin from installed-plugin collection."""

    class _Client:
        async def get_installed_plugins(self) -> set[str]:
            """Return installed plugin names for collection-based detection tests."""
            return {"os-vnstat", "os-homeassistant-maxit"}

    client = _Client()
    patched: Any = factory_mod._add_plugin_compat(client)
    assert await patched.is_plugin_installed() is True
    assert await patched.is_plugin_deprecated() is False


@pytest.mark.asyncio
async def test_add_plugin_compat_uses_installed_plugins_package_rows() -> None:
    """Plugin compatibility shim should parse package rows from installed plugins."""

    class _Client:
        async def get_installed_plugins(self) -> list[dict[str, str]]:
            """Return package rows for row-based plugin detection tests."""
            return [
                {"name": "os-vnstat", "installed": "1"},
                {"name": "os-homeassistant-maxit", "installed": "1"},
            ]

    client = _Client()
    patched: Any = factory_mod._add_plugin_compat(client)
    assert await patched.is_plugin_installed() is True
    assert await patched.is_plugin_deprecated() is False


@pytest.mark.asyncio
async def test_add_plugin_compat_uses_firmware_info_when_plugin_helpers_missing() -> None:
    """Plugin compatibility shim should fallback to firmware info package payload."""

    class _Client:
        async def get_firmware_info(self) -> dict[str, Any]:
            """Return firmware payload containing package metadata for plugin detection."""
            return {
                "package": [
                    {"name": "os-homeassistant-maxit", "installed": "1"},
                ]
            }

    client = _Client()
    patched: Any = factory_mod._add_plugin_compat(client)
    assert await patched.is_plugin_installed() is True
    assert await patched.is_plugin_deprecated() is False


@pytest.mark.asyncio
async def test_add_plugin_compat_caches_safe_dict_firmware_info() -> None:
    """Plugin compatibility shim should cache firmware-info package lookups."""

    class _Client:
        def __init__(self) -> None:
            """Initialize fake client with firmware-info fallback response."""
            self._safe_dict_get = AsyncMock(
                return_value={
                    "package": [
                        {"name": "os-vnstat", "installed": "1"},
                        {"name": "os-homeassistant-maxit", "installed": "1"},
                    ]
                }
            )

    client = _Client()
    patched: Any = factory_mod._add_plugin_compat(client)
    assert await patched.is_plugin_installed() is True
    assert await patched.is_plugin_installed() is True
    client._safe_dict_get.assert_awaited_once_with("/api/core/firmware/info")


@pytest.mark.asyncio
async def test_add_plugin_compat_caches_absent_plugin_from_firmware_info() -> None:
    """Plugin compatibility shim should cache successful negative firmware-info lookups."""

    class _Client:
        def __init__(self) -> None:
            """Initialize fake client with firmware-info payload that lacks plugin."""
            self._safe_dict_get = AsyncMock(
                return_value={"package": [{"name": "os-vnstat", "installed": "1"}]}
            )

    client = _Client()
    patched: Any = factory_mod._add_plugin_compat(client)
    assert await patched.is_plugin_installed() is False
    assert await patched.is_plugin_installed() is False
    client._safe_dict_get.assert_awaited_once_with("/api/core/firmware/info")


@pytest.mark.asyncio
async def test_add_plugin_compat_retries_inconclusive_direct_key_payload() -> None:
    """Plugin compatibility shim should retry direct-key payloads without target plugin."""

    class _Client:
        def __init__(self) -> None:
            """Initialize fake client with inconclusive then valid direct-key payloads."""
            self._safe_dict_get = AsyncMock(
                side_effect=[
                    {"os-vnstat": "1"},
                    {"os-homeassistant-maxit": "1"},
                ]
            )

    client = _Client()
    patched: Any = factory_mod._add_plugin_compat(client)
    assert await patched.is_plugin_installed() is False
    assert await patched.is_plugin_installed() is True
    assert client._safe_dict_get.await_count == 2


@pytest.mark.asyncio
async def test_add_plugin_compat_retries_invalid_firmware_info_payload() -> None:
    """Plugin compatibility shim should not cache invalid firmware-info payloads."""

    class _Client:
        def __init__(self) -> None:
            """Initialize fake client with invalid then valid firmware-info payloads."""
            self._safe_dict_get = AsyncMock(
                side_effect=[
                    None,
                    {"package": [{"name": "os-homeassistant-maxit", "installed": "1"}]},
                ]
            )

    client = _Client()
    patched: Any = factory_mod._add_plugin_compat(client)
    assert await patched.is_plugin_installed() is False
    assert await patched.is_plugin_installed() is True
    assert client._safe_dict_get.await_count == 2


@pytest.mark.asyncio
async def test_add_plugin_compat_defaults_to_false_without_helpers() -> None:
    """Plugin compatibility shim should return False when no plugin helpers exist."""

    class _Client:
        pass

    client = _Client()
    patched: Any = factory_mod._add_plugin_compat(client)
    assert await patched.is_plugin_installed() is False
    assert await patched.is_plugin_deprecated() is False


@pytest.mark.asyncio
async def test_add_core_compat_noop_when_core_methods_exist() -> None:
    """Core compatibility shim should not override existing core methods."""

    class _Client:
        async def set_use_snake_case(self, initial: bool = False) -> None:
            """Accept naming-mode call so shim preserves existing implementation.

            Args:
                initial: Initial-setup flag passed by caller.
            """
            return

        async def reset_query_counts(self) -> None:
            """Accept query-counter reset call in no-op compatibility test."""
            return

        async def get_query_counts(self) -> tuple[int, int]:
            """Return query counters so shim preserves existing implementation."""
            return (3, 4)

    client = _Client()
    patched: Any = factory_mod._add_core_compat(client)
    await patched.set_use_snake_case(initial=True)
    await patched.reset_query_counts()
    assert await patched.get_query_counts() == (3, 4)


@pytest.mark.asyncio
async def test_add_core_compat_defaults_when_core_methods_missing() -> None:
    """Core compatibility shim should attach defaults when methods are missing."""

    class _Client:
        pass

    client = _Client()
    patched: Any = factory_mod._add_core_compat(client)
    await patched.set_use_snake_case(initial=True)
    await patched.reset_query_counts()
    assert await patched.get_query_counts() == (0, 0)


def test_add_query_count_compat_noop_without_query_methods() -> None:
    """Compatibility shim should return original client when no query methods exist."""

    class _Client:
        pass

    client = _Client()
    patched: Any = factory_mod._add_query_count_compat(client)
    assert not hasattr(patched, "get_query_counts")


@pytest.mark.asyncio
async def test_create_client_uses_legacy_for_old_firmware(monkeypatch: pytest.MonkeyPatch) -> None:
    """Factory should return the bundled legacy client for old firmware."""

    class _LegacyClient:
        def __init__(self, **kwargs: Any) -> None:
            """Initialize fake legacy client used for old-firmware routing tests.

            Args:
                **kwargs: Unused constructor kwargs passed by factory.
            """
            self.closed = False

        async def get_host_firmware_version(self) -> str:
            """Return old firmware value so factory keeps legacy backend."""
            return "25.7"

        async def async_close(self) -> None:
            """Record close calls from factory probe cleanup."""
            self.closed = True

    monkeypatch.setattr(factory_mod, "LegacyOPNsenseClient", _LegacyClient)

    client = await factory_mod.create_opnsense_client(
        url="https://router",
        username="u",
        password="p",
        session=SimpleNamespace(),
        opts={"verify_ssl": True},
    )
    assert isinstance(client, _LegacyClient)
    assert client.closed is False


@pytest.mark.asyncio
async def test_create_client_uses_external_for_new_firmware(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Factory should route firmware >= 26.1.1 to external aiopnsense client."""
    created: dict[str, Any] = {"legacy_closed": False, "attempts": 0}

    class _LegacyClient:
        def __init__(self, **kwargs: Any) -> None:
            """Initialize fake legacy probe client for external-routing tests.

            Args:
                **kwargs: Unused constructor kwargs passed by factory.
            """
            return

        async def get_host_firmware_version(self) -> str:
            """Return new firmware value so factory routes to external backend."""
            return "26.1.1"

        async def async_close(self) -> None:
            """Record that probe client was closed before switching backends."""
            created["legacy_closed"] = True

    class _ExternalClient:
        def __init__(self, **kwargs: Any) -> None:
            """Simulate first-attempt constructor failure and second-attempt success.

            Args:
                **kwargs: Constructor kwargs passed by factory.

            Raises:
                TypeError: Raised on first invocation to trigger fallback kwargs retry.
            """
            created["attempts"] += 1
            self.attempt = created["attempts"]
            if self.attempt == 1:
                raise TypeError("unsupported kwargs")
            self.kwargs = kwargs

        async def get_query_count(self) -> int:
            """Return scalar query count so compatibility shim can normalize it."""
            return 5

    monkeypatch.setattr(factory_mod, "LegacyOPNsenseClient", _LegacyClient)
    monkeypatch.setattr(
        factory_mod,
        "import_module",
        lambda module_name: SimpleNamespace(OPNsenseClient=_ExternalClient),
    )

    client = await factory_mod.create_opnsense_client(
        url="https://router",
        username="u",
        password="p",
        session=SimpleNamespace(),
        opts={"verify_ssl": True},
        name="Test Router",
    )
    assert isinstance(client, _ExternalClient)
    assert client.attempt == 2
    assert created["legacy_closed"] is True
    assert "name" not in client.kwargs
    assert "initial" not in client.kwargs
    assert await client.get_query_counts() == (5, 0)


@pytest.mark.asyncio
async def test_create_client_logs_external_version_for_new_firmware(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Factory should log external aiopnsense version when routing to external backend."""

    class _LegacyClient:
        async def get_host_firmware_version(self) -> str:
            """Return new firmware so factory selects external backend."""
            return "26.3"

        async def async_close(self) -> None:
            """Provide cleanup hook expected by factory code paths."""
            return

    class _ExternalClient:
        pass

    monkeypatch.setattr(factory_mod, "LegacyOPNsenseClient", lambda **kwargs: _LegacyClient())
    monkeypatch.setattr(
        factory_mod, "_create_external_client", AsyncMock(return_value=_ExternalClient())
    )
    monkeypatch.setattr(
        factory_mod, "_get_external_aiopnsense_version", AsyncMock(return_value="1.0.2")
    )

    caplog.set_level("INFO")
    client = await factory_mod.create_opnsense_client(
        url="https://router",
        username="u",
        password="p",
        session=SimpleNamespace(),
        opts={"verify_ssl": True},
    )

    assert isinstance(client, _ExternalClient)
    assert "Using aiopnsense 1.0.2 for firmware >= 26.1.1" in caplog.text


@pytest.mark.asyncio
async def test_create_external_client_retries_without_name_and_initial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """External constructor should retry when first call rejects name/initial kwargs."""
    calls: list[dict[str, Any]] = []

    class _ExternalClient:
        def __init__(self, **kwargs: Any) -> None:
            """Capture kwargs and fail on unsupported keys to test retry behavior.

            Args:
                **kwargs: Constructor kwargs passed by factory.

            Raises:
                TypeError: Raised when unsupported kwargs are present.
            """
            calls.append(kwargs)
            if "name" in kwargs or "initial" in kwargs:
                raise TypeError("unsupported kwargs")

    monkeypatch.setattr(
        factory_mod,
        "import_module",
        lambda module_name: SimpleNamespace(OPNsenseClient=_ExternalClient),
    )

    client = await factory_mod._create_external_client(
        url="https://router",
        username="u",
        password="p",
        session=SimpleNamespace(),
        opts={"verify_ssl": True},
        name="Router",
        initial=True,
    )
    assert isinstance(client, _ExternalClient)
    assert len(calls) == 2
    assert "name" in calls[0] and "initial" in calls[0]
    assert "name" not in calls[1] and "initial" not in calls[1]


@pytest.mark.asyncio
async def test_create_external_client_raises_when_missing_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """External client creation should fail when module misses OPNsenseClient attribute."""
    monkeypatch.setattr(factory_mod, "import_module", lambda module_name: SimpleNamespace())

    with pytest.raises(factory_mod.MissingExternalAiopnsenseDependency):
        await factory_mod._create_external_client(
            url="https://router",
            username="u",
            password="p",
            session=SimpleNamespace(),
            opts={"verify_ssl": True},
        )


@pytest.mark.asyncio
async def test_create_external_client_raises_when_retry_still_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """External client creation should fail when both constructor attempts fail."""

    class _ExternalClient:
        def __init__(self, **kwargs: Any) -> None:
            """Always fail constructor to validate dependency-wrapping path.

            Args:
                **kwargs: Constructor kwargs passed by factory.

            Raises:
                TypeError: Always raised by this stub.
            """
            raise TypeError("always fails")

    monkeypatch.setattr(
        factory_mod,
        "import_module",
        lambda module_name: SimpleNamespace(OPNsenseClient=_ExternalClient),
    )

    with pytest.raises(factory_mod.MissingExternalAiopnsenseDependency):
        await factory_mod._create_external_client(
            url="https://router",
            username="u",
            password="p",
            session=SimpleNamespace(),
            opts={"verify_ssl": True},
            name="Router",
            initial=True,
        )


@pytest.mark.asyncio
async def test_create_client_raises_when_external_dependency_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Factory should raise dedicated dependency error for new firmware."""

    class _LegacyClient:
        def __init__(self, **kwargs: Any) -> None:
            """Initialize fake legacy probe for missing-dependency test.

            Args:
                **kwargs: Unused constructor kwargs passed by factory.
            """
            return

        async def get_host_firmware_version(self) -> str:
            """Return new firmware so external backend path is exercised."""
            return "26.2"

        async def async_close(self) -> None:
            """Provide cleanup hook expected by factory code paths."""
            return

    monkeypatch.setattr(factory_mod, "LegacyOPNsenseClient", _LegacyClient)

    def _raise_import_error(module_name: str) -> Any:
        """Raise import error to emulate missing external dependency.

        Args:
            module_name: Module name requested by the factory.

        Raises:
            ImportError: Always raised by this stub.
        """
        raise ImportError("not found")

    monkeypatch.setattr(factory_mod, "import_module", _raise_import_error)

    with pytest.raises(factory_mod.MissingExternalAiopnsenseDependency):
        await factory_mod.create_opnsense_client(
            url="https://router",
            username="u",
            password="p",
            session=SimpleNamespace(),
            opts={"verify_ssl": True},
        )


@pytest.mark.asyncio
async def test_create_client_falls_back_to_legacy_on_uncomparable_firmware(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Factory should keep legacy backend when firmware comparison raises."""

    class _LegacyClient:
        def __init__(self, **kwargs: Any) -> None:
            """Initialize fake legacy client used in compare-failure fallback tests.

            Args:
                **kwargs: Unused constructor kwargs passed by factory.
            """
            self.closed = False

        async def get_host_firmware_version(self) -> str:
            """Return non-comparable firmware string for fallback scenario."""
            return "weird"

        async def async_close(self) -> None:
            """Record close calls from factory cleanup paths."""
            self.closed = True

    class _BrokenAwesomeVersion:
        def __init__(self, value: Any) -> None:
            """Store wrapped version value for comparison-stub parity.

            Args:
                value: Version payload passed by factory compare logic.
            """
            self.value = value

        def __ge__(self, other: Any) -> bool:
            """Raise compare error to force legacy fallback behavior.

            Args:
                other: Comparison target ignored by this stub.

            Raises:
                ValueError: Always raised by this comparison stub.
            """
            raise ValueError("cannot compare")

    monkeypatch.setattr(factory_mod, "LegacyOPNsenseClient", _LegacyClient)
    monkeypatch.setattr(factory_mod.awesomeversion, "AwesomeVersion", _BrokenAwesomeVersion)

    client = await factory_mod.create_opnsense_client(
        url="https://router",
        username="u",
        password="p",
        session=SimpleNamespace(),
        opts={"verify_ssl": True},
    )
    assert isinstance(client, _LegacyClient)
    assert client.closed is False


@pytest.mark.asyncio
async def test_create_client_closes_probe_when_firmware_probe_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Factory should close the probe client and re-raise when probe fails."""
    closed = {"value": False}

    class _LegacyClient:
        def __init__(self, **kwargs: Any) -> None:
            """Initialize fake probe client used in probe-failure tests.

            Args:
                **kwargs: Unused constructor kwargs passed by factory.
            """
            return

        async def get_host_firmware_version(self) -> str:
            """Raise probe error to test close-and-reraise behavior.

            Raises:
                RuntimeError: Always raised by this stub.
            """
            raise RuntimeError("probe failed")

        async def async_close(self) -> None:
            """Record close call after probe failure."""
            closed["value"] = True

    monkeypatch.setattr(factory_mod, "LegacyOPNsenseClient", _LegacyClient)

    with pytest.raises(RuntimeError, match="probe failed"):
        await factory_mod.create_opnsense_client(
            url="https://router",
            username="u",
            password="p",
            session=SimpleNamespace(),
            opts={"verify_ssl": True},
        )
    assert closed["value"] is True
