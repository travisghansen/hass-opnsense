"""Client factory for selecting legacy or external OPNsense backends."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, MutableMapping
from datetime import datetime
from importlib import import_module
from importlib.metadata import PackageNotFoundError, version as package_version
import logging
from typing import Any

import aiohttp
import awesomeversion

from .client_protocol import OPNsenseClientProtocol
from .pyopnsense import OPNsenseClient as LegacyOPNsenseClient

_LOGGER: logging.Logger = logging.getLogger(__name__)
AIOPNSENSE_MIN_FIRMWARE = "26.1.1"


class MissingExternalAiopnsenseDependency(ImportError):
    """Raised when external ``aiopnsense`` is required but unavailable."""


async def _get_external_aiopnsense_version() -> str | None:
    """Resolve installed external aiopnsense version in a non-blocking way.

    Returns:
        str | None: aiopnsense package version string when available, else `None`.
    """
    try:
        external_module = await asyncio.to_thread(import_module, "aiopnsense")
    except ImportError:
        return None

    module_version: Any = getattr(external_module, "__version__", None)
    if isinstance(module_version, str) and module_version.strip():
        return module_version.strip()

    try:
        return await asyncio.to_thread(package_version, "aiopnsense")
    except PackageNotFoundError:
        return None


def _build_client_kwargs(
    *,
    url: str,
    username: str,
    password: str,
    session: aiohttp.ClientSession,
    opts: MutableMapping[str, Any] | None = None,
    initial: bool = False,
    name: str | None = None,
) -> dict[str, Any]:
    """Build normalized keyword arguments for client construction.

    Args:
        url: Base URL for the OPNsense host.
        username: API username used for authentication.
        password: API password used for authentication.
        session: Shared aiohttp session used by the client.
        opts: Optional transport options, such as SSL verification flags.
        initial: Whether the client is being created for initial setup validation.
        name: Optional display name for logs and diagnostics.

    Returns:
        dict[str, Any]: Constructor kwargs accepted by legacy and external client classes.
    """
    kwargs: dict[str, Any] = {
        "url": url,
        "username": username,
        "password": password,
        "session": session,
        "opts": opts,
        "initial": initial,
    }
    if name is not None:
        kwargs["name"] = name
    return kwargs


def _coerce_query_counts(count_value: Any) -> tuple[int, int]:
    """Normalize query count payloads to `(rest_api_count, xmlrpc_count)`.

    Args:
        count_value: Raw value returned by backend query-count helpers.

    Returns:
        tuple[int, int]: REST and XML-RPC query totals coerced to integers.
    """
    if isinstance(count_value, tuple | list):
        if len(count_value) >= 2:
            return int(count_value[0]), int(count_value[1])
        if len(count_value) == 1:
            return int(count_value[0]), 0
        return (0, 0)
    if isinstance(count_value, Mapping):
        rest_count = count_value.get("rest_api_count", count_value.get("rest", 0))
        xmlrpc_count = count_value.get("xmlrpc_count", count_value.get("xmlrpc", 0))
        return int(rest_count), int(xmlrpc_count)
    if isinstance(count_value, int | float | str):
        try:
            return int(count_value), 0
        except TypeError, ValueError:
            return (0, 0)
    return (0, 0)


def _add_query_count_compat(client: OPNsenseClientProtocol) -> OPNsenseClientProtocol:
    """Attach query-count compatibility wrappers for backend differences.

    Args:
        client: Client instance that may expose non-uniform query count helpers.

    Returns:
        OPNsenseClientProtocol: The same client instance with normalized query count behavior.
    """
    get_query_counts: Callable[[], Any] | None = getattr(client, "get_query_counts", None)
    if get_query_counts is not None:

        async def _get_query_counts() -> tuple[int, int]:
            """Return normalized query counters from `get_query_counts`.

            Returns:
                tuple[int, int]: REST and XML-RPC query totals.
            """
            count_value = await get_query_counts()
            return _coerce_query_counts(count_value)

        setattr(client, "get_query_counts", _get_query_counts)
        _LOGGER.debug("Applied aiopnsense query-count normalization shim using get_query_counts()")
        return client

    get_query_count: Callable[[], Any] | None = getattr(client, "get_query_count", None)
    if get_query_count is not None:

        async def _get_query_counts() -> tuple[int, int]:
            """Return normalized query counters from legacy `get_query_count`.

            Returns:
                tuple[int, int]: REST and XML-RPC query totals.
            """
            count_value = await get_query_count()
            return _coerce_query_counts(count_value)

        setattr(client, "get_query_counts", _get_query_counts)
        _LOGGER.debug("Applied aiopnsense query-count compatibility shim using get_query_count()")

    return client


def _add_plugin_compat(client: OPNsenseClientProtocol) -> OPNsenseClientProtocol:
    """Attach plugin capability shims when backend methods are missing.

    Args:
        client: Client instance to patch with plugin-related compatibility methods.

    Returns:
        OPNsenseClientProtocol: The same client instance with plugin compatibility methods.
    """
    if not hasattr(client, "is_plugin_installed"):
        is_named_plugin_installed: Callable[[str], Any] | None = getattr(
            client, "is_named_plugin_installed", None
        )
        get_installed_plugins: Callable[[], Any] | None = getattr(
            client, "get_installed_plugins", None
        )
        get_firmware_info: Callable[[], Any] | None = getattr(client, "get_firmware_info", None)
        safe_dict_get: Callable[[str], Any] | None = getattr(client, "_safe_dict_get", None)
        installed_plugins_cache: set[str] | None = None
        installed_plugins_updated_at: datetime | None = None
        installed_plugins_refresh_succeeded = False
        plugin_cache_ttl_seconds = int(
            getattr(
                client,
                "_plugin_cache_ttl_seconds",
                getattr(client, "_endpoint_cache_ttl_seconds", 6 * 60 * 60),
            )
        )

        async def _is_plugin_installed() -> bool:
            """Detect whether the Home Assistant OPNsense plugin is installed.

            Returns:
                bool: `True` when `os-homeassistant-maxit` is present, otherwise `False`.
            """

            nonlocal installed_plugins_cache
            nonlocal installed_plugins_updated_at
            nonlocal installed_plugins_refresh_succeeded

            def _installed_plugins_from_payload(payload: Any) -> set[str] | None:
                """Extract installed plugin names from a backend payload.

                Args:
                    payload: Firmware or plugin payload returned by backend helper methods.

                Returns:
                    set[str] | None: Installed plugin names, or `None` when payload is invalid.
                """
                if isinstance(payload, Mapping):
                    package_list = payload.get("package")
                    if isinstance(package_list, list):
                        installed_plugins: set[str] = set()
                        for pkg in package_list:
                            name = pkg.get("name") if isinstance(pkg, Mapping) else None
                            if (
                                isinstance(pkg, Mapping)
                                and isinstance(name, str)
                                and str(pkg.get("installed")) == "1"
                            ):
                                installed_plugins.add(name)
                        return installed_plugins
                    if "os-homeassistant-maxit" in payload:
                        return {str(key) for key in payload}
                    return None
                if isinstance(payload, list | set | tuple):
                    installed_plugins = set()
                    for item in payload:
                        if isinstance(item, str):
                            installed_plugins.add(item)
                        if (
                            isinstance(item, Mapping)
                            and isinstance(item.get("name"), str)
                            and str(item.get("installed")) == "1"
                        ):
                            installed_plugins.add(item["name"])
                    return installed_plugins
                return None

            async def _refresh_installed_plugins() -> None:
                """Refresh plugin names using the best available compatibility source."""
                nonlocal installed_plugins_cache
                nonlocal installed_plugins_updated_at
                nonlocal installed_plugins_refresh_succeeded

                now = datetime.now().astimezone()
                cache_is_fresh = (
                    installed_plugins_refresh_succeeded
                    and installed_plugins_cache is not None
                    and installed_plugins_updated_at is not None
                    and (now - installed_plugins_updated_at).total_seconds()
                    < plugin_cache_ttl_seconds
                )
                if cache_is_fresh:
                    return

                payload: Any | None = None
                if is_named_plugin_installed is not None:
                    installed = await is_named_plugin_installed("os-homeassistant-maxit")
                    installed_plugins_cache = {"os-homeassistant-maxit"} if installed else set()
                    installed_plugins_updated_at = now
                    installed_plugins_refresh_succeeded = True
                    return
                if get_installed_plugins is not None:
                    payload = await get_installed_plugins()
                elif get_firmware_info is not None:
                    payload = await get_firmware_info()
                elif safe_dict_get is not None:
                    payload = await safe_dict_get("/api/core/firmware/info")

                installed_plugins = _installed_plugins_from_payload(payload)
                if installed_plugins is None:
                    installed_plugins_refresh_succeeded = False
                    return

                installed_plugins_cache = installed_plugins
                installed_plugins_updated_at = now
                installed_plugins_refresh_succeeded = True

            await _refresh_installed_plugins()
            return "os-homeassistant-maxit" in (installed_plugins_cache or set())

        setattr(client, "is_plugin_installed", _is_plugin_installed)
        _LOGGER.debug("Applied aiopnsense plugin compatibility shim for is_plugin_installed()")

    if not hasattr(client, "is_plugin_deprecated"):

        async def _is_plugin_deprecated() -> bool:
            """Return a default deprecation state for unsupported backends.

            Returns:
                bool: Always `False` when backend deprecation metadata is unavailable.
            """
            return False

        setattr(client, "is_plugin_deprecated", _is_plugin_deprecated)
        _LOGGER.debug("Applied aiopnsense plugin compatibility shim for is_plugin_deprecated()")

    return client


def _add_core_compat(client: OPNsenseClientProtocol) -> OPNsenseClientProtocol:
    """Attach default implementations for required core client methods.

    Args:
        client: Client instance that may be missing required lifecycle/query methods.

    Returns:
        OPNsenseClientProtocol: The same client instance with required core compatibility shims.
    """
    if not hasattr(client, "set_use_snake_case"):

        async def _set_use_snake_case(initial: bool = False) -> None:
            """Provide a no-op naming-mode setter for backends without support.

            Args:
                initial: Whether the call occurs during initial setup.
            """
            _ = initial

        setattr(client, "set_use_snake_case", _set_use_snake_case)
        _LOGGER.debug("Applied aiopnsense core compatibility shim for set_use_snake_case()")

    if not hasattr(client, "reset_query_counts"):

        async def _reset_query_counts() -> None:
            """Provide a no-op query-counter reset for backends without support."""
            return

        setattr(client, "reset_query_counts", _reset_query_counts)
        _LOGGER.debug("Applied aiopnsense core compatibility shim for reset_query_counts()")

    if not hasattr(client, "get_query_counts"):

        async def _get_query_counts() -> tuple[int, int]:
            """Provide default zero query counters for backends without support.

            Returns:
                tuple[int, int]: A zeroed `(rest_api_count, xmlrpc_count)` tuple.
            """
            return (0, 0)

        setattr(client, "get_query_counts", _get_query_counts)
        _LOGGER.debug("Applied aiopnsense core compatibility shim for get_query_counts()")

    return client


async def _create_external_client(**kwargs: Any) -> OPNsenseClientProtocol:
    """Create an external `aiopnsense` client instance.

    Args:
        **kwargs: Normalized constructor kwargs for the external client class.

    Returns:
        OPNsenseClientProtocol: Instantiated external client implementation.

    Raises:
        MissingExternalAiopnsenseDependency: External package import or construction failed.
    """
    try:
        external_module = await asyncio.to_thread(import_module, "aiopnsense")
        external_client_class = getattr(external_module, "OPNsenseClient")
    except (AttributeError, ImportError) as err:
        raise MissingExternalAiopnsenseDependency(
            "Firmware >= 26.1.1 requires the external aiopnsense package"
        ) from err

    try:
        client = external_client_class(**kwargs)
    except TypeError:
        fallback_kwargs = dict(kwargs)
        fallback_kwargs.pop("name", None)
        fallback_kwargs.pop("initial", None)
        try:
            client = external_client_class(**fallback_kwargs)
        except TypeError as err:
            raise MissingExternalAiopnsenseDependency(
                "Unable to initialize external aiopnsense OPNsenseClient"
            ) from err

    return _add_core_compat(_add_plugin_compat(_add_query_count_compat(client)))


async def create_opnsense_client(
    *,
    url: str,
    username: str,
    password: str,
    session: aiohttp.ClientSession,
    opts: MutableMapping[str, Any] | None = None,
    initial: bool = False,
    name: str | None = None,
) -> OPNsenseClientProtocol:
    """Create the backend client selected by detected firmware.

    Args:
        url: Base URL for the OPNsense host.
        username: API username used for authentication.
        password: API password used for authentication.
        session: Shared aiohttp session used by created clients.
        opts: Optional transport options, such as SSL verification flags.
        initial: Whether the client is being created for initial setup validation.
        name: Optional display name for logs and diagnostics.

    Returns:
        OPNsenseClientProtocol: Client implementation appropriate for the detected firmware.

    Raises:
        MissingExternalAiopnsenseDependency: Firmware requires external backend but dependency is unavailable.
    """
    kwargs = _build_client_kwargs(
        url=url,
        username=username,
        password=password,
        session=session,
        opts=opts,
        initial=initial,
        name=name,
    )
    probe_client: OPNsenseClientProtocol = LegacyOPNsenseClient(**kwargs)
    try:
        firmware = await probe_client.get_host_firmware_version()
    except Exception:  # noqa: BLE001
        try:
            await probe_client.async_close()
        finally:
            raise
    # _LOGGER.debug("Client factory detected firmware: %s", firmware)

    try:
        if awesomeversion.AwesomeVersion(firmware) >= awesomeversion.AwesomeVersion(
            AIOPNSENSE_MIN_FIRMWARE
        ):
            await probe_client.async_close()
            client = await _create_external_client(**kwargs)
            aiopnsense_version: str | None = await _get_external_aiopnsense_version()
            if aiopnsense_version:
                _LOGGER.info(
                    "Using aiopnsense %s for firmware >= %s",
                    aiopnsense_version,
                    AIOPNSENSE_MIN_FIRMWARE,
                )
            else:
                _LOGGER.info(
                    "Using aiopnsense for firmware >= %s",
                    AIOPNSENSE_MIN_FIRMWARE,
                )
            return client
    except awesomeversion.exceptions.AwesomeVersionCompareException, TypeError, ValueError:
        _LOGGER.debug(
            "Unable to compare firmware '%s' in client factory. Falling back to legacy backend.",
            firmware,
        )

    _LOGGER.debug("Using bundled legacy pyopnsense backend")
    return probe_client
