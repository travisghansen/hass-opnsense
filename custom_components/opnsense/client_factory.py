"""Client factory for selecting legacy or external OPNsense backends."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, MutableMapping
from importlib import import_module
import logging
from typing import Any

import aiohttp
import awesomeversion

from .client_protocol import OPNsenseClientProtocol
from .pyopnsense import OPNsenseClient as LegacyOPNsenseClient

_LOGGER: logging.Logger = logging.getLogger(__name__)
AI_OPNSENSE_MIN_FIRMWARE = "26.1.1"


class MissingExternalAiopnsenseDependency(ImportError):
    """Raised when external ``aiopnsense`` is required but unavailable."""


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
    """Build normalized client constructor kwargs.

    Parameters
    ----------
    url : str
        OPNsense base URL.
    username : str
        API username.
    password : str
        API password.
    session : aiohttp.ClientSession
        Shared aiohttp session.
    opts : MutableMapping[str, Any] | None
        Optional connection options.
    initial : bool
        Whether client is created for initial setup.
    name : str | None
        Optional display name.

    Returns
    -------
    dict[str, Any]
        Keyword arguments for client construction.

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
    """Normalize heterogeneous query count payloads to an integer tuple.

    Parameters
    ----------
    count_value : Any
        Value returned by compatibility query count methods.

    Returns
    -------
    tuple[int, int]
        ``(rest_api_count, xmlrpc_count)``.

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
        except (TypeError, ValueError):
            return (0, 0)
    return (0, 0)


def _add_query_count_compat(client: OPNsenseClientProtocol) -> OPNsenseClientProtocol:
    """Attach query-count compatibility shim when needed.

    Parameters
    ----------
    client : OPNsenseClientProtocol
        Client instance to patch when required.

    Returns
    -------
    OPNsenseClientProtocol
        The original client with potential compatibility method attached.

    """
    get_query_counts: Callable[[], Any] | None = getattr(client, "get_query_counts", None)
    if get_query_counts is not None:

        async def _get_query_counts() -> tuple[int, int]:
            count_value = await get_query_counts()
            return _coerce_query_counts(count_value)

        setattr(client, "get_query_counts", _get_query_counts)
        _LOGGER.debug("Applied aiopnsense query-count normalization shim using get_query_counts()")
        return client

    get_query_count: Callable[[], Any] | None = getattr(client, "get_query_count", None)
    if get_query_count is not None:

        async def _get_query_counts() -> tuple[int, int]:
            count_value = await get_query_count()
            return _coerce_query_counts(count_value)

        setattr(client, "get_query_counts", _get_query_counts)
        _LOGGER.debug("Applied aiopnsense query-count compatibility shim using get_query_count()")

    return client


def _add_plugin_compat(client: OPNsenseClientProtocol) -> OPNsenseClientProtocol:
    """Attach plugin compatibility shims when external backends lack methods.

    Parameters
    ----------
    client : OPNsenseClientProtocol
        Client instance to patch when required.

    Returns
    -------
    OPNsenseClientProtocol
        The original client with potential plugin compatibility methods attached.

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

        async def _is_plugin_installed() -> bool:
            def _plugin_present_from_payload(payload: Any) -> bool:
                if isinstance(payload, Mapping):
                    if "os-homeassistant-maxit" in payload:
                        return True
                    package_list = payload.get("package")
                    if isinstance(package_list, list):
                        for pkg in package_list:
                            if (
                                isinstance(pkg, Mapping)
                                and pkg.get("name") == "os-homeassistant-maxit"
                                and str(pkg.get("installed")) == "1"
                            ):
                                return True
                    return False
                if isinstance(payload, list | set | tuple):
                    for item in payload:
                        if item == "os-homeassistant-maxit":
                            return True
                        if (
                            isinstance(item, Mapping)
                            and item.get("name") == "os-homeassistant-maxit"
                            and str(item.get("installed")) == "1"
                        ):
                            return True
                return False

            if is_named_plugin_installed is not None:
                result = await is_named_plugin_installed("os-homeassistant-maxit")
                return bool(result)
            if get_installed_plugins is not None:
                plugins = await get_installed_plugins()
                if _plugin_present_from_payload(plugins):
                    return True
            if get_firmware_info is not None:
                firmware_info = await get_firmware_info()
                if _plugin_present_from_payload(firmware_info):
                    return True
            if safe_dict_get is not None:
                firmware_info = await safe_dict_get("/api/core/firmware/info")
                if _plugin_present_from_payload(firmware_info):
                    return True
            return False

        setattr(client, "is_plugin_installed", _is_plugin_installed)
        _LOGGER.debug("Applied aiopnsense plugin compatibility shim for is_plugin_installed()")

    if not hasattr(client, "is_plugin_deprecated"):

        async def _is_plugin_deprecated() -> bool:
            return False

        setattr(client, "is_plugin_deprecated", _is_plugin_deprecated)
        _LOGGER.debug("Applied aiopnsense plugin compatibility shim for is_plugin_deprecated()")

    return client


def _add_core_compat(client: OPNsenseClientProtocol) -> OPNsenseClientProtocol:
    """Attach compatibility shims for core client lifecycle/query methods.

    Parameters
    ----------
    client : OPNsenseClientProtocol
        Client instance to patch when required.

    Returns
    -------
    OPNsenseClientProtocol
        The original client with potential core compatibility methods attached.

    """
    if not hasattr(client, "set_use_snake_case"):

        async def _set_use_snake_case(initial: bool = False) -> None:
            _ = initial

        setattr(client, "set_use_snake_case", _set_use_snake_case)
        _LOGGER.debug("Applied aiopnsense core compatibility shim for set_use_snake_case()")

    if not hasattr(client, "reset_query_counts"):

        async def _reset_query_counts() -> None:
            return None

        setattr(client, "reset_query_counts", _reset_query_counts)
        _LOGGER.debug("Applied aiopnsense core compatibility shim for reset_query_counts()")

    if not hasattr(client, "get_query_counts"):

        async def _get_query_counts() -> tuple[int, int]:
            return (0, 0)

        setattr(client, "get_query_counts", _get_query_counts)
        _LOGGER.debug("Applied aiopnsense core compatibility shim for get_query_counts()")

    return client


async def _create_external_client(**kwargs: Any) -> OPNsenseClientProtocol:
    """Create external ``aiopnsense`` client instance.

    Parameters
    ----------
    **kwargs : Any
        Client construction kwargs.

    Returns
    -------
    OPNsenseClientProtocol
        External client instance.

    Raises
    ------
    MissingExternalAiopnsenseDependency
        Raised when package import or construction fails.

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
    """Create firmware-routed OPNsense client backend.

    Parameters
    ----------
    url : str
        OPNsense base URL.
    username : str
        API username.
    password : str
        API password.
    session : aiohttp.ClientSession
        Shared aiohttp session.
    opts : MutableMapping[str, Any] | None
        Optional connection options.
    initial : bool
        Whether this client is created during initial setup.
    name : str | None
        Optional display name.

    Returns
    -------
    OPNsenseClientProtocol
        Firmware-routed client backend.

    Raises
    ------
    MissingExternalAiopnsenseDependency
        Raised when firmware requires external backend but dependency is absent.

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
    _LOGGER.debug("Client factory detected firmware: %s", firmware)

    try:
        if awesomeversion.AwesomeVersion(firmware) >= awesomeversion.AwesomeVersion(
            AI_OPNSENSE_MIN_FIRMWARE
        ):
            await probe_client.async_close()
            _LOGGER.debug(
                "Using external aiopnsense backend for firmware >= %s",
                AI_OPNSENSE_MIN_FIRMWARE,
            )
            return await _create_external_client(**kwargs)
    except (awesomeversion.exceptions.AwesomeVersionCompareException, TypeError, ValueError):
        _LOGGER.debug(
            "Unable to compare firmware '%s' in client factory. Falling back to legacy backend.",
            firmware,
        )

    _LOGGER.debug("Using bundled legacy pyopnsense backend")
    return probe_client
