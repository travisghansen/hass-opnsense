"""Client factory for creating the aiopnsense OPNsense backend."""

from __future__ import annotations

import asyncio
from importlib import import_module
from importlib.metadata import PackageNotFoundError, version as package_version
import logging
from typing import Any

import aiohttp

from .client_protocol import OPNsenseClientProtocol

_LOGGER: logging.Logger = logging.getLogger(__name__)


class MissingExternalAiopnsenseDependencyError(ImportError):
    """Raised when external ``aiopnsense`` is required but unavailable."""


MissingExternalAiopnsenseDependency = MissingExternalAiopnsenseDependencyError


async def _get_external_aiopnsense_version() -> str | None:
    """Resolve the installed aiopnsense version in a non-blocking way."""
    try:
        external_module = await asyncio.to_thread(import_module, "aiopnsense")
    except ImportError:
        return None

    module_version = getattr(external_module, "__version__", None)
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
    opts: dict[str, Any] | None = None,
    initial: bool = False,
    name: str | None = None,
) -> dict[str, Any]:
    """Build and normalize kwargs for aiopnsense client construction."""
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


async def create_opnsense_client(
    *,
    url: str,
    username: str,
    password: str,
    session: aiohttp.ClientSession,
    opts: dict[str, Any] | None = None,
    initial: bool = False,
    name: str | None = None,
) -> OPNsenseClientProtocol:
    """Create the external aiopnsense client.

    Raises:
        MissingExternalAiopnsenseDependency: External aiopnsense dependency
        is unavailable or invalid for this constructor call.
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

    try:
        external_module = await asyncio.to_thread(import_module, "aiopnsense")
    except ImportError as err:
        raise MissingExternalAiopnsenseDependency("aiopnsense is required") from err
    try:
        external_client_class = external_module.OPNsenseClient
    except AttributeError as err:
        raise MissingExternalAiopnsenseDependency("aiopnsense is required") from err

    client = external_client_class(**kwargs)

    aiopnsense_version = await _get_external_aiopnsense_version()
    if aiopnsense_version:
        _LOGGER.info("Using aiopnsense %s", aiopnsense_version)
    else:
        _LOGGER.info("Using aiopnsense")

    return client
