"""Typing protocol contracts for pyopnsense mixins."""

from abc import abstractmethod
from collections.abc import MutableMapping
from datetime import datetime, tzinfo
from typing import Any, Protocol


class PyOPNsenseClientProtocol(Protocol):
    """Structural typing contract used by split pyopnsense mixins."""

    _use_snake_case: bool
    _plugin_deprecated: bool | None
    _firmware_version: str | None
    _installed_plugins: set[str] | None
    _installed_plugins_updated_at: datetime | None
    _plugin_cache_ttl_seconds: int
    _endpoint_availability: dict[str, bool]
    _endpoint_checked_at: dict[str, datetime]
    _endpoint_retry_after: dict[str, datetime]
    _endpoint_failure_count: dict[str, int]
    _endpoint_cache_ttl_seconds: int

    @abstractmethod
    async def _get(self, path: str) -> MutableMapping[str, Any] | list | None:
        """Queue a GET request and return the decoded payload.

        Parameters
        ----------
        path : str
            Relative API path.

        Returns
        -------
        MutableMapping[str, Any] | list | None
            Decoded JSON payload, or ``None`` when unavailable.

        """
        ...

    @abstractmethod
    async def _post(
        self, path: str, payload: MutableMapping[str, Any] | None = None
    ) -> MutableMapping[str, Any] | list | None:
        """Queue a POST request and return the decoded payload.

        Parameters
        ----------
        path : str
            Relative API path.
        payload : MutableMapping[str, Any] | None
            Optional request body.

        Returns
        -------
        MutableMapping[str, Any] | list | None
            Decoded JSON payload, or ``None`` when unavailable.

        """
        ...

    @abstractmethod
    async def _get_from_stream(self, path: str) -> dict[str, Any]:
        """Queue a streaming GET request and parse the first data payload.

        Parameters
        ----------
        path : str
            Relative API path.

        Returns
        -------
        dict[str, Any]
            Parsed stream payload.

        """
        ...

    @abstractmethod
    async def _safe_dict_get(self, path: str) -> dict[str, Any]:
        """Fetch a GET payload and coerce non-mapping values to an empty mapping.

        Parameters
        ----------
        path : str
            Relative API path.

        Returns
        -------
        dict[str, Any]
            Dictionary payload.

        """
        ...

    @abstractmethod
    async def _safe_list_get(self, path: str) -> list:
        """Fetch a GET payload and coerce non-list values to an empty list.

        Parameters
        ----------
        path : str
            Relative API path.

        Returns
        -------
        list
            List payload.

        """
        ...

    @abstractmethod
    async def _safe_dict_post(
        self, path: str, payload: MutableMapping[str, Any] | None = None
    ) -> dict[str, Any]:
        """Fetch a POST payload and coerce non-mapping values to an empty mapping.

        Parameters
        ----------
        path : str
            Relative API path.
        payload : MutableMapping[str, Any] | None
            Optional request body.

        Returns
        -------
        dict[str, Any]
            Dictionary payload.

        """
        ...

    @abstractmethod
    async def _safe_list_post(
        self, path: str, payload: MutableMapping[str, Any] | None = None
    ) -> list:
        """Fetch a POST payload and coerce non-list values to an empty list.

        Parameters
        ----------
        path : str
            Relative API path.
        payload : MutableMapping[str, Any] | None
            Optional request body.

        Returns
        -------
        list
            List payload.

        """
        ...

    @abstractmethod
    async def _get_opnsense_timezone(self, datetime_str: str | None = None) -> tzinfo:
        """Resolve timezone information from OPNsense system time data.

        Parameters
        ----------
        datetime_str : str | None
            Optional datetime string from OPNsense ``system_time`` output.

        Returns
        -------
        tzinfo
            Parsed timezone when available, otherwise a local fixed-offset fallback.

        """
        ...

    @abstractmethod
    async def _exec_php(self, script: str) -> dict[str, Any]:
        """Execute a PHP script via XMLRPC and decode the JSON payload.

        Parameters
        ----------
        script : str
            PHP source snippet.

        Returns
        -------
        dict[str, Any]
            Decoded dictionary payload.

        """
        ...

    @abstractmethod
    async def _restore_config_section(
        self, section_name: str, data: MutableMapping[str, Any]
    ) -> None:
        """Restore a configuration section via XMLRPC.

        Parameters
        ----------
        section_name : str
            Config section key.
        data : MutableMapping[str, Any]
            Replacement section payload.

        Returns
        -------
        None

        """
        ...

    @abstractmethod
    async def _filter_configure(self) -> None:
        """Apply pending firewall and NAT filter configuration changes.

        Returns
        -------
        None

        """
        ...

    @abstractmethod
    async def get_config(self) -> dict[str, Any]:
        """Return full OPNsense configuration payload.

        Returns
        -------
        dict[str, Any]
            Full configuration dictionary.

        """
        ...

    @abstractmethod
    async def get_host_firmware_version(self) -> str | None:
        """Return the host firmware version string.

        Returns
        -------
        str | None
            Parsed firmware version, if available.

        """
        ...

    @abstractmethod
    async def is_plugin_installed(self) -> bool:
        """Return whether plugin installation is detected.

        Returns
        -------
        bool
            ``True`` when the plugin is installed.

        """
        ...

    @abstractmethod
    async def is_named_plugin_installed(self, plugin_name: str) -> bool:
        """Return whether a specific plugin package is installed.

        Parameters
        ----------
        plugin_name : str
            OPNsense package name (for example ``os-vnstat``).

        Returns
        -------
        bool
            ``True`` when the package is installed.

        """
        ...

    @abstractmethod
    async def is_endpoint_available(self, path: str, force_refresh: bool = False) -> bool:
        """Return whether a specific API endpoint appears available.

        Parameters
        ----------
        path : str
            API path to probe.
        force_refresh : bool
            Whether to bypass cached probe results.

        Returns
        -------
        bool
            ``True`` when endpoint probe succeeds.

        """
        ...

    @abstractmethod
    async def is_plugin_deprecated(self) -> bool:
        """Return whether plugin is deprecated for host firmware.

        Returns
        -------
        bool
            ``True`` when the plugin should be considered deprecated.

        """
        ...
