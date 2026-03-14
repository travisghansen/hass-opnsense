"""Core transport and queue plumbing for OPNsenseClient."""

import asyncio
from collections.abc import MutableMapping
from datetime import datetime, timedelta
from functools import partial
import inspect
import json
import socket
import ssl
from typing import Any, Protocol, cast
from urllib.parse import quote, urlparse
import xmlrpc.client

import aiohttp
import awesomeversion

from .const import (
    DEFAULT_ENDPOINT_CACHE_TTL_SECONDS,
    DEFAULT_ENDPOINT_NEGATIVE_CACHE_SECONDS,
    DEFAULT_PLUGIN_CACHE_TTL_SECONDS,
    DEFAULT_TIMEOUT,
    MAX_ENDPOINT_NEGATIVE_CACHE_SECONDS,
    MIN_ENDPOINT_CACHE_TTL_SECONDS,
    MIN_PLUGIN_CACHE_TTL_SECONDS,
)
from .exceptions import UnknownFirmware
from .helpers import _LOGGER, _xmlrpc_timeout


class _FirmwareVersionProvider(Protocol):
    """Structural contract for firmware mixin behavior used by ClientBaseMixin."""

    async def get_host_firmware_version(self) -> str | None:
        """Return the host firmware version string."""


class ClientBaseMixin:
    """ClientBase methods for OPNsenseClient."""

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        session: aiohttp.ClientSession,
        opts: MutableMapping[str, Any] | None = None,
        initial: bool = False,
        name: str = "OPNsense",
    ) -> None:
        """Initialize the OPNsense client.

        Parameters
        ----------
        url : str
            Base URL of the OPNsense instance.
        username : str
            API username used for authentication.
        password : str
            API password used for authentication.
        session : aiohttp.ClientSession
            Shared aiohttp client session used for HTTP requests.
        opts : MutableMapping[str, Any] | None
            Optional connection options (for example verify_ssl). Defaults to None.
        initial : bool
            Whether the call runs during initial setup/validation. Defaults to False.
        name : str
            Human-friendly name used in logs and identifiers. Defaults to 'OPNsense'.

        """

        self._username: str = username
        self._password: str = password
        self._name: str = name

        self._opts: dict[str, Any] = dict(opts or {})
        self._verify_ssl: bool = self._opts.get("verify_ssl", True)
        parts = urlparse(url.rstrip("/"))
        self._url: str = f"{parts.scheme}://{parts.netloc}"
        self._xmlrpc_url: str = (
            f"{parts.scheme}://{quote(username, safe='')}:{quote(password, safe='')}@{parts.netloc}"
        )
        self._scheme: str = parts.scheme
        self._session: aiohttp.ClientSession = session
        self._initial = initial
        self._firmware_version: str | None = None
        self._plugin_deprecated: bool | None = None
        self._installed_plugins: set[str] | None = None
        self._installed_plugins_updated_at: datetime | None = None
        self._endpoint_availability: dict[str, bool] = {}
        self._endpoint_checked_at: dict[str, datetime] = {}
        self._endpoint_retry_after: dict[str, datetime] = {}
        self._endpoint_failure_count: dict[str, int] = {}
        requested_ttl = self._opts.get("plugin_cache_ttl_seconds", DEFAULT_PLUGIN_CACHE_TTL_SECONDS)
        try:
            ttl_seconds = int(requested_ttl)
        except (TypeError, ValueError):
            ttl_seconds = DEFAULT_PLUGIN_CACHE_TTL_SECONDS
        self._plugin_cache_ttl_seconds = max(ttl_seconds, MIN_PLUGIN_CACHE_TTL_SECONDS)
        requested_endpoint_ttl = self._opts.get(
            "endpoint_cache_ttl_seconds", DEFAULT_ENDPOINT_CACHE_TTL_SECONDS
        )
        try:
            endpoint_ttl_seconds = int(requested_endpoint_ttl)
        except (TypeError, ValueError):
            endpoint_ttl_seconds = DEFAULT_ENDPOINT_CACHE_TTL_SECONDS
        self._endpoint_cache_ttl_seconds = max(endpoint_ttl_seconds, MIN_ENDPOINT_CACHE_TTL_SECONDS)
        self._use_snake_case: bool = True
        self._xmlrpc_query_count = 0
        self._rest_api_query_count = 0
        self._request_queue: asyncio.Queue = asyncio.Queue()
        self._queue_monitor: asyncio.Task[Any] | None = None
        self._workers: list[asyncio.Task[Any]] = []
        # Number of parallel workers to process the queue
        self._max_workers = 2
        # Don't use directly. Use await self._get_active_loop() instead
        self._loop: asyncio.AbstractEventLoop | None = None

    async def _ensure_workers_started(self) -> None:
        """Ensure queue workers are running on the active event loop.

        This binds loop-dependent resources lazily to the currently running
        loop, avoiding private loop creation during object construction.

        """
        self._loop = asyncio.get_running_loop()

        if self._queue_monitor is None or self._queue_monitor.done():
            self._queue_monitor = asyncio.create_task(self._monitor_queue())

        self._workers = [worker for worker in self._workers if not worker.done()]
        while len(self._workers) < self._max_workers:
            self._workers.append(asyncio.create_task(self._process_queue()))

    async def _get_active_loop(self) -> asyncio.AbstractEventLoop:
        """Ensure workers are started and return the active event loop."""
        await self._ensure_workers_started()
        if self._loop is None:
            raise RuntimeError("Event loop is not initialized")
        return self._loop

    @property
    def name(self) -> str:
        """Return the name of the client.

        Returns
        -------
        str
        Configured client display name.


        """
        return self._name

    async def reset_query_counts(self) -> None:
        """Reset REST and XMLRPC query counters to zero."""
        self._xmlrpc_query_count = 0
        self._rest_api_query_count = 0

    async def get_query_counts(self) -> tuple:
        """Return current REST and XMLRPC query counts.

        Returns
        -------
        tuple
        Two-item tuple containing REST query count and XMLRPC query count.


        """
        return self._rest_api_query_count, self._xmlrpc_query_count

    def _get_proxy(self) -> xmlrpc.client.ServerProxy:
        """Create an XMLRPC server proxy for the configured OPNsense host.

        Returns
        -------
        xmlrpc.client.ServerProxy
        XMLRPC ServerProxy configured for this client instance.


        """
        # https://docs.python.org/3/library/xmlrpc.client.html#module-xmlrpc.client
        # https://stackoverflow.com/questions/30461969/disable-default-certificate-verification-in-python-2-7-9
        context = None

        if self._scheme == "https" and not self._verify_ssl:
            context = ssl._create_unverified_context()  # noqa: SLF001

        # set to True if necessary during development
        verbose = False

        return xmlrpc.client.ServerProxy(
            f"{self._xmlrpc_url}/xmlrpc.php", context=context, verbose=verbose
        )

    @_xmlrpc_timeout
    async def _restore_config_section(
        self, section_name: str, data: MutableMapping[str, Any]
    ) -> None:
        """Restore a specific configuration section via XMLRPC.

        Parameters
        ----------
        section_name : str
            Configuration section name to restore.
        data : MutableMapping[str, Any]
            Input mapping used to build the request payload.

        """
        loop = await self._get_active_loop()
        params = {section_name: data}
        proxy_method = partial(self._get_proxy().opnsense.restore_config_section, params)
        await loop.run_in_executor(None, proxy_method)

    @_xmlrpc_timeout
    async def _exec_php(self, script: str) -> dict[str, Any]:
        """Execute a PHP snippet through XMLRPC and decode the JSON payload.

        Parameters
        ----------
        script : str
            PHP script source executed through XMLRPC.

        Returns
        -------
        dict[str, Any]
        JSON-decoded response payload, or an empty dictionary on failure.


        """
        loop = await self._get_active_loop()
        self._xmlrpc_query_count += 1
        script = rf"""
ini_set('display_errors', 0);

{script}

// wrapping this in json_encode and then unwrapping in python prevents funny XMLRPC NULL encoding errors
// https://github.com/travisghansen/hass-pfsense/issues/35
$toreturn_real = $toreturn;
$toreturn = [];
$toreturn["real"] = json_encode($toreturn_real);
        """
        try:
            response = await loop.run_in_executor(None, self._get_proxy().opnsense.exec_php, script)
            if not isinstance(response, MutableMapping):
                return {}
            if response.get("real"):
                response_json = json.loads(response.get("real", ""))
                return dict(response_json) if isinstance(response_json, MutableMapping) else {}
        except TypeError as e:
            stack = inspect.stack()
            calling_function = stack[1].function.strip("_") if len(stack) > 1 else "Unknown"
            _LOGGER.error(
                "Invalid data returned from exec_php for %s. %s: %s. Called from %s",
                calling_function,
                type(e).__name__,
                e,
                calling_function,
            )
        except xmlrpc.client.Fault as e:
            stack = inspect.stack()
            calling_function = stack[1].function.strip("_") if len(stack) > 1 else "Unknown"
            _LOGGER.error(
                "Error running exec_php script for %s. %s: %s. Ensure the 'os-homeassistant-maxit' plugin has been installed on OPNsense",
                calling_function,
                type(e).__name__,
                e,
            )
        except socket.gaierror as e:
            stack = inspect.stack()
            calling_function = stack[1].function.strip("_") if len(stack) > 1 else "Unknown"
            _LOGGER.warning(
                "Connection Error running exec_php script for %s. %s: %s. Will retry",
                calling_function,
                type(e).__name__,
                e,
            )
        except ssl.SSLError as e:
            stack = inspect.stack()
            calling_function = stack[1].function.strip("_") if len(stack) > 1 else "Unknown"
            _LOGGER.warning(
                "SSL Connection Error running exec_php script for %s. %s: %s. Will retry",
                calling_function,
                type(e).__name__,
                e,
            )
        return {}

    async def set_use_snake_case(self, initial: bool = False) -> None:
        """Set whether to use snake_case or camelCase for API calls.

        Parameters
        ----------
        initial : bool
            Whether the call runs during initial setup/validation. Defaults to False.

        """
        firmware = await cast("_FirmwareVersionProvider", self).get_host_firmware_version()

        self._use_snake_case = True
        try:
            if awesomeversion.AwesomeVersion(firmware) < awesomeversion.AwesomeVersion("25.7"):
                _LOGGER.debug("Using camelCase for OPNsense < 25.7")
                self._use_snake_case = False
            else:
                _LOGGER.debug("Using snake_case for OPNsense >= 25.7")
        except (
            awesomeversion.exceptions.AwesomeVersionCompareException,
            TypeError,
            ValueError,
        ) as e:
            _LOGGER.error(
                "Error comparing firmware version %s. Using snake_case by default",
                firmware,
            )
            if initial:
                raise UnknownFirmware from e

    async def _get_from_stream(self, path: str) -> dict[str, Any]:
        """Queue a streaming GET request and return the parsed payload.

        Parameters
        ----------
        path : str
            API endpoint path to call on the OPNsense host.

        Returns
        -------
        dict[str, Any]
        Queued streaming-response payload parsed into a dictionary.


        """
        loop = await self._get_active_loop()
        try:
            caller = inspect.stack()[1].function
        except (IndexError, AttributeError):
            caller = "Unknown"
        future = loop.create_future()
        await self._request_queue.put(("get_from_stream", path, None, future, caller))
        return await future

    async def _get(self, path: str) -> MutableMapping[str, Any] | list | None:
        """Queue a GET request and return the result.

        Parameters
        ----------
        path : str
            API endpoint path to call on the OPNsense host.

        Returns
        -------
        MutableMapping[str, Any] | list | None
        Decoded JSON payload from a queued GET request, or None when request/parse fails.


        """
        loop = await self._get_active_loop()
        try:
            caller = inspect.stack()[1].function
        except (IndexError, AttributeError):
            caller = "Unknown"
        future = loop.create_future()
        await self._request_queue.put(("get", path, None, future, caller))
        return await future

    async def _post(
        self, path: str, payload: MutableMapping[str, Any] | None = None
    ) -> MutableMapping[str, Any] | list | None:
        """Queue a POST request and return the result.

        Parameters
        ----------
        path : str
            API endpoint path to call on the OPNsense host.
        payload : MutableMapping[str, Any] | None
            JSON payload body sent with the API request. Defaults to None.

        Returns
        -------
        MutableMapping[str, Any] | list | None
        Decoded JSON payload from a queued POST request, or None when request/parse fails.


        """
        loop = await self._get_active_loop()
        try:
            caller = inspect.stack()[1].function
        except (IndexError, AttributeError):
            caller = "Unknown"
        future = loop.create_future()
        await self._request_queue.put(("post", path, payload, future, caller))
        return await future

    async def _process_queue(self) -> None:
        """Continuously process queued API requests and resolve waiting futures."""
        while True:
            method: str | None = None
            path: str | None = None
            payload: dict[str, Any] | None = None
            future: asyncio.Future[Any] | None = None
            caller = "Unknown"
            try:
                method, path, payload, future, caller = await self._request_queue.get()
                if method == "get_from_stream":
                    result: Any = await self._do_get_from_stream(path, caller)
                    if future is not None and not future.done():
                        future.set_result(result)
                elif method == "get":
                    result = await self._do_get(path, caller)
                    if future is not None and not future.done():
                        future.set_result(result)
                elif method == "post":
                    result = await self._do_post(path, payload, caller)
                    if future is not None and not future.done():
                        future.set_result(result)
                else:
                    _LOGGER.error("Unknown method to add to Queue: %s", method)
                    if future is not None and not future.done():
                        future.set_exception(
                            RuntimeError(f"Unknown method to add to Queue: {method}")
                        )
            except asyncio.CancelledError:
                _LOGGER.debug("Request queue processor cancelled (called by %s)", caller)
                if future is not None and not future.done():
                    future.cancel()
                raise
            except Exception as e:  # noqa: BLE001
                _LOGGER.error(
                    "Exception in request queue processor (called by %s). %s: %s",
                    caller,
                    type(e).__name__,
                    e,
                )
                if future is not None and not future.done():
                    future.set_exception(e)
            await asyncio.sleep(0.3)

    async def _monitor_queue(self) -> None:
        """Periodically log request queue backlog size for diagnostics."""
        while True:
            try:
                queue_size = self._request_queue.qsize()
                if queue_size > 0:
                    _LOGGER.debug("OPNsense API queue backlog: %d tasks", queue_size)
            except Exception as e:  # noqa: BLE001
                _LOGGER.error("Error monitoring queue size. %s: %s", type(e).__name__, e)
            await asyncio.sleep(10)

    async def _do_get_from_stream(self, path: str, caller: str = "Unknown") -> dict[str, Any]:
        """Execute a streaming GET request immediately.

        Parameters
        ----------
        path : str
            API endpoint path to call on the OPNsense host.
        caller : str
            Name of the calling method used for log context. Defaults to 'Unknown'.

        Returns
        -------
        dict[str, Any]
        Parsed JSON object extracted from the stream payload.


        """
        self._rest_api_query_count += 1
        url: str = f"{self._url}{path}"
        _LOGGER.debug("[get_from_stream] url: %s", url)
        try:
            async with self._session.get(
                url,
                auth=aiohttp.BasicAuth(self._username, self._password),
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
                ssl=self._verify_ssl,
            ) as response:
                _LOGGER.debug(
                    "[get_from_stream] Response %s: %s",
                    response.status,
                    response.reason,
                )

                if response.ok:
                    buffer = ""
                    message_count = 0

                    async for chunk in response.content.iter_chunked(1024):
                        buffer += chunk.decode("utf-8")
                        # _LOGGER.debug("[get_from_stream] buffer: %s", buffer)

                        while "\n\n" in buffer:
                            message, buffer = buffer.split("\n\n", 1)
                            lines = message.splitlines()
                            for line in lines:
                                if line.startswith("data:"):
                                    message_count += 1
                                    if message_count == 2:
                                        response_str: str = line[len("data:") :].strip()
                                        response_json = json.loads(response_str)
                                        _LOGGER.debug(
                                            "[get_from_stream] response_json (%s): %s",
                                            type(response_json).__name__,
                                            response_json,
                                        )
                                        return (
                                            dict(response_json)
                                            if isinstance(response_json, MutableMapping)
                                            else {}
                                        )  # Exit after processing the second message
                                    _LOGGER.debug(
                                        "[get_from_stream] Ignored message %s: %s",
                                        message_count,
                                        line,
                                    )
                                else:
                                    _LOGGER.debug("[get_from_stream] Unparsed: %s", line)
                else:
                    if response.status == 403:
                        _LOGGER.error(
                            "Permission Error in do_get_from_stream (called by %s). Path: %s. Ensure the OPNsense user connected to HA has appropriate access. Recommend full admin access",
                            caller,
                            url,
                        )
                    else:
                        _LOGGER.error(
                            "Error in do_get_from_stream (called by %s). Path: %s. Response %s: %s",
                            caller,
                            url,
                            response.status,
                            response.reason,
                        )
                    if self._initial:
                        raise aiohttp.ClientResponseError(
                            request_info=response.request_info,
                            history=response.history,
                            status=response.status,
                            message=f"HTTP Status Error: {response.status} {response.reason}",
                            headers=response.headers,
                        )
        except (aiohttp.ClientError, TimeoutError) as e:
            _LOGGER.error("Client error. %s: %s", type(e).__name__, e)
            if self._initial:
                raise

        return {}

    async def _do_get(
        self, path: str, caller: str = "Unknown"
    ) -> MutableMapping[str, Any] | list | None:
        """Execute a GET request immediately without queueing.

        Parameters
        ----------
        path : str
            API endpoint path to call on the OPNsense host.
        caller : str
            Name of the calling method used for log context. Defaults to 'Unknown'.

        Returns
        -------
        MutableMapping[str, Any] | list | None
        Decoded JSON payload from an immediate GET request, or None when request/parse fails.


        """
        # /api/<module>/<controller>/<command>/[<param1>/[<param2>/...]]
        self._rest_api_query_count += 1
        url: str = f"{self._url}{path}"
        _LOGGER.debug("[get] url: %s", url)
        try:
            async with self._session.get(
                url,
                auth=aiohttp.BasicAuth(self._username, self._password),
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
                ssl=self._verify_ssl,
            ) as response:
                _LOGGER.debug("[get] Response %s: %s", response.status, response.reason)
                if response.ok:
                    return await response.json(content_type=None)
                if response.status == 403:
                    _LOGGER.error(
                        "Permission Error in do_get (called by %s). Path: %s. Ensure the OPNsense user connected to HA has appropriate access. Recommend full admin access",
                        caller,
                        url,
                    )
                else:
                    _LOGGER.error(
                        "Error in do_get (called by %s). Path: %s. Response %s: %s",
                        caller,
                        url,
                        response.status,
                        response.reason,
                    )
                if self._initial:
                    raise aiohttp.ClientResponseError(
                        request_info=response.request_info,
                        history=response.history,
                        status=response.status,
                        message=f"HTTP Status Error: {response.status} {response.reason}",
                        headers=response.headers,
                    )
        except (aiohttp.ClientError, TimeoutError) as e:
            _LOGGER.error("Client error. %s: %s", type(e).__name__, e)
            if self._initial:
                raise

        return None

    async def _safe_dict_get(self, path: str) -> dict[str, Any]:
        """Fetch data from the given path, ensuring the result is a dict.

        Parameters
        ----------
        path : str
            API endpoint path to call on the OPNsense host.

        Returns
        -------
        dict[str, Any]
        Dictionary payload from the GET request, or an empty dictionary if the response is not a mapping.


        """
        result = await self._get(path=path)
        return dict(result) if isinstance(result, MutableMapping) else {}

    async def _safe_list_get(self, path: str) -> list:
        """Fetch data from the given path, ensuring the result is a list.

        Parameters
        ----------
        path : str
            API endpoint path to call on the OPNsense host.

        Returns
        -------
        list
        List payload from the GET request, or an empty list if the response is not a list.


        """
        result = await self._get(path=path)
        return result if isinstance(result, list) else []

    async def _do_post(
        self, path: str, payload: MutableMapping[str, Any] | None = None, caller: str = "Unknown"
    ) -> MutableMapping[str, Any] | list | None:
        """Execute a POST request immediately without queueing.

        Parameters
        ----------
        path : str
            API endpoint path to call on the OPNsense host.
        payload : MutableMapping[str, Any] | None
            JSON payload body sent with the API request. Defaults to None.
        caller : str
            Name of the calling method used for log context. Defaults to 'Unknown'.

        Returns
        -------
        MutableMapping[str, Any] | list | None
        Decoded JSON payload from an immediate POST request, or None when request/parse fails.


        """
        self._rest_api_query_count += 1
        url: str = f"{self._url}{path}"
        _LOGGER.debug("[post] url: %s", url)
        _LOGGER.debug("[post] payload: %s", payload)
        try:
            async with self._session.post(
                url,
                json=payload,
                auth=aiohttp.BasicAuth(self._username, self._password),
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
                ssl=self._verify_ssl,
            ) as response:
                _LOGGER.debug("[post] Response %s: %s", response.status, response.reason)
                if response.ok:
                    response_json: dict[str, Any] | list = await response.json(content_type=None)
                    return response_json
                if response.status == 403:
                    _LOGGER.error(
                        "Permission Error in do_post (called by %s). Path: %s. Ensure the OPNsense user connected to HA has appropriate access. Recommend full admin access",
                        caller,
                        url,
                    )
                else:
                    _LOGGER.error(
                        "Error in do_post (called by %s). Path: %s. Response %s: %s",
                        caller,
                        url,
                        response.status,
                        response.reason,
                    )
                if self._initial:
                    raise aiohttp.ClientResponseError(
                        request_info=response.request_info,
                        history=response.history,
                        status=response.status,
                        message=f"HTTP Status Error: {response.status} {response.reason}",
                        headers=response.headers,
                    )
        except (aiohttp.ClientError, TimeoutError) as e:
            _LOGGER.error("Client error. %s: %s", type(e).__name__, e)
            if self._initial:
                raise

        return None

    async def _safe_dict_post(
        self, path: str, payload: MutableMapping[str, Any] | None = None
    ) -> dict[str, Any]:
        """Fetch data from the given path, ensuring the result is a dict.

        Parameters
        ----------
        path : str
            API endpoint path to call on the OPNsense host.
        payload : MutableMapping[str, Any] | None
            JSON payload body sent with the API request. Defaults to None.

        Returns
        -------
        dict[str, Any]
        Dictionary payload from the POST request, or an empty dictionary if the response is not a mapping.


        """
        result = await self._post(path=path, payload=payload)
        return dict(result) if isinstance(result, MutableMapping) else {}

    async def _safe_list_post(
        self, path: str, payload: MutableMapping[str, Any] | None = None
    ) -> list:
        """Fetch data from the given path, ensuring the result is a list.

        Parameters
        ----------
        path : str
            API endpoint path to call on the OPNsense host.
        payload : MutableMapping[str, Any] | None
            JSON payload body sent with the API request. Defaults to None.

        Returns
        -------
        list
        List payload from the POST request, or an empty list if the response is not a list.


        """
        result = await self._post(path=path, payload=payload)
        return result if isinstance(result, list) else []

    async def is_endpoint_available(self, path: str, force_refresh: bool = False) -> bool:
        """Return whether a specific API endpoint appears to be available.

        Parameters
        ----------
        path : str
            API endpoint path to check on the OPNsense host.
        force_refresh : bool
            Whether to bypass cached availability state and perform a new probe.

        Returns
        -------
        bool
            ``True`` when endpoint probe succeeded, otherwise ``False``.

        """
        if not isinstance(path, str) or not path:
            return False

        now = datetime.now().astimezone()
        cache_is_fresh = (
            path in self._endpoint_checked_at
            and (now - self._endpoint_checked_at[path]).total_seconds()
            < self._endpoint_cache_ttl_seconds
        )
        retry_after = self._endpoint_retry_after.get(path)
        availability = self._endpoint_availability.get(path)

        if not force_refresh and availability is False and isinstance(retry_after, datetime):
            if retry_after > now:
                return False
            # Retry window has elapsed, so probe again even if the TTL cache is still fresh.
            cache_is_fresh = False

        if not force_refresh and cache_is_fresh and path in self._endpoint_availability:
            return self._endpoint_availability[path]

        self._rest_api_query_count += 1
        url: str = f"{self._url}{path}"
        _LOGGER.debug("[is_endpoint_available] url: %s", url)

        try:
            async with self._session.get(
                url,
                auth=aiohttp.BasicAuth(self._username, self._password),
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
                ssl=self._verify_ssl,
            ) as response:
                available = bool(response.ok)
                self._endpoint_availability[path] = available
                self._endpoint_checked_at[path] = now

                if available:
                    self._endpoint_failure_count[path] = 0
                    self._endpoint_retry_after.pop(path, None)
                    return True

                failures = self._endpoint_failure_count.get(path, 0) + 1
                self._endpoint_failure_count[path] = failures
                retry_seconds = min(
                    DEFAULT_ENDPOINT_NEGATIVE_CACHE_SECONDS * (2 ** (failures - 1)),
                    MAX_ENDPOINT_NEGATIVE_CACHE_SECONDS,
                )
                self._endpoint_retry_after[path] = now + timedelta(seconds=retry_seconds)

                if response.status == 403:
                    _LOGGER.error(
                        "Permission Error in is_endpoint_available. Path: %s. Ensure the OPNsense user connected to HA has appropriate access. Recommend full admin access",
                        url,
                    )
                else:
                    _LOGGER.debug(
                        "Endpoint check failed for %s with status %s: %s",
                        path,
                        response.status,
                        response.reason,
                    )
                return False
        except (aiohttp.ClientError, TimeoutError) as e:
            failures = self._endpoint_failure_count.get(path, 0) + 1
            self._endpoint_failure_count[path] = failures
            retry_seconds = min(
                DEFAULT_ENDPOINT_NEGATIVE_CACHE_SECONDS * (2 ** (failures - 1)),
                MAX_ENDPOINT_NEGATIVE_CACHE_SECONDS,
            )
            self._endpoint_retry_after[path] = now + timedelta(seconds=retry_seconds)
            self._endpoint_availability[path] = False
            self._endpoint_checked_at[path] = now
            _LOGGER.warning(
                "Endpoint availability check failed for %s. %s: %s",
                path,
                type(e).__name__,
                e,
            )
            return False

    async def async_close(self) -> None:
        """Cancel all running background tasks and clear the request queue."""
        _LOGGER.debug("Closing OPNsenseClient and cancelling background tasks")

        tasks_to_cancel = []

        if self._queue_monitor and not self._queue_monitor.done():
            self._queue_monitor.cancel()
            tasks_to_cancel.append(self._queue_monitor)

        if self._workers:
            for worker in self._workers:
                if not worker.done():
                    worker.cancel()
                tasks_to_cancel.append(worker)

        if tasks_to_cancel:
            try:
                await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
                _LOGGER.debug("All background tasks cancelled successfully")
            except Exception as e:  # noqa: BLE001
                _LOGGER.warning(
                    "Error during background task cancellation. %s: %s", type(e).__name__, e
                )

        while not self._request_queue.empty():
            try:
                _method, _path, _payload, future, _caller = self._request_queue.get_nowait()
                if future is not None and not future.done():
                    future.set_exception(asyncio.CancelledError("OPNsenseClient is closing"))
            except asyncio.QueueEmpty:
                break
        self._queue_monitor = None
        self._workers = []
        self._loop = None
        _LOGGER.debug("Request queue cleared")
