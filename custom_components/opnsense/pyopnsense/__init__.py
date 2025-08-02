"""pyopnsense to manage OPNsense from HA."""

from abc import ABC
import asyncio
from collections.abc import Callable, MutableMapping
from datetime import datetime, timedelta, timezone
from functools import partial
import inspect
import ipaddress
import json
import logging
import re
import socket
import ssl
import traceback
from typing import Any
from urllib.parse import quote, quote_plus, urlparse
import xmlrpc.client

import aiohttp
import awesomeversion
from dateutil.parser import ParserError, UnknownTimezoneWarning, parse

from .const import AMBIGUOUS_TZINFOS

# value to set as the socket timeout
DEFAULT_TIMEOUT = 60

_LOGGER: logging.Logger = logging.getLogger(__name__)


def _log_errors(func: Callable) -> Any:
    async def inner(self: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            return await func(self, *args, **kwargs)
        except asyncio.CancelledError:
            raise
        except (TimeoutError, aiohttp.ServerTimeoutError) as e:
            _LOGGER.warning("Timeout Error in %s. Will retry. %s", func.__name__.strip("_"), e)
            if self._initial:
                raise
        except Exception as e:
            redacted_message = re.sub(r"(\w+):(\w+)@", "<redacted>:<redacted>@", str(e))
            _LOGGER.error(
                "Error in %s. %s: %s\n%s",
                func.__name__.strip("_"),
                type(e).__name__,
                redacted_message,
                "".join(traceback.format_tb(e.__traceback__)),
            )
            if self._initial:
                raise

    return inner


def _xmlrpc_timeout(func: Callable) -> Any:
    async def inner(self: Any, *args: Any, **kwargs: Any) -> Any:
        response = None
        # timout applies to each recv() call, not the whole request
        default_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(DEFAULT_TIMEOUT)
            response = await func(self, *args, **kwargs)
        finally:
            socket.setdefaulttimeout(default_timeout)
        return response

    return inner


def wireguard_is_connected(past_time: datetime | None) -> bool:
    """Return if Wireguard client is still connected."""
    if not past_time:
        return False
    return datetime.now().astimezone() - past_time <= timedelta(minutes=3)


def human_friendly_duration(seconds: int) -> str:
    """Convert the duration in seconds to human friendly."""
    months, seconds = divmod(
        seconds, 2419200
    )  # 28 days in a month (28 * 24 * 60 * 60 = 2419200 seconds)
    weeks, seconds = divmod(seconds, 604800)  # 604800 seconds in a week
    days, seconds = divmod(seconds, 86400)  # 86400 seconds in a day
    hours, seconds = divmod(seconds, 3600)  # 3600 seconds in an hour
    minutes, seconds = divmod(seconds, 60)  # 60 seconds in a minute

    duration: list = []
    if months > 0:
        duration.append(f"{months} month{'s' if months > 1 else ''}")
    if weeks > 0:
        duration.append(f"{weeks} week{'s' if weeks > 1 else ''}")
    if days > 0:
        duration.append(f"{days} day{'s' if days > 1 else ''}")
    if hours > 0:
        duration.append(f"{hours} hour{'s' if hours > 1 else ''}")
    if minutes > 0:
        duration.append(f"{minutes} minute{'s' if minutes > 1 else ''}")
    if seconds > 0 or not duration:
        duration.append(f"{seconds} second{'s' if seconds != 1 else ''}")

    return ", ".join(duration)


def get_ip_key(item: MutableMapping[str, Any]) -> tuple:
    """Use to sort the DHCP Lease IPs."""
    address = item.get("address", None)

    if not address:
        # If the address is empty, place it at the end
        return (3, "")
    try:
        ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(address)
    except ValueError:
        return (2, "")
    else:
        # Sort by IP version (IPv4 first, IPv6 second), then by numerical value
        return (0 if ip_obj.version == 4 else 1, ip_obj)


def dict_get(data: MutableMapping[str, Any], path: str, default: Any | None = None) -> Any | None:
    """Parse the path to get the desired value out of the data."""
    pathList: list = re.split(r"\.", path, flags=re.IGNORECASE)
    result: Any | None = data
    for key in pathList:
        if key.isnumeric():
            key = int(key)
        if isinstance(result, MutableMapping | list) and key in result:
            result = result[key]
        else:
            result = default
            break

    return result


def timestamp_to_datetime(timestamp: int | None) -> datetime | None:
    """Convert a timestamp to a timezone-aware datetime."""
    if timestamp is None:
        return None
    return datetime.fromtimestamp(
        int(timestamp),
        tz=timezone(datetime.now().astimezone().utcoffset() or timedelta()),
    )


class VoucherServerError(Exception):
    """Error from Voucher Server."""


class OPNsenseClient(ABC):
    """OPNsense Client."""

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
        """OPNsense Client initializer."""

        self._username: str = username
        self._password: str = password
        self._name: str = name

        self._opts: MutableMapping[str, Any] = opts or {}
        self._verify_ssl: bool = self._opts.get("verify_ssl", True)
        parts = urlparse(url.rstrip("/"))
        self._url: str = f"{parts.scheme}://{parts.netloc}"
        self._xmlrpc_url: str = (
            f"{parts.scheme}://{quote_plus(username)}:{quote_plus(password)}@{parts.netloc}"
        )
        self._scheme: str = parts.scheme
        self._session: aiohttp.ClientSession = session
        self._initial = initial
        self._firmware_version: str | None = None
        self._use_snake_case: bool | None = None
        self._xmlrpc_query_count = 0
        self._rest_api_query_count = 0
        self._request_queue: asyncio.Queue = asyncio.Queue()
        self._queue_monitor = asyncio.create_task(self._monitor_queue())
        self._workers = []
        self._max_workers = 2  # Number of parallel workers to process the queue

        for _ in range(self._max_workers):
            self._workers.append(asyncio.create_task(self._process_queue()))

        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

    @property
    def name(self) -> str:
        """Return the name of the client."""
        return self._name

    async def reset_query_counts(self) -> None:
        """Reset the number of queries counter."""
        self._xmlrpc_query_count = 0
        self._rest_api_query_count = 0

    async def get_query_counts(self) -> tuple:
        """Return the number of REST and XMLRPC queries."""
        return self._rest_api_query_count, self._xmlrpc_query_count

    # https://stackoverflow.com/questions/64983392/python-multiple-patch-gives-http-client-cannotsendrequest-request-sent
    def _get_proxy(self) -> xmlrpc.client.ServerProxy:
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
        params = {section_name: data}
        proxy_method = partial(self._get_proxy().opnsense.restore_config_section, params)
        await self._loop.run_in_executor(None, proxy_method)

    @_xmlrpc_timeout
    async def _exec_php(self, script: str) -> MutableMapping[str, Any]:
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
            response = await self._loop.run_in_executor(
                None, self._get_proxy().opnsense.exec_php, script
            )
            if not isinstance(response, MutableMapping):
                return {}
            if response.get("real"):
                return json.loads(response.get("real", ""))
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

    @_log_errors
    async def get_host_firmware_version(self) -> None | str:
        """Return the OPNsense Firmware version."""
        firmware_info = await self._safe_dict_get("/api/core/firmware/status")
        firmware: str | None = firmware_info.get("product", {}).get("product_version")
        if not firmware or not awesomeversion.AwesomeVersion(firmware).valid:
            old = firmware
            firmware = firmware_info.get("product", {}).get("product_series", old)
            if firmware != old:
                _LOGGER.debug(
                    "[get_host_firmware_version] firmware: %s not valid SemVer, using %s",
                    old,
                    firmware,
                )
        else:
            _LOGGER.debug("[get_host_firmware_version] firmware: %s", firmware)
        self._firmware_version = firmware
        return firmware

    async def set_use_snake_case(self) -> None:
        """Set whether to use snake_case or camelCase for API calls.

        In 25.7+ a number of API calls changed from camelCase to snake_case.
        """
        if self._firmware_version is None:
            await self.get_host_firmware_version()

        self._use_snake_case = True
        try:
            if awesomeversion.AwesomeVersion(
                self._firmware_version
            ) < awesomeversion.AwesomeVersion("25.7"):
                _LOGGER.debug("Using camelCase for OPNsense < 25.7")
                self._use_snake_case = False
            else:
                _LOGGER.debug("Using snake_case for OPNsense >= 25.7")
        except awesomeversion.exceptions.AwesomeVersionCompareException:
            pass

    async def is_plugin_installed(self) -> bool:
        """Retun whether OPNsense plugin is installed or not."""
        firmware_info = await self._safe_dict_get("/api/core/firmware/info")
        if not isinstance(firmware_info.get("package"), list):
            return False
        for pkg in firmware_info.get("package", []):
            if pkg.get("name") == "os-homeassistant-maxit":
                return True
        return False

    async def _get_from_stream(self, path: str) -> MutableMapping[str, Any]:
        try:
            caller = inspect.stack()[1].function
        except (IndexError, AttributeError):
            caller = "Unknown"
        future = asyncio.get_event_loop().create_future()
        await self._request_queue.put(("get_from_stream", path, None, future, caller))
        return await future

    async def _get(self, path: str) -> MutableMapping[str, Any] | list | None:
        try:
            caller = inspect.stack()[1].function
        except (IndexError, AttributeError):
            caller = "Unknown"
        future = asyncio.get_event_loop().create_future()
        await self._request_queue.put(("get", path, None, future, caller))
        return await future

    async def _post(
        self, path: str, payload: MutableMapping[str, Any] | None = None
    ) -> MutableMapping[str, Any] | list | None:
        try:
            caller = inspect.stack()[1].function
        except (IndexError, AttributeError):
            caller = "Unknown"
        future = asyncio.get_event_loop().create_future()
        await self._request_queue.put(("post", path, payload, future, caller))
        return await future

    async def _process_queue(self) -> None:
        while True:
            method, path, payload, future, caller = await self._request_queue.get()
            try:
                if method == "get_from_stream":
                    result: MutableMapping[str, Any] | list | None = await self._do_get_from_stream(
                        path, caller
                    )
                elif method == "get":
                    result = await self._do_get(path, caller)
                elif method == "post":
                    result = await self._do_post(path, payload, caller)
                else:
                    _LOGGER.error("Unknown method to add to Queue: %s", method)
                future.set_result(result)
            except Exception as e:  # noqa: BLE001
                _LOGGER.error(
                    "Exception in request queue processor (called by %s). %s: %s",
                    caller,
                    type(e).__name__,
                    e,
                )
                future.set_exception(e)
            await asyncio.sleep(0.3)

    async def _monitor_queue(self) -> None:
        while True:
            try:
                queue_size = self._request_queue.qsize()
                if queue_size > 0:
                    _LOGGER.debug("OPNsense API queue backlog: %d tasks", queue_size)
            except Exception as e:  # noqa: BLE001
                _LOGGER.error("Error monitoring queue size. %s: %s", type(e).__name__, e)
            await asyncio.sleep(10)

    async def _do_get_from_stream(
        self, path: str, caller: str = "Unknown"
    ) -> MutableMapping[str, Any]:
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

                        if "\n\n" in buffer:
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
                                            response_json
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
        except aiohttp.ClientError as e:
            _LOGGER.error("Client error. %s: %s", type(e).__name__, e)
            if self._initial:
                raise

        return {}

    async def _do_get(
        self, path: str, caller: str = "Unknown"
    ) -> MutableMapping[str, Any] | list | None:
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
        except aiohttp.ClientError as e:
            _LOGGER.error("Client error. %s: %s", type(e).__name__, e)
            if self._initial:
                raise

        return None

    async def _safe_dict_get(self, path: str) -> MutableMapping[str, Any]:
        """Fetch data from the given path, ensuring the result is a dict."""
        result = await self._get(path=path)
        return result if isinstance(result, MutableMapping) else {}

    async def _safe_list_get(self, path: str) -> list:
        """Fetch data from the given path, ensuring the result is a list."""
        result = await self._get(path=path)
        return result if isinstance(result, list) else []

    async def _do_post(
        self, path: str, payload: MutableMapping[str, Any] | None = None, caller: str = "Unknown"
    ) -> MutableMapping[str, Any] | list | None:
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
                    response_json: MutableMapping[str, Any] | list = await response.json(
                        content_type=None
                    )
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
        except aiohttp.ClientError as e:
            _LOGGER.error("Client error. %s: %s", type(e).__name__, e)
            if self._initial:
                raise

        return None

    async def _safe_dict_post(
        self, path: str, payload: MutableMapping[str, Any] | None = None
    ) -> MutableMapping[str, Any]:
        """Fetch data from the given path, ensuring the result is a dict."""
        result = await self._post(path=path, payload=payload)
        return result if isinstance(result, MutableMapping) else {}

    async def _safe_list_post(
        self, path: str, payload: MutableMapping[str, Any] | None = None
    ) -> list:
        """Fetch data from the given path, ensuring the result is a list."""
        result = await self._post(path=path, payload=payload)
        return result if isinstance(result, list) else []

    @_log_errors
    async def _filter_configure(self) -> None:
        script: str = r"""
filter_configure();
clear_subsystem_dirty('natconf');
clear_subsystem_dirty('filter');
"""
        await self._exec_php(script)

    @_log_errors
    async def get_device_unique_id(self) -> str | None:
        """Get the OPNsense Unique ID."""
        instances = await self._safe_list_get("/api/interfaces/overview/export")
        mac_addresses = [
            d.get("macaddr_hw") for d in instances if d.get("is_physical") and "macaddr_hw" in d
        ]

        unique_mac_addresses: list = sorted(set(mac_addresses))
        device_unique_id: str | None = unique_mac_addresses[0] if unique_mac_addresses else None
        if device_unique_id:
            device_unique_id_fmt = device_unique_id.replace(":", "_").strip()
            _LOGGER.debug("[get_device_unique_id] device_unique_id: %s", device_unique_id_fmt)
            return device_unique_id_fmt
        _LOGGER.debug("[get_device_unique_id] device_unique_id: None")
        return None

    @_log_errors
    async def get_system_info(self) -> MutableMapping[str, Any]:
        """Return the system info from OPNsense."""
        system_info: MutableMapping[str, Any] = {}
        if self._use_snake_case:
            response = await self._safe_dict_get("/api/diagnostics/system/system_information")
        else:
            response = await self._safe_dict_get("/api/diagnostics/system/systemInformation")
        system_info["name"] = response.get("name", None)
        return system_info

    @_log_errors
    async def get_firmware_update_info(self) -> MutableMapping[str, Any]:
        """Get the details of available firmware updates."""
        status = await self._safe_dict_get("/api/core/firmware/status")

        # if error or too old trigger check (only if check is not already in progress)
        # {'status_msg': 'Firmware status check was aborted internally. Please try again.', 'status': 'error'}
        # error could be because data has not been refreshed at all OR an upgrade is currently in progress
        # _LOGGER.debug("[get_firmware_update_info] status: %s", status)

        if error_status := bool(status.get("status") == "error"):
            _LOGGER.debug("Last firmware status check returned an error")

        product_version = dict_get(status, "product.product_version")
        product_latest = dict_get(status, "product.product_latest")
        missing_data = False
        if (
            not product_version
            or not product_latest
            or not isinstance(dict_get(status, "product.product_check"), MutableMapping)
            or not dict_get(status, "product.product_check")
        ):
            _LOGGER.debug("Missing data in firmware status")
            missing_data = True

        update_needs_info = False
        try:
            if (
                awesomeversion.AwesomeVersion(product_latest)
                > awesomeversion.AwesomeVersion(product_version)
                and status.get("status_msg", "").strip()
                == "There are no updates available on the selected mirror."
            ):
                _LOGGER.debug("Update available but missing details")
                update_needs_info = True
        except awesomeversion.exceptions.AwesomeVersionCompareException as e:
            _LOGGER.debug("Error checking firmware versions. %s: %s", type(e).__name__, e)
            update_needs_info = True

        last_check_str = status.get("last_check")
        last_check_expired = True
        if last_check_str:
            try:
                last_check_dt = parse(last_check_str, tzinfos=AMBIGUOUS_TZINFOS)
                if last_check_dt.tzinfo is None:
                    last_check_dt = last_check_dt.replace(
                        tzinfo=timezone(datetime.now().astimezone().utcoffset() or timedelta())
                    )
                last_check_expired = (datetime.now().astimezone() - last_check_dt) > timedelta(
                    days=1
                )
                if last_check_expired:
                    _LOGGER.debug("Firmware status last check > 1 day ago")
            except (ValueError, TypeError, ParserError, UnknownTimezoneWarning) as e:
                _LOGGER.debug(
                    "Error getting firmware status last check. %s: %s", type(e).__name__, e
                )
        else:
            _LOGGER.debug("Firmware status last check is missing")

        if error_status or last_check_expired or missing_data or update_needs_info:
            _LOGGER.info("Triggering firmware check")
            await self._post("/api/core/firmware/check")

        return status

    @_log_errors
    async def upgrade_firmware(self, type: str = "update") -> MutableMapping[str, Any] | None:
        """Trigger a firmware upgrade."""
        # minor updates of the same opnsense version
        if type == "update":
            # can watch the progress on the 'Updates' tab in the UI
            return await self._safe_dict_post("/api/core/firmware/update")

        # major updates to a new opnsense version
        if type == "upgrade":
            # can watch the progress on the 'Updates' tab in the UI
            return await self._safe_dict_post("/api/core/firmware/upgrade")
        return None

    @_log_errors
    async def upgrade_status(self) -> MutableMapping[str, Any]:
        """Return the status of the firmware upgrade."""
        return await self._safe_dict_post("/api/core/firmware/upgradestatus")

    @_log_errors
    async def firmware_changelog(self, version: str) -> MutableMapping[str, Any]:
        """Return the changelog for the firmware upgrade."""
        return await self._safe_dict_post(f"/api/core/firmware/changelog/{version}")

    @_log_errors
    async def get_config(self) -> MutableMapping[str, Any]:
        """XMLRPC call to return all the config settings."""
        script: str = r"""
global $config;

$toreturn = [
  "data" => $config,
];
"""
        response: MutableMapping[str, Any] = await self._exec_php(script)
        if not isinstance(response, MutableMapping):
            return {}
        ret_data = response.get("data", {})
        if not isinstance(ret_data, MutableMapping):
            return {}
        return ret_data

    @_log_errors
    async def enable_filter_rule_by_created_time(self, created_time: str) -> None:
        """Enable a filter rule."""
        config = await self.get_config()
        for rule in config["filter"]["rule"]:
            if "created" not in rule:
                continue
            if "time" not in rule["created"]:
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" in rule:
                del rule["disabled"]
                await self._restore_config_section("filter", config["filter"])
                await self._filter_configure()

    @_log_errors
    async def disable_filter_rule_by_created_time(self, created_time: str) -> None:
        """Disable a filter rule."""
        config: MutableMapping[str, Any] = await self.get_config()

        for rule in config.get("filter", {}).get("rule", []):
            if "created" not in rule:
                continue
            if "time" not in rule["created"]:
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" not in rule:
                rule["disabled"] = "1"
                await self._restore_config_section("filter", config["filter"])
                await self._filter_configure()

    # use created_time as a unique_id since none other exists
    @_log_errors
    async def enable_nat_port_forward_rule_by_created_time(self, created_time: str) -> None:
        """Enable a NAT Port Forward rule."""
        config: MutableMapping[str, Any] = await self.get_config()
        for rule in config.get("nat", {}).get("rule", []):
            if "created" not in rule:
                continue
            if "time" not in rule["created"]:
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" in rule:
                del rule["disabled"]
                await self._restore_config_section("nat", config["nat"])
                await self._filter_configure()

    # use created_time as a unique_id since none other exists
    @_log_errors
    async def disable_nat_port_forward_rule_by_created_time(self, created_time: str) -> None:
        """Disable a NAT Port Forward rule."""
        config: MutableMapping[str, Any] = await self.get_config()
        for rule in config.get("nat", {}).get("rule", []):
            if "created" not in rule:
                continue
            if "time" not in rule["created"]:
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" not in rule:
                rule["disabled"] = "1"
                await self._restore_config_section("nat", config["nat"])
                await self._filter_configure()

    # use created_time as a unique_id since none other exists
    @_log_errors
    async def enable_nat_outbound_rule_by_created_time(self, created_time: str) -> None:
        """Enable NAT Outbound rule."""
        config: MutableMapping[str, Any] = await self.get_config()
        for rule in config.get("nat", {}).get("outbound", {}).get("rule", []):
            if "created" not in rule:
                continue
            if "time" not in rule["created"]:
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" in rule:
                del rule["disabled"]
                await self._restore_config_section("nat", config["nat"])
                await self._filter_configure()

    # use created_time as a unique_id since none other exists
    @_log_errors
    async def disable_nat_outbound_rule_by_created_time(self, created_time: str) -> None:
        """Disable NAT Outbound Rule."""
        config: MutableMapping[str, Any] = await self.get_config()
        for rule in config.get("nat", {}).get("outbound", {}).get("rule", []):
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" not in rule:
                rule["disabled"] = "1"
                await self._restore_config_section("nat", config["nat"])
                await self._filter_configure()

    @_log_errors
    async def get_arp_table(self, resolve_hostnames: bool = False) -> list:
        """Return the active ARP table."""
        # [{'hostname': '?', 'ip-address': '<ip>', 'mac-address': '<mac>', 'interface': 'em0', 'expires': 1199, 'type': 'ethernet'}, ...]
        request_body: MutableMapping[str, Any] = {"resolve": "yes"}
        arp_table_info = await self._safe_dict_post(
            "/api/diagnostics/interface/search_arp", payload=request_body
        )
        # _LOGGER.debug(f"[get_arp_table] arp_table_info: {arp_table_info}")
        arp_table: list = arp_table_info.get("rows", [])
        # _LOGGER.debug(f"[get_arp_table] arp_table: {arp_table}")
        return arp_table

    @_log_errors
    async def get_services(self) -> list:
        """Get the list of OPNsense services."""
        response = await self._safe_dict_get("/api/core/service/search")
        # _LOGGER.debug(f"[get_services] response: {response}")
        services: list = response.get("rows", [])
        for service in services:
            service["status"] = service.get("running", 0) == 1
        # _LOGGER.debug(f"[get_services] services: {services}")
        return services

    @_log_errors
    async def get_service_is_running(self, service: str) -> bool:
        """Return if the OPNsense service is running."""
        services: list = await self.get_services()
        if services is None or not isinstance(services, list):
            return False
        for svc in services:
            if (svc.get("name", None) == service or svc.get("id", None) == service) and svc.get(
                "status", False
            ):
                return True
        return False

    async def _manage_service(self, action: str, service: str) -> bool:
        if not service:
            return False
        api_addr: str = f"/api/core/service/{action}/{service}"
        response = await self._safe_dict_post(api_addr)
        _LOGGER.debug("[%s_service] service: %s, response: %s", action, service, response)
        return response.get("result", "failed") == "ok"

    @_log_errors
    async def start_service(self, service: str) -> bool:
        """Start OPNsense service."""
        return await self._manage_service("start", service)

    @_log_errors
    async def stop_service(self, service: str) -> bool:
        """Stop OPNsense service."""
        return await self._manage_service("stop", service)

    @_log_errors
    async def restart_service(self, service: str) -> bool:
        """Restart OPNsense service."""
        return await self._manage_service("restart", service)

    @_log_errors
    async def restart_service_if_running(self, service: str) -> bool:
        """Restart OPNsense service only if it is running."""
        if await self.get_service_is_running(service):
            return await self.restart_service(service)
        return True

    @_log_errors
    async def get_dhcp_leases(self) -> MutableMapping[str, Any]:
        """Return list of DHCP leases."""
        leases_raw: list = (
            await self._get_kea_dhcpv4_leases()
            + await self._get_isc_dhcpv4_leases()
            + await self._get_isc_dhcpv6_leases()
            + await self._get_dnsmasq_leases()
        )
        # TODO: Add Kea dhcpv6 leases if API ever gets added

        # _LOGGER.debug(f"[get_dhcp_leases] leases_raw: {leases_raw}")
        leases: MutableMapping[str, Any] = {}
        lease_interfaces: MutableMapping[str, Any] = await self._get_kea_interfaces()
        for lease in leases_raw:
            if (
                not isinstance(lease, MutableMapping)
                or not isinstance(lease.get("if_name", None), str)
                or len(lease.get("if_name", "")) == 0
            ):
                continue
            if_name = lease.pop("if_name", None)
            if_descr = lease.pop("if_descr", None)
            if if_name not in leases:
                lease_interfaces[if_name] = if_descr
                leases[if_name] = []
            leases[if_name].append(lease)

        sorted_lease_interfaces: MutableMapping[str, Any] = {
            key: lease_interfaces[key] for key in sorted(lease_interfaces)
        }
        sorted_leases: MutableMapping[str, Any] = {key: leases[key] for key in sorted(leases)}
        for if_subnet in sorted_leases.values():
            sorted_if: list = sorted(if_subnet, key=get_ip_key)
            if_subnet = sorted_if

        dhcp_leases: MutableMapping[str, Any] = {
            "lease_interfaces": sorted_lease_interfaces,
            "leases": sorted_leases,
        }
        # _LOGGER.debug(f"[get_dhcp_leases] dhcp_leases: {dhcp_leases}")

        return dhcp_leases

    async def _get_kea_interfaces(self) -> MutableMapping[str, Any]:
        """Return interfaces setup for Kea."""
        response = await self._safe_dict_get("/api/kea/dhcpv4/get")
        lease_interfaces: MutableMapping[str, Any] = {}
        general: MutableMapping[str, Any] = response.get("dhcpv4", {}).get("general", {})
        if general.get("enabled", "0") != "1":
            return {}
        for if_name, iface in general.get("interfaces", {}).items():
            if not isinstance(iface, MutableMapping):
                continue
            if iface.get("selected", 0) == 1 and iface.get("value", None):
                lease_interfaces[if_name] = iface.get("value")
        # _LOGGER.debug(f"[get_kea_interfaces] lease_interfaces: {lease_interfaces}")
        return lease_interfaces

    async def _get_kea_dhcpv4_leases(self) -> list:
        """Return IPv4 DHCP Leases by Kea."""
        response = await self._safe_dict_get("/api/kea/leases4/search")
        if not isinstance(response.get("rows", None), list):
            return []
        if self._use_snake_case:
            res_resp = await self._safe_dict_get("/api/kea/dhcpv4/search_reservation")
        else:
            res_resp = await self._safe_dict_get("/api/kea/dhcpv4/searchReservation")
        if not isinstance(res_resp.get("rows", None), list):
            res_info = []
        else:
            res_info = res_resp.get("rows", [])
        reservations = {}
        for res in res_info:
            if res.get("hw_address", None):
                reservations.update({res.get("hw_address"): res.get("ip_address", "")})
        # _LOGGER.debug(f"[get_kea_dhcpv4_leases] reservations: {reservations}")
        leases_info: list = response.get("rows", [])
        # _LOGGER.debug(f"[get_kea_dhcpv4_leases] leases_info: {leases_info}")
        leases: list = []
        for lease_info in leases_info:
            if (
                lease_info is None
                or not isinstance(lease_info, MutableMapping)
                or lease_info.get("state", "0") != "0"
                or not lease_info.get("hwaddr", None)
            ):
                continue
            lease: MutableMapping[str, Any] = {}
            lease["address"] = lease_info.get("address", None)
            lease["hostname"] = (
                lease_info.get("hostname", None).strip(".")
                if isinstance(lease_info.get("hostname", None), str)
                and len(lease_info.get("hostname", "")) > 0
                else None
            )
            lease["if_descr"] = lease_info.get("if_descr", None)
            lease["if_name"] = lease_info.get("if_name", None)
            if (
                lease_info.get("hwaddr", None)
                and lease_info.get("hwaddr") in reservations
                and reservations[lease_info.get("hwaddr")] == lease_info.get("address", None)
            ):
                lease["type"] = "static"
            else:
                lease["type"] = "dynamic"
            lease["mac"] = lease_info.get("hwaddr", None)
            if OPNsenseClient._try_to_int(lease_info.get("expire", None)):
                lease["expires"] = timestamp_to_datetime(
                    OPNsenseClient._try_to_int(lease_info.get("expire", None)) or 0
                )
                if lease["expires"] < datetime.now().astimezone():
                    continue
            else:
                lease["expires"] = lease_info.get("expire", None)
            leases.append(lease)
        # _LOGGER.debug(f"[get_kea_dhcpv4_leases] leases: {leases}")
        return leases

    def _keep_latest_leases(self, reservations: list[dict]) -> list[dict]:
        seen: dict[tuple, dict] = {}

        for entry in reservations:
            # Create a key from all fields except 'expire'
            key = tuple((k, v) for k, v in entry.items() if k != "expire")

            # Keep the entry with the latest expiration time
            if key not in seen or entry["expire"] > seen[key]["expire"]:
                seen[key] = entry

        return list(seen.values())

    async def _get_dnsmasq_leases(self) -> list:
        """Return Dnsmasq IPv4 and IPv6 DHCP Leases."""

        try:
            if awesomeversion.AwesomeVersion(
                self._firmware_version
            ) < awesomeversion.AwesomeVersion("25.1"):
                _LOGGER.debug("Skipping get_dnsmasq_leases for OPNsense < 25.1")
                return []
            if awesomeversion.AwesomeVersion(
                self._firmware_version
            ) < awesomeversion.AwesomeVersion("25.1.7"):
                _LOGGER.debug("Skipping get_dnsmasq_leases for OPNsense < 25.1.7")
                return []
        except awesomeversion.exceptions.AwesomeVersionCompareException:
            pass

        response = await self._safe_dict_get("/api/dnsmasq/leases/search")
        leases_info: list = response.get("rows", [])
        if not isinstance(leases_info, list):
            return []
        # _LOGGER.debug("[get_dnsmasq_leases] leases_info: %s", leases_info)
        cleaned_leases = self._keep_latest_leases(leases_info)
        # _LOGGER.debug("[get_dnsmasq_leases] cleaned_leases: %s", cleaned_leases)

        leases: list = []
        for lease_info in cleaned_leases:
            # _LOGGER.debug("[get_dnsmasq_leases] lease_info: %s", lease_info)
            if not isinstance(lease_info, MutableMapping):
                continue
            lease: MutableMapping[str, Any] = {}
            lease["address"] = lease_info.get("address", None)
            lease["hostname"] = (
                lease_info.get("hostname", None)
                if isinstance(lease_info.get("hostname", None), str)
                and lease_info.get("hostname", None) != "*"
                and len(lease_info.get("hostname", "")) > 0
                else None
            )
            lease["if_descr"] = lease_info.get("if_descr", None)
            lease["if_name"] = lease_info.get("if", None)
            if lease_info.get("is_reserved", "0") == "1":
                lease["type"] = "static"
            else:
                lease["type"] = "dynamic"
            lease["mac"] = (
                lease_info.get("hwaddr", None)
                if isinstance(lease_info.get("hwaddr", None), str)
                and len(lease_info.get("hwaddr", "")) > 0
                else None
            )

            if OPNsenseClient._try_to_int(lease_info.get("expire", None)):
                lease["expires"] = timestamp_to_datetime(
                    OPNsenseClient._try_to_int(lease_info.get("expire", None)) or 0
                )
                if lease["expires"] < datetime.now().astimezone():
                    continue
            else:
                lease["expires"] = lease_info.get("expire", None)
            leases.append(lease)
        # _LOGGER.debug("[get_dnsmasq_leases] leases: %s", leases)
        return leases

    async def _get_isc_dhcpv4_leases(self) -> list:
        """Return IPv4 DHCP Leases by ISC."""
        if self._use_snake_case:
            response = await self._safe_dict_get("/api/dhcpv4/leases/search_lease")
        else:
            response = await self._safe_dict_get("/api/dhcpv4/leases/searchLease")
        leases_info: list = response.get("rows", [])
        if not isinstance(leases_info, list):
            return []
        # _LOGGER.debug(f"[get_isc_dhcpv4_leases] leases_info: {leases_info}")
        leases: list = []
        for lease_info in leases_info:
            # _LOGGER.debug(f"[get_isc_dhcpv4_leases] lease_info: {lease_info}")
            if (
                not isinstance(lease_info, MutableMapping)
                or lease_info.get("state", "") != "active"
                or not lease_info.get("mac", None)
            ):
                continue
            lease: MutableMapping[str, Any] = {}
            lease["address"] = lease_info.get("address", None)
            lease["hostname"] = (
                lease_info.get("hostname", None)
                if isinstance(lease_info.get("hostname", None), str)
                and len(lease_info.get("hostname", "")) > 0
                else None
            )
            lease["if_descr"] = lease_info.get("if_descr", None)
            lease["if_name"] = lease_info.get("if", None)
            lease["type"] = lease_info.get("type", None)
            lease["mac"] = lease_info.get("mac", None)
            if lease_info.get("ends", None):
                dt: datetime = datetime.strptime(lease_info.get("ends", None), "%Y/%m/%d %H:%M:%S")
                lease["expires"] = dt.replace(
                    tzinfo=timezone(datetime.now().astimezone().utcoffset() or timedelta())
                )
                if lease["expires"] < datetime.now().astimezone():
                    continue
            else:
                lease["expires"] = lease_info.get("ends", None)
            leases.append(lease)
        # _LOGGER.debug(f"[get_isc_dhcpv4_leases] leases: {leases}")
        return leases

    async def _get_isc_dhcpv6_leases(self) -> list:
        """Return IPv6 DHCP Leases by ISC."""
        if self._use_snake_case:
            response = await self._safe_dict_get("/api/dhcpv6/leases/search_lease")
        else:
            response = await self._safe_dict_get("/api/dhcpv6/leases/searchLease")
        leases_info: list = response.get("rows", [])
        if not isinstance(leases_info, list):
            return []
        # _LOGGER.debug(f"[get_isc_dhcpv6_leases] leases_info: {leases_info}")
        leases: list = []
        for lease_info in leases_info:
            # _LOGGER.debug(f"[get_isc_dhcpv6_leases] lease_info: {lease_info}")
            if (
                not isinstance(lease_info, MutableMapping)
                or lease_info.get("state", "") != "active"
                or not lease_info.get("mac", None)
            ):
                continue
            lease: MutableMapping[str, Any] = {}
            lease["address"] = lease_info.get("address", None)
            lease["hostname"] = (
                lease_info.get("hostname", None)
                if isinstance(lease_info.get("hostname", None), str)
                and len(lease_info.get("hostname", "")) > 0
                else None
            )
            lease["if_descr"] = lease_info.get("if_descr", None)
            lease["if_name"] = lease_info.get("if", None)
            lease["type"] = lease_info.get("type", None)
            lease["mac"] = lease_info.get("mac", None)
            if lease_info.get("ends", None):
                dt: datetime = datetime.strptime(lease_info.get("ends", None), "%Y/%m/%d %H:%M:%S")
                lease["expires"] = dt.replace(
                    tzinfo=timezone(datetime.now().astimezone().utcoffset() or timedelta())
                )
                if lease["expires"] < datetime.now().astimezone():
                    continue
            else:
                lease["expires"] = lease_info.get("ends", None)
            leases.append(lease)
        # _LOGGER.debug(f"[get_isc_dhcpv6_leases] leases: {leases}")
        return leases

    @_log_errors
    async def get_carp_status(self) -> bool:
        """Return the Carp status."""
        response = await self._safe_dict_get("/api/diagnostics/interface/get_vip_status")
        # _LOGGER.debug(f"[get_carp_status] response: {response}")
        return response.get("carp", {}).get("allow", "0") == "1"

    @_log_errors
    async def get_carp_interfaces(self) -> list:
        """Return the interfaces used by Carp."""
        vip_settings_raw = await self._safe_dict_get("/api/interfaces/vip_settings/get")
        if not isinstance(vip_settings_raw.get("rows", None), list):
            vip_settings: list = []
        else:
            vip_settings = vip_settings_raw.get("rows", [])
        # _LOGGER.debug(f"[get_carp_interfaces] vip_settings: {vip_settings}")

        vip_status_raw = await self._safe_dict_get("/api/diagnostics/interface/get_vip_status")
        if not isinstance(vip_status_raw.get("rows", None), list):
            vip_status: list = []
        else:
            vip_status = vip_status_raw.get("rows", [])
        # _LOGGER.debug(f"[get_carp_interfaces] vip_status: {vip_status}")
        carp = []
        for vip in vip_settings:
            if vip.get("mode", "").lower() != "carp":
                continue

            for status in vip_status:
                if vip.get("interface", "").lower() == status.get("interface", "_").lower():
                    vip["status"] = status.get("status", None)
                    break
            if "status" not in vip or not vip.get("status"):
                vip["status"] = "DISABLED"

            carp.append(vip)
        _LOGGER.debug("[get_carp_interfaces] carp: %s", carp)
        return carp

    @_log_errors
    async def system_reboot(self) -> bool:
        """Reboot OPNsense."""
        response = await self._safe_dict_post("/api/core/system/reboot")
        _LOGGER.debug("[system_reboot] response: %s", response)
        if response.get("status", "") == "ok":
            return True
        return False

    @_log_errors
    async def system_halt(self) -> None:
        """Shutdown OPNsense."""
        response = await self._safe_dict_post("/api/core/system/halt")
        _LOGGER.debug("[system_halt] response: %s", response)
        if response.get("status", "") == "ok":
            return
        return

    @_log_errors
    async def send_wol(self, interface: str, mac: str) -> bool:
        """Send a wake on lan packet to the specified MAC address."""
        payload: MutableMapping[str, Any] = {"wake": {"interface": interface, "mac": mac}}
        _LOGGER.debug("[send_wol] payload: %s", payload)
        response = await self._safe_dict_post("/api/wol/wol/set", payload)
        _LOGGER.debug("[send_wol] response: %s", response)
        if response.get("status", "") == "ok":
            return True
        return False

    @staticmethod
    def _try_to_int(input: Any | None, retval: int | None = None) -> int | None:
        """Return field to int."""
        if input is None:
            return retval
        try:
            return int(input)
        except (ValueError, TypeError):
            return retval

    @staticmethod
    def _try_to_float(input: Any | None, retval: float | None = None) -> float | None:
        """Return field to float."""
        if input is None:
            return retval
        try:
            return float(input)
        except (ValueError, TypeError):
            return retval

    @_log_errors
    async def get_telemetry(self) -> MutableMapping[str, Any]:
        """Get telemetry data from OPNsense."""
        telemetry: MutableMapping[str, Any] = {}
        telemetry["mbuf"] = await self._get_telemetry_mbuf()
        telemetry["pfstate"] = await self._get_telemetry_pfstate()
        telemetry["memory"] = await self._get_telemetry_memory()
        telemetry["system"] = await self._get_telemetry_system()
        telemetry["cpu"] = await self._get_telemetry_cpu()
        telemetry["filesystems"] = await self._get_telemetry_filesystems()
        telemetry["temps"] = await self._get_telemetry_temps()
        # _LOGGER.debug(f"[get_telemetry] telemetry: {telemetry}")
        return telemetry

    @_log_errors
    async def get_interfaces(self) -> MutableMapping[str, Any]:
        """Return all OPNsense interfaces."""
        interface_info = await self._safe_list_get("/api/interfaces/overview/export")
        # _LOGGER.debug(f"[get_interfaces] interface_info: {interface_info}")
        if not len(interface_info) > 0:
            return {}
        interfaces: MutableMapping[str, Any] = {}
        for ifinfo in interface_info:
            interface: MutableMapping[str, Any] = {}
            if not isinstance(ifinfo, MutableMapping) or ifinfo.get("identifier", "") == "":
                continue
            interface["inpkts"] = OPNsenseClient._try_to_int(
                ifinfo.get("statistics", {}).get("packets received", None)
            )
            interface["outpkts"] = OPNsenseClient._try_to_int(
                ifinfo.get("statistics", {}).get("packets transmitted", None)
            )
            interface["inbytes"] = OPNsenseClient._try_to_int(
                ifinfo.get("statistics", {}).get("bytes received", None)
            )
            interface["outbytes"] = OPNsenseClient._try_to_int(
                ifinfo.get("statistics", {}).get("bytes transmitted", None)
            )
            interface["inbytes_frmt"] = OPNsenseClient._try_to_int(
                ifinfo.get("statistics", {}).get("bytes received", None)
            )
            interface["outbytes_frmt"] = OPNsenseClient._try_to_int(
                ifinfo.get("statistics", {}).get("bytes transmitted", None)
            )
            interface["inerrs"] = OPNsenseClient._try_to_int(
                ifinfo.get("statistics", {}).get("input errors", None)
            )
            interface["outerrs"] = OPNsenseClient._try_to_int(
                ifinfo.get("statistics", {}).get("output errors", None)
            )
            interface["collisions"] = OPNsenseClient._try_to_int(
                ifinfo.get("statistics", {}).get("collisions", None)
            )
            interface["interface"] = ifinfo.get("identifier", "")
            interface["name"] = ifinfo.get("description", "")
            interface["status"] = ""
            if ifinfo.get("status", "") in {"down", "no carrier", "up"}:
                interface["status"] = ifinfo.get("status", "")
            elif ifinfo.get("status", "") in ("associated"):
                interface["status"] = "up"
            interface["ipv4"] = ifinfo.get("addr4", None)
            interface["ipv6"] = ifinfo.get("addr6", None)
            interface["media"] = ifinfo.get("media", None)
            interface["gateways"] = ifinfo.get("gateways", [])
            interface["routes"] = ifinfo.get("routes", [])
            interface["device"] = ifinfo.get("device", None)
            if ifinfo.get("macaddr", None) and ifinfo.get("macaddr", None) != "00:00:00:00:00:00":
                interface["mac"] = ifinfo.get("macaddr", None)
            interface["enabled"] = ifinfo.get("enabled", None)
            interface["vlan_tag"] = ifinfo.get("vlan_tag", None)
            interfaces[ifinfo.get("identifier", "")] = interface
        # _LOGGER.debug(f"[get_interfaces] interfaces: {interfaces}")
        return interfaces

    @_log_errors
    async def _get_telemetry_mbuf(self) -> MutableMapping[str, Any]:
        mbuf_info = await self._safe_dict_post("/api/diagnostics/system/system_mbuf")
        # _LOGGER.debug(f"[get_telemetry_mbuf] mbuf_info: {mbuf_info}")
        mbuf: MutableMapping[str, Any] = {}
        mbuf["used"] = OPNsenseClient._try_to_int(
            mbuf_info.get("mbuf-statistics", {}).get("mbuf-current", None)
        )
        mbuf["total"] = OPNsenseClient._try_to_int(
            mbuf_info.get("mbuf-statistics", {}).get("mbuf-total", None)
        )
        mbuf["used_percent"] = (
            round(mbuf["used"] / mbuf["total"] * 100)
            if isinstance(mbuf["used"], int)
            and isinstance(mbuf["total"], int)
            and mbuf["total"] > 0
            else None
        )
        # _LOGGER.debug(f"[get_telemetry_mbuf] mbuf: {mbuf}")
        return mbuf

    @_log_errors
    async def _get_telemetry_pfstate(self) -> MutableMapping[str, Any]:
        pfstate_info = await self._safe_dict_post("/api/diagnostics/firewall/pf_states")
        # _LOGGER.debug(f"[get_telemetry_pfstate] pfstate_info: {pfstate_info}")
        pfstate: MutableMapping[str, Any] = {}
        pfstate["used"] = OPNsenseClient._try_to_int(pfstate_info.get("current", None))
        pfstate["total"] = OPNsenseClient._try_to_int(pfstate_info.get("limit", None))
        pfstate["used_percent"] = (
            round(pfstate["used"] / pfstate["total"] * 100)
            if isinstance(pfstate["used"], int)
            and isinstance(pfstate["total"], int)
            and pfstate["total"] > 0
            else None
        )
        # _LOGGER.debug(f"[get_telemetry_pfstate] pfstate: {pfstate}")
        return pfstate

    @_log_errors
    async def _get_telemetry_memory(self) -> MutableMapping[str, Any]:
        if self._use_snake_case:
            memory_info = await self._safe_dict_post("/api/diagnostics/system/system_resources")
        else:
            memory_info = await self._safe_dict_post("/api/diagnostics/system/systemResources")
        # _LOGGER.debug(f"[get_telemetry_memory] memory_info: {memory_info}")
        memory: MutableMapping[str, Any] = {}
        memory["physmem"] = OPNsenseClient._try_to_int(
            memory_info.get("memory", {}).get("total", None)
        )
        memory["used"] = OPNsenseClient._try_to_int(memory_info.get("memory", {}).get("used", None))
        memory["used_percent"] = (
            round(memory["used"] / memory["physmem"] * 100)
            if isinstance(memory["used"], int)
            and isinstance(memory["physmem"], int)
            and memory["physmem"] > 0
            else None
        )
        swap_info = await self._safe_dict_post("/api/diagnostics/system/system_swap")
        if (
            not isinstance(swap_info.get("swap", None), list)
            or not len(swap_info.get("swap", [])) > 0
            or not isinstance(swap_info.get("swap", [])[0], MutableMapping)
        ):
            return memory
        # _LOGGER.debug(f"[get_telemetry_memory] swap_info: {swap_info}")
        memory["swap_total"] = OPNsenseClient._try_to_int(
            swap_info.get("swap", [])[0].get("total", None)
        )
        memory["swap_reserved"] = OPNsenseClient._try_to_int(swap_info["swap"][0].get("used", None))
        memory["swap_used_percent"] = (
            round(memory["swap_reserved"] / memory["swap_total"] * 100)
            if isinstance(memory["swap_reserved"], int)
            and isinstance(memory["swap_total"], int)
            and memory["swap_total"] > 0
            else 0
        )
        # _LOGGER.debug(f"[get_telemetry_memory] memory: {memory}")
        return memory

    @_log_errors
    async def _get_telemetry_system(self) -> MutableMapping[str, Any]:
        if self._use_snake_case:
            time_info = await self._safe_dict_post("/api/diagnostics/system/system_time")
        else:
            time_info = await self._safe_dict_post("/api/diagnostics/system/systemTime")
        # _LOGGER.debug("[get_telemetry_system] time_info: %s", time_info)
        system: MutableMapping[str, Any] = {}

        try:
            systemtime: datetime = parse(time_info["datetime"], tzinfos=AMBIGUOUS_TZINFOS)
            if systemtime.tzinfo is None:
                systemtime = systemtime.replace(
                    tzinfo=timezone(datetime.now().astimezone().utcoffset() or timedelta())
                )
        except (ValueError, TypeError, ParserError, UnknownTimezoneWarning) as e:
            _LOGGER.warning(
                "Failed to parse opnsense system time (aka. datetime), using HA system time instead: %s. %s: %s",
                time_info["datetime"],
                type(e).__name__,
                e,
            )
            systemtime = datetime.now().astimezone()

        pattern = re.compile(r"^(?:(\d+)\s+days?,\s+)?(\d{2}):(\d{2}):(\d{2})$")
        match = pattern.match(time_info.get("uptime", ""))
        if match:
            days_str, hours_str, minutes_str, seconds_str = match.groups()
            days = OPNsenseClient._try_to_int(days_str, 0) or 0
            hours = OPNsenseClient._try_to_int(hours_str, 0) or 0
            minutes = OPNsenseClient._try_to_int(minutes_str, 0) or 0
            seconds = OPNsenseClient._try_to_int(seconds_str, 0) or 0

            uptime = days * 86400 + hours * 3600 + minutes * 60 + seconds

        boottime: datetime | None = None
        if "boottime" in time_info:
            try:
                boottime = parse(time_info["boottime"], tzinfos=AMBIGUOUS_TZINFOS)
                if boottime and boottime.tzinfo is None:
                    boottime = boottime.replace(
                        tzinfo=timezone(datetime.now().astimezone().utcoffset() or timedelta())
                    )
            except (ValueError, TypeError, ParserError, UnknownTimezoneWarning) as e:
                _LOGGER.info(
                    "Failed to parse opnsense boottime: %s. %s: %s",
                    time_info["boottime"],
                    type(e).__name__,
                    e,
                )

        if boottime:
            system["boottime"] = boottime.timestamp()
            if match:
                system["uptime"] = uptime
            else:
                system["uptime"] = int((systemtime - boottime).total_seconds())
        elif match:
            system["uptime"] = uptime
            boottime = systemtime - timedelta(seconds=system["uptime"])
            system["boottime"] = boottime.timestamp()
        else:
            _LOGGER.warning("Invalid uptime format")

        load_str: str = time_info.get("loadavg", "")
        load_list: list[str] = load_str.split(", ")
        if len(load_list) == 3:
            system["load_average"] = {
                "one_minute": float(load_list[0]),
                "five_minute": float(load_list[1]),
                "fifteen_minute": float(load_list[2]),
            }
        else:
            system["load_average"] = {
                "one_minute": None,
                "five_minute": None,
                "fifteen_minute": None,
            }
        # _LOGGER.debug(f"[get_telemetry_system] system: {system}")
        return system

    @_log_errors
    async def _get_telemetry_cpu(self) -> MutableMapping[str, Any]:
        if self._use_snake_case:
            cputype_info = await self._safe_list_post("/api/diagnostics/cpu_usage/get_c_p_u_type")
        else:
            cputype_info = await self._safe_list_post("/api/diagnostics/cpu_usage/getCPUType")
        # _LOGGER.debug(f"[get_telemetry_cpu] cputype_info: {cputype_info}")
        if not len(cputype_info) > 0:
            return {}
        cpu: MutableMapping[str, Any] = {}
        cores_match = re.search(r"\((\d+) cores", cputype_info[0])
        cpu["count"] = OPNsenseClient._try_to_int(cores_match.group(1)) if cores_match else 0

        cpustream_info = await self._get_from_stream("/api/diagnostics/cpu_usage/stream")
        # {"total":29,"user":2,"nice":0,"sys":27,"intr":0,"idle":70}
        # _LOGGER.debug(f"[get_telemetry_cpu] cpustream_info: {cpustream_info}")
        cpu["usage_total"] = OPNsenseClient._try_to_int(cpustream_info.get("total", None))
        cpu["usage_user"] = OPNsenseClient._try_to_int(cpustream_info.get("user", None))
        cpu["usage_nice"] = OPNsenseClient._try_to_int(cpustream_info.get("nice", None))
        cpu["usage_system"] = OPNsenseClient._try_to_int(cpustream_info.get("sys", None))
        cpu["usage_interrupt"] = OPNsenseClient._try_to_int(cpustream_info.get("intr", None))
        cpu["usage_idle"] = OPNsenseClient._try_to_int(cpustream_info.get("idle", None))
        # _LOGGER.debug(f"[get_telemetry_cpu] cpu: {cpu}")
        return cpu

    @_log_errors
    async def _get_telemetry_filesystems(self) -> list:
        if self._use_snake_case:
            filesystems_info = await self._safe_dict_post("/api/diagnostics/system/system_disk")
        else:
            filesystems_info = await self._safe_dict_post("/api/diagnostics/system/systemDisk")
        # _LOGGER.debug(f"[get_telemetry_filesystems] filesystems_info: {filesystems_info}")
        filesystems: list = filesystems_info.get("devices", [])
        # _LOGGER.debug(f"[get_telemetry_filesystems] filesystems: {filesystems}")
        return filesystems

    @_log_errors
    async def get_openvpn(self) -> MutableMapping[str, Any]:
        """Return OpenVPN information."""
        # https://docs.opnsense.org/development/api/core/openvpn.html
        # https://github.com/opnsense/core/blob/master/src/opnsense/www/js/widgets/OpenVPNClients.js
        # https://github.com/opnsense/core/blob/master/src/opnsense/www/js/widgets/OpenVPNServers.js
        openvpn: MutableMapping[str, Any] = {"servers": {}, "clients": {}}

        # Fetch data
        if self._use_snake_case:
            sessions_info = await self._safe_dict_get("/api/openvpn/service/search_sessions")
            routes_info = await self._safe_dict_get("/api/openvpn/service/search_routes")
        else:
            sessions_info = await self._safe_dict_get("/api/openvpn/service/searchSessions")
            routes_info = await self._safe_dict_get("/api/openvpn/service/searchRoutes")
        providers_info = await self._safe_dict_get("/api/openvpn/export/providers")
        instances_info = await self._safe_dict_get("/api/openvpn/instances/search")

        await OPNsenseClient._process_openvpn_instances(instances_info, openvpn)
        await OPNsenseClient._process_openvpn_providers(providers_info, openvpn)
        await OPNsenseClient._process_openvpn_sessions(sessions_info, openvpn)
        await OPNsenseClient._process_openvpn_routes(routes_info, openvpn)
        # _LOGGER.debug(f"[get_openvpn] sessions_info: {sessions_info}")
        # _LOGGER.debug(f"[get_openvpn] routes_info: {routes_info}")
        # _LOGGER.debug(f"[get_openvpn] providers_info: {providers_info}")
        # _LOGGER.debug(f"[get_openvpn] instances_info: {instances_info}")

        await self._fetch_openvpn_server_details(openvpn)

        _LOGGER.debug("[get_openvpn] openvpn: %s", openvpn)
        return openvpn

    @staticmethod
    async def _process_openvpn_instances(
        instances_info: MutableMapping[str, Any], openvpn: MutableMapping[str, Any]
    ) -> None:
        """Process OpenVPN instances into servers and clients."""
        for instance in instances_info.get("rows", []):
            if not isinstance(instance, MutableMapping):
                continue
            role = instance.get("role", "").lower()
            uuid = instance.get("uuid")
            if role == "server":
                await OPNsenseClient._add_openvpn_server(instance, openvpn)
            elif role == "client" and uuid:
                openvpn["clients"][uuid] = {
                    "name": instance.get("description"),
                    "uuid": uuid,
                    "enabled": instance.get("enabled") == "1",
                }

    @staticmethod
    async def _add_openvpn_server(
        instance: MutableMapping[str, Any], openvpn: MutableMapping[str, Any]
    ) -> None:
        """Add a server to the OpenVPN structure."""
        uuid = instance.get("uuid")
        if not uuid:
            return
        if uuid not in openvpn["servers"]:
            openvpn["servers"][uuid] = {
                "uuid": uuid,
                "name": instance.get("description"),
                "enabled": instance.get("enabled") == "1",
                "dev_type": instance.get("dev_type"),
                "clients": [],
            }

    @staticmethod
    async def _process_openvpn_providers(
        providers_info: MutableMapping[str, Any], openvpn: MutableMapping[str, Any]
    ) -> None:
        """Process OpenVPN providers."""
        for uuid, vpn_info in providers_info.items():
            if not uuid or not isinstance(vpn_info, MutableMapping):
                continue
            server = openvpn["servers"].setdefault(uuid, {"uuid": uuid, "clients": []})
            server.update({"name": vpn_info.get("name")})
            if vpn_info.get("hostname") and vpn_info.get("local_port"):
                server["endpoint"] = f"{vpn_info['hostname']}:{vpn_info['local_port']}"

    @staticmethod
    async def _process_openvpn_sessions(
        sessions_info: MutableMapping[str, Any], openvpn: MutableMapping[str, Any]
    ) -> None:
        """Process OpenVPN sessions."""
        for session in sessions_info.get("rows", []):
            if session.get("type") != "server":
                continue
            server_id = str(session["id"]).split("_", 1)[0]
            server = openvpn["servers"].setdefault(server_id, {"uuid": server_id, "clients": []})
            server["name"] = session.get("description", "")
            await OPNsenseClient._update_openvpn_server_status(server, session)

    @staticmethod
    async def _update_openvpn_server_status(
        server: MutableMapping[str, Any], session: MutableMapping[str, Any]
    ) -> None:
        """Update server status based on session data."""
        status = session.get("status")
        if not session.get("is_client", False):
            server["status"] = (
                "disabled"
                if not server.get("enabled", True)
                else "up"
                if status in {"connected", "ok"}
                else "failed"
                if status == "failed"
                else status or "down"
            )
        else:
            server.update(
                {
                    "status": "up",
                    "latest_handshake": timestamp_to_datetime(
                        session.get("connected_since__time_t_")
                    ),
                    "total_bytes_recv": OPNsenseClient._try_to_int(
                        session.get("bytes_received", 0), 0
                    ),
                    "total_bytes_sent": OPNsenseClient._try_to_int(session.get("bytes_sent", 0), 0),
                }
            )

    @staticmethod
    async def _process_openvpn_routes(
        routes_info: MutableMapping[str, Any], openvpn: MutableMapping[str, Any]
    ) -> None:
        """Process OpenVPN routes."""
        for route in routes_info.get("rows", []):
            server_id = route.get("id")
            if not isinstance(route, MutableMapping) or server_id not in openvpn["servers"]:
                continue
            openvpn["servers"][server_id]["clients"].append(
                {
                    "name": route.get("common_name"),
                    "endpoint": route.get("real_address"),
                    "tunnel_addresses": [route.get("virtual_address")],
                    "latest_handshake": timestamp_to_datetime(route.get("last_ref__time_t_", 0)),
                }
            )

    async def _fetch_openvpn_server_details(self, openvpn: MutableMapping[str, Any]) -> None:
        """Fetch detailed server information."""
        for uuid, server in openvpn["servers"].items():
            server.setdefault("total_bytes_sent", 0)
            server.setdefault("total_bytes_recv", 0)
            server["connected_clients"] = len(server.get("clients", []))
            details_info = await self._safe_dict_get(f"/api/openvpn/instances/get/{uuid}")
            details = (
                details_info.get("instance", {}) if isinstance(details_info, MutableMapping) else {}
            )
            if details.get("server"):
                server["tunnel_addresses"] = [details["server"]]
            server["dns_servers"] = [
                dns["value"]
                for dns in details.get("dns_servers", {}).values()
                if dns.get("selected") == 1 and dns.get("value")
            ]

    @_log_errors
    async def get_gateways(self) -> MutableMapping[str, Any]:
        """Return OPNsense Gateway details."""
        gateways_info = await self._safe_dict_get("/api/routes/gateway/status")
        # _LOGGER.debug(f"[get_gateways] gateways_info: {gateways_info}")
        gateways: MutableMapping[str, Any] = {}
        for gw_info in gateways_info.get("items", []):
            if isinstance(gw_info, MutableMapping) and "name" in gw_info:
                gateways[gw_info["name"]] = gw_info
        for gateway in gateways.values():
            gateway["status"] = gateway.pop("status_translated", gateway.get("status", "")).lower()
        # _LOGGER.debug(f"[get_gateways] gateways: {gateways}")
        return gateways

    @_log_errors
    async def _get_telemetry_temps(self) -> MutableMapping[str, Any]:
        if self._use_snake_case:
            temps_info = await self._safe_list_get("/api/diagnostics/system/system_temperature")
        else:
            temps_info = await self._safe_list_get("/api/diagnostics/system/systemTemperature")
        # _LOGGER.debug(f"[get_telemetry_temps] temps_info: {temps_info}")
        if not len(temps_info) > 0:
            return {}
        temps: MutableMapping[str, Any] = {}
        for i, temp_info in enumerate(temps_info):
            temp: MutableMapping[str, Any] = {}
            temp["temperature"] = OPNsenseClient._try_to_float(temp_info.get("temperature", 0), 0)
            temp["name"] = (
                f"{temp_info.get('type_translated', 'Num')} {temp_info.get('device_seq', i)}"
            )
            temp["device_id"] = temp_info.get("device", str(i))
            temps[temp_info.get("device", str(i)).replace(".", "_")] = temp
        # _LOGGER.debug(f"[get_telemetry_temps] temps: {temps}")
        return temps

    @_log_errors
    async def get_notices(self) -> MutableMapping[str, Any]:
        """Get active OPNsense notices."""
        notices_info = await self._safe_dict_get("/api/core/system/status")
        # _LOGGER.debug(f"[get_notices] notices_info: {notices_info}")
        pending_notices_present = False
        pending_notices: list = []
        for key, notice in notices_info.items():
            if isinstance(notice, MutableMapping) and notice.get("statusCode", 2) != 2:
                pending_notices_present = True
                pending_notices.append(
                    {
                        "notice": notice.get("message", None),
                        "id": key,
                        "created_at": (
                            timestamp_to_datetime(int(notice.get("timestamp", 0)))
                            if notice.get("timestamp", None)
                            else None
                        ),
                    }
                )

        return {
            "pending_notices_present": pending_notices_present,
            "pending_notices": pending_notices,
        }
        # _LOGGER.debug(f"[get_notices] notices: {notices}")

    @_log_errors
    async def close_notice(self, id: str) -> bool:
        """Close selected notices."""

        dismiss_endpoint = (
            "/api/core/system/dismiss_status"
            if self._use_snake_case
            else "/api/core/system/dismissStatus"
        )

        # id = "all" to close all notices
        success = True
        if id.lower() == "all":
            notices = await self._safe_dict_get("/api/core/system/status")
            # _LOGGER.debug(f"[close_notice] notices: {notices}")
            for key, notice in notices.items():
                if "statusCode" in notice:
                    dismiss = await self._safe_dict_post(dismiss_endpoint, payload={"subject": key})
                    # _LOGGER.debug(f"[close_notice] id: {key}, dismiss: {dismiss}")
                    if dismiss.get("status", "failed") != "ok":
                        success = False
        else:
            dismiss = await self._safe_dict_post(dismiss_endpoint, payload={"subject": id})
            _LOGGER.debug("[close_notice] id: %s, dismiss: %s", id, dismiss)
            if dismiss.get("status", "failed") != "ok":
                success = False
        _LOGGER.debug("[close_notice] success: %s", success)
        return success

    @_log_errors
    async def get_unbound_blocklist(self) -> MutableMapping[str, Any]:
        """Return the Unbound Blocklist details."""
        response = await self._safe_dict_get("/api/unbound/settings/get")
        # _LOGGER.debug(f"[get_unbound_blocklist] response: {response}")
        dnsbl_settings = response.get("unbound", {}).get("dnsbl", {})
        # _LOGGER.debug(f"[get_unbound_blocklist] dnsbl_settings: {dnsbl_settings}")
        if not isinstance(dnsbl_settings, MutableMapping):
            return {}
        dnsbl = {}
        for attr in ("enabled", "safesearch", "nxdomain", "address"):
            dnsbl[attr] = dnsbl_settings.get(attr, "")
        for attr in ("type", "lists", "whitelists", "blocklists", "wildcards"):
            if isinstance(dnsbl_settings.get(attr, None), MutableMapping):
                dnsbl[attr] = ",".join(
                    [
                        key
                        for key, value in dnsbl_settings.get(attr, {}).items()
                        if isinstance(value, MutableMapping) and value.get("selected", 0) == 1
                    ]
                )
            else:
                dnsbl[attr] = ""
        # _LOGGER.debug(f"[get_unbound_blocklist] dnsbl: {dnsbl}")
        return dnsbl

    async def _set_unbound_blocklist(self, set_state: bool) -> bool:
        payload: MutableMapping[str, Any] = {}
        payload["unbound"] = {}
        payload["unbound"]["dnsbl"] = await self.get_unbound_blocklist()
        if not payload["unbound"]["dnsbl"]:
            _LOGGER.error("Unable to get Unbound Blocklist Status")
            return False
        if set_state:
            payload["unbound"]["dnsbl"]["enabled"] = "1"
        else:
            payload["unbound"]["dnsbl"]["enabled"] = "0"
        response = await self._post("/api/unbound/settings/set", payload=payload)
        dnsbl_resp = await self._get("/api/unbound/service/dnsbl")
        restart_resp = await self._post("/api/unbound/service/restart")
        _LOGGER.debug(
            "[set_unbound_blocklist] set_state: %s, payload: %s, response: %s, dnsbl_resp: %s, restart_resp: %s",
            "On" if set_state else "Off",
            payload,
            response,
            dnsbl_resp,
            restart_resp,
        )
        return (
            isinstance(response, MutableMapping)
            and isinstance(dnsbl_resp, MutableMapping)
            and isinstance(restart_resp, MutableMapping)
            and response.get("result", "failed") == "saved"
            and dnsbl_resp.get("status", "failed").startswith("OK")
            and restart_resp.get("response", "failed") == "OK"
        )

    @_log_errors
    async def enable_unbound_blocklist(self) -> bool:
        """Enable the unbound blocklist."""
        return await self._set_unbound_blocklist(set_state=True)

    @_log_errors
    async def disable_unbound_blocklist(self) -> bool:
        """Disable the unbound blocklist."""
        return await self._set_unbound_blocklist(set_state=False)

    @_log_errors
    async def get_wireguard(self) -> MutableMapping[str, Any]:
        """Get the details of the WireGuard services."""
        data_sources = {
            "summary_raw": "/api/wireguard/service/show",
            "clients_raw": "/api/wireguard/client/get",
            "servers_raw": "/api/wireguard/server/get",
        }
        data = {key: await self._safe_dict_get(path) for key, path in data_sources.items()}

        summary = data["summary_raw"].get("rows", [])
        client_summ = data["clients_raw"].get("client", {}).get("clients", {}).get("client", {})
        server_summ = data["servers_raw"].get("server", {}).get("servers", {}).get("server", {})

        if (
            not isinstance(summary, list)
            or not isinstance(client_summ, MutableMapping)
            or not isinstance(server_summ, MutableMapping)
        ):
            return {}

        servers = {
            uid: await OPNsenseClient._process_wireguard_server(uid, srv)
            for uid, srv in server_summ.items()
            if isinstance(srv, MutableMapping)
        }
        clients = {
            uid: await OPNsenseClient._process_wireguard_client(uid, clnt, servers)
            for uid, clnt in client_summ.items()
            if isinstance(clnt, MutableMapping)
        }

        await OPNsenseClient._update_wireguard_status(summary, servers, clients)

        wireguard = {"servers": servers, "clients": clients}
        _LOGGER.debug("[get_wireguard] wireguard: %s", wireguard)
        return wireguard

    @staticmethod
    async def _process_wireguard_server(
        uid: str, srv: MutableMapping[str, Any]
    ) -> MutableMapping[str, Any]:
        """Process a single WireGuard server entry."""
        return {
            "uuid": uid,
            "name": srv.get("name"),
            "pubkey": srv.get("pubkey"),
            "enabled": srv.get("enabled", "") == "1",
            "interface": f"wg{srv.get('instance', '')}",
            "dns_servers": [srv.get("peer_dns")] if srv.get("peer_dns") else [],
            "tunnel_addresses": [
                addr.get("value")
                for addr in srv.get("tunneladdress", {}).values()
                if addr.get("selected") == 1 and addr.get("value")
            ],
            "clients": [
                {
                    "name": peer.get("value"),
                    "uuid": peer_id,
                    "connected": False,
                }
                for peer_id, peer in srv.get("peers", {}).items()
                if peer.get("selected") == 1 and peer.get("value")
            ],
            "connected_clients": 0,
            "total_bytes_recv": 0,
            "total_bytes_sent": 0,
        }

    @staticmethod
    async def _process_wireguard_client(
        uid: str, clnt: MutableMapping[str, Any], servers: MutableMapping[str, Any]
    ) -> MutableMapping[str, Any]:
        """Process a single WireGuard client entry."""
        return {
            "uuid": uid,
            "name": clnt.get("name"),
            "pubkey": clnt.get("pubkey"),
            "enabled": clnt.get("enabled", "") == "1",
            "tunnel_addresses": [
                addr.get("value")
                for addr in clnt.get("tunneladdress", {}).values()
                if addr.get("selected") == 1 and addr.get("value")
            ],
            "servers": [
                await OPNsenseClient._link_wireguard_client_to_server(srv_id, servers, srv)
                for srv_id, srv in clnt.get("servers", {}).items()
                if srv.get("selected") == 1 and srv.get("value")
            ],
            "connected_servers": 0,
            "total_bytes_recv": 0,
            "total_bytes_sent": 0,
        }

    @staticmethod
    async def _link_wireguard_client_to_server(
        srv_id: str, servers: MutableMapping[str, Any], srv: MutableMapping[str, Any]
    ) -> MutableMapping[str, Any]:
        """Link a WireGuard client to its corresponding server."""
        if srv_id in servers:
            server = servers[srv_id]
            return {
                "name": server.get("name"),
                "uuid": srv_id,
                "connected": False,
                "pubkey": server.get("pubkey"),
                "interface": server.get("interface"),
                "tunnel_addresses": server.get("tunnel_addresses"),
            }
        return {
            "name": srv.get("value"),
            "uuid": srv_id,
            "connected": False,
        }

    @staticmethod
    async def _update_wireguard_status(
        summary: list[MutableMapping[str, Any]],
        servers: MutableMapping[str, Any],
        clients: MutableMapping[str, Any],
    ) -> None:
        """Update WireGuard server and client statuses based on the summary."""
        for entry in summary:
            if entry.get("type") == "interface":
                for server in servers.values():
                    if server.get("pubkey") == entry.get("public-key"):
                        server["status"] = entry.get("status")
            elif entry.get("type") == "peer":
                await OPNsenseClient._update_wireguard_peer_status(entry, servers, clients)

    @staticmethod
    async def _update_wireguard_peer_status(
        entry: MutableMapping[str, Any],
        servers: MutableMapping[str, Any],
        clients: MutableMapping[str, Any],
    ) -> None:
        """Update the WireGuard peer status for clients and servers."""
        pubkey = entry.get("public-key", "-")
        interface = entry.get("if", "-")
        endpoint = entry.get("endpoint", None)
        transfer_rx = int(entry.get("transfer-rx", 0))
        transfer_tx = int(entry.get("transfer-tx", 0))
        latest_handshake = int(entry.get("latest-handshake", 0))
        handshake_time = timestamp_to_datetime(latest_handshake)
        is_connected = wireguard_is_connected(handshake_time)

        # Update servers
        for server in servers.values():
            if server.get("interface") == interface:
                for client in server.get("clients", []):
                    if client.get("pubkey") == pubkey:
                        await OPNsenseClient._update_wireguard_peer_details(
                            peer=client,
                            server_or_client=server,
                            endpoint=endpoint,
                            transfer_rx=transfer_rx,
                            transfer_tx=transfer_tx,
                            handshake_time=handshake_time,
                            is_connected=is_connected,
                            connection_counter_key="connected_clients",
                        )

        # Update clients
        for client in clients.values():
            if client.get("pubkey") == pubkey:
                for server in client.get("servers", []):
                    if server.get("interface") == interface:
                        await OPNsenseClient._update_wireguard_peer_details(
                            peer=server,
                            server_or_client=client,
                            endpoint=endpoint,
                            transfer_rx=transfer_rx,
                            transfer_tx=transfer_tx,
                            handshake_time=handshake_time,
                            is_connected=is_connected,
                            connection_counter_key="connected_servers",
                        )

    @staticmethod
    async def _update_wireguard_peer_details(
        peer: MutableMapping[str, Any],
        server_or_client: MutableMapping[str, Any],
        endpoint: str,
        transfer_rx: int,
        transfer_tx: int,
        handshake_time: datetime | None,
        is_connected: bool,
        connection_counter_key: str,
    ) -> None:
        """Update details of WireGuard peers."""
        if endpoint and endpoint != "(none)":
            peer["endpoint"] = endpoint
        peer["bytes_recv"] = transfer_rx
        peer["bytes_sent"] = transfer_tx
        peer["latest_handshake"] = handshake_time
        peer["connected"] = is_connected

        # Update the parent (server or client) stats
        server_or_client["total_bytes_recv"] = (
            server_or_client.get("total_bytes_recv", 0) + transfer_rx
        )
        server_or_client["total_bytes_sent"] = (
            server_or_client.get("total_bytes_sent", 0) + transfer_tx
        )

        if is_connected:
            server_or_client[connection_counter_key] = (
                server_or_client.get(connection_counter_key, 0) + 1
            )
            # Update the latest handshake time if it's newer
            if (
                server_or_client.get("latest_handshake") is None
                or server_or_client["latest_handshake"] < handshake_time
            ):
                server_or_client["latest_handshake"] = handshake_time

    async def toggle_vpn_instance(self, vpn_type: str, clients_servers: str, uuid: str) -> bool:
        """Toggle the specified VPN instance on or off."""
        if vpn_type == "openvpn":
            success = await self._safe_dict_post(f"/api/openvpn/instances/toggle/{uuid}")
            if not success.get("changed", False):
                return False
            reconfigure = await self._safe_dict_post("/api/openvpn/service/reconfigure")
            return reconfigure.get("result", "") == "ok"
        if vpn_type == "wireguard":
            if clients_servers == "clients":
                endpoint = (
                    f"/api/wireguard/client/toggle_client/{uuid}"
                    if self._use_snake_case
                    else f"/api/wireguard/client/toggleClient/{uuid}"
                )
            elif clients_servers == "servers":
                endpoint = (
                    f"/api/wireguard/server/toggle_server/{uuid}"
                    if self._use_snake_case
                    else f"/api/wireguard/server/toggleServer/{uuid}"
                )
            success = await self._safe_dict_post(endpoint)
            if not success.get("changed", False):
                return False
            reconfigure = await self._safe_dict_post("/api/wireguard/service/reconfigure")
            return reconfigure.get("result", "") == "ok"
        return False

    async def reload_interface(self, if_name: str) -> bool:
        """Reload the specified interface."""
        if self._use_snake_case:
            reload = await self._safe_dict_post(
                f"/api/interfaces/overview/reload_interface/{if_name}"
            )
        else:
            reload = await self._safe_dict_post(
                f"/api/interfaces/overview/reloadInterface/{if_name}"
            )
        return reload.get("message", "").startswith("OK")

    async def get_certificates(self) -> MutableMapping[str, Any]:
        """Return the active encryption certificates."""
        certs_raw = await self._safe_dict_get("/api/trust/cert/search")
        if not isinstance(certs_raw.get("rows", None), list):
            return {}
        certs: MutableMapping[str, Any] = {}
        for cert in certs_raw.get("rows", None):
            if cert.get("descr", None):
                certs[cert.get("descr")] = {
                    "uuid": cert.get("uuid", None),
                    "issuer": cert.get("caref", None),
                    "purpose": cert.get("rfc3280_purpose", None),
                    "in_use": bool(cert.get("in_use", "0") == "1"),
                    "valid_from": timestamp_to_datetime(
                        OPNsenseClient._try_to_int(cert.get("valid_from", None)) or 0
                    ),
                    "valid_to": timestamp_to_datetime(
                        OPNsenseClient._try_to_int(cert.get("valid_to", None)) or 0
                    ),
                }
        _LOGGER.debug("[get_certificates] certs: %s", certs)
        return certs

    async def generate_vouchers(self, data: MutableMapping[str, Any]) -> list:
        """Generate vouchers from the Voucher Server."""
        if data.get("voucher_server", None):
            server = data.get("voucher_server")
        else:
            if self._use_snake_case:
                servers = await self._safe_list_get("/api/captiveportal/voucher/list_providers")
            else:
                servers = await self._safe_list_get("/api/captiveportal/voucher/listProviders")
            if len(servers) == 0:
                raise VoucherServerError("No voucher servers exist")
            if len(servers) != 1:
                raise VoucherServerError(
                    "More than one voucher server. Must specify voucher server name"
                )
            server = servers[0]
        server_slug = quote(str(server))
        payload: MutableMapping[str, Any] = dict(data).copy()
        payload.pop("voucher_server", None)
        if self._use_snake_case:
            voucher_url: str = f"/api/captiveportal/voucher/generate_vouchers/{server_slug}/"
        else:
            voucher_url = f"/api/captiveportal/voucher/generateVouchers/{server_slug}/"
        _LOGGER.debug("[generate_vouchers] url: %s, payload: %s", voucher_url, payload)
        vouchers = await self._safe_list_post(
            voucher_url,
            payload=payload,
        )
        ordered_keys: list = [
            "username",
            "password",
            "vouchergroup",
            "starttime",
            "expirytime",
            "expiry_timestamp",
            "validity_str",
            "validity",
        ]
        for voucher in vouchers:
            if voucher.get("validity", None):
                voucher["validity_str"] = human_friendly_duration(voucher.get("validity"))
            if voucher.get("expirytime", None):
                voucher["expiry_timestamp"] = voucher.get("expirytime")
                voucher["expirytime"] = timestamp_to_datetime(
                    OPNsenseClient._try_to_int(voucher.get("expirytime")) or 0
                )

            rearranged_voucher: MutableMapping[str, Any] = {
                key: voucher[key] for key in ordered_keys if key in voucher
            }
            voucher.clear()
            voucher.update(rearranged_voucher)

        _LOGGER.debug("[generate_vouchers] vouchers: %s", vouchers)
        return vouchers

    async def kill_states(self, ip_addr: str) -> MutableMapping[str, Any]:
        """Kill the active states of the IP address."""
        payload: MutableMapping[str, Any] = {"filter": ip_addr}
        response = await self._safe_dict_post(
            "/api/diagnostics/firewall/kill_states/",
            payload=payload,
        )
        _LOGGER.debug("[kill_states] ip_addr: %s, response: %s", ip_addr, response)
        return {
            "success": bool(response.get("result", "") == "ok"),
            "dropped_states": response.get("dropped_states", 0),
        }

    async def toggle_alias(self, alias: str, toggle_on_off: str) -> bool:
        """Toggle alias on and off."""
        if self._use_snake_case:
            alias_list_resp = await self._safe_dict_get("/api/firewall/alias/search_item")
        else:
            alias_list_resp = await self._safe_dict_get("/api/firewall/alias/searchItem")
        alias_list: list = alias_list_resp.get("rows", [])
        if not isinstance(alias_list, list):
            return False
        uuid: str | None = None
        for item in alias_list:
            if not isinstance(item, MutableMapping):
                continue
            if item.get("name") == alias:
                uuid = item.get("uuid")
                break
        if not uuid:
            return False
        payload: MutableMapping[str, Any] = {}
        if self._use_snake_case:
            url: str = f"/api/firewall/alias/toggle_item/{uuid}"
        else:
            url = f"/api/firewall/alias/toggleItem/{uuid}"
        if toggle_on_off == "on":
            url = f"{url}/1"
        elif toggle_on_off == "off":
            url = f"{url}/0"
        response = await self._safe_dict_post(
            url,
            payload=payload,
        )
        _LOGGER.debug(
            "[toggle_alias] alias: %s, uuid: %s, action: %s, url: %s, response: %s",
            alias,
            uuid,
            toggle_on_off,
            url,
            response,
        )
        if response.get("result") == "failed":
            return False

        set_resp = await self._safe_dict_post("/api/firewall/alias/set")
        if set_resp.get("result") != "saved":
            return False

        reconfigure_resp = await self._safe_dict_post("/api/firewall/alias/reconfigure")
        if reconfigure_resp.get("status") != "ok":
            return False

        return True

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
                self._request_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        _LOGGER.debug("Request queue cleared")
