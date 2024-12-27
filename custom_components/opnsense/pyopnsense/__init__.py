"""pyopnsense to manage OPNsense from HA."""

from abc import ABC
import asyncio
from collections.abc import MutableMapping
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
from typing import Any, Callable
from urllib.parse import quote, quote_plus, urlparse
import xmlrpc.client

import aiohttp
import awesomeversion
from dateutil.parser import UnknownTimezoneWarning, parse

from .const import AMBIGUOUS_TZINFOS

# value to set as the socket timeout
DEFAULT_TIMEOUT = 60

_LOGGER: logging.Logger = logging.getLogger(__name__)


def _log_errors(func: Callable):
    async def inner(self, *args, **kwargs):
        try:
            return await func(self, *args, **kwargs)
        except asyncio.CancelledError:
            raise
        except (TimeoutError, aiohttp.ServerTimeoutError) as e:
            _LOGGER.warning(
                "Timeout Error in %s. Will retry. %s", func.__name__.strip("_"), e
            )
            if self._initial:
                raise
        except Exception as e:
            redacted_message = re.sub(r"(\w+):(\w+)@", "<redacted>:<redacted>@", str(e))
            _LOGGER.error(
                "Error in %s. %s: %s\n%s",
                func.__name__.strip("_"),
                e.__class__.__qualname__,
                redacted_message,
                "".join(traceback.format_tb(e.__traceback__)),
            )
            if self._initial:
                raise

    return inner


def _xmlrpc_timeout(func: Callable):
    async def inner(self, *args, **kwargs):
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


def wireguard_is_connected(past_time: datetime) -> bool:
    """Return if Wireguard client is still connected."""
    return datetime.now().astimezone() - past_time <= timedelta(minutes=3)


def human_friendly_duration(seconds) -> str:
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


def get_ip_key(item) -> tuple:
    """Use to sort the DHCP Lease IPs."""
    address = item.get("address", None)

    if not address:
        # If the address is empty, place it at the end
        return (3, "")
    try:
        ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(
            address
        )
    except ValueError:
        return (2, "")
    else:
        # Sort by IP version (IPv4 first, IPv6 second), then by numerical value
        return (0 if ip_obj.version == 4 else 1, ip_obj)


def dict_get(data: MutableMapping[str, Any], path: str, default=None):
    """Parse the path to get the desired value out of the data."""
    pathList = re.split(r"\.", path, flags=re.IGNORECASE)
    result = data
    for key in pathList:
        if key.isnumeric():
            key = int(key)
        if isinstance(result, (MutableMapping, list)) and key in result:
            result = result[key]
        else:
            result = default
            break

    return result


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
        self._xmlrpc_url: str = f"{parts.scheme}://{quote_plus(username)}:{quote_plus(password)}@{parts.netloc}"
        self._scheme: str = parts.scheme
        self._session: aiohttp.ClientSession = session
        self._initial = initial
        self._firmware_version: str | None = None
        self._xmlrpc_query_count = 0
        self._rest_api_query_count = 0
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

    # @_xmlrpc_timeout
    async def _get_config_section(self, section) -> MutableMapping[str, Any]:
        config: MutableMapping[str, Any] = await self.get_config()
        if config is None or not isinstance(config, MutableMapping):
            _LOGGER.error("Invalid data returned from get_config_section")
            return {}
        return config.get(section, {})

    @_xmlrpc_timeout
    async def _restore_config_section(self, section_name, data):
        params = {section_name: data}
        proxy_method = partial(
            self._get_proxy().opnsense.restore_config_section, params
        )
        return await self._loop.run_in_executor(None, proxy_method)

    @_xmlrpc_timeout
    async def _exec_php(self, script) -> MutableMapping[str, Any]:
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
            calling_function = (
                stack[1].function.strip("_") if len(stack) > 1 else "Unknown"
            )
            _LOGGER.error(
                "Invalid data returned from exec_php for %s. %s: %s. Called from %s",
                calling_function,
                e.__class__.__qualname__,
                e,
                calling_function,
            )
        except xmlrpc.client.Fault as e:
            stack = inspect.stack()
            calling_function = (
                stack[1].function.strip("_") if len(stack) > 1 else "Unknown"
            )
            _LOGGER.error(
                "Error running exec_php script for %s. %s: %s. Ensure the 'os-homeassistant-maxit' plugin has been installed on OPNsense",
                calling_function,
                e.__class__.__qualname__,
                e,
            )
        except socket.gaierror as e:
            stack = inspect.stack()
            calling_function = (
                stack[1].function.strip("_") if len(stack) > 1 else "Unknown"
            )
            _LOGGER.warning(
                "Connection Error running exec_php script for %s. %s: %s. Will retry",
                calling_function,
                e.__class__.__qualname__,
                e,
            )
        except ssl.SSLError as e:
            stack = inspect.stack()
            calling_function = (
                stack[1].function.strip("_") if len(stack) > 1 else "Unknown"
            )
            _LOGGER.warning(
                "SSL Connection Error running exec_php script for %s. %s: %s. Will retry",
                calling_function,
                e.__class__.__qualname__,
                e,
            )
        return {}

    @_log_errors
    async def get_host_firmware_version(self) -> None | str:
        """Return the OPNsense Firmware version."""
        firmware_info = await self._get("/api/core/firmware/status")
        if not isinstance(firmware_info, MutableMapping):
            return None
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

    async def is_plugin_installed(self) -> bool:
        """Retun whether OPNsense plugin is installed or not."""
        firmware_info = await self._get("/api/core/firmware/info")
        if not isinstance(firmware_info, MutableMapping) or not isinstance(
            firmware_info.get("package"), list
        ):
            return False
        for pkg in firmware_info.get("package", []):
            if pkg.get("name") == "os-homeassistant-maxit":
                return True
        return False

    async def _get_from_stream(
        self, path: str
    ) -> MutableMapping[str, Any] | list | None:
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

                        if "\n\n" in buffer:
                            message, buffer = buffer.split("\n\n", 1)
                            lines = message.splitlines()

                            for line in lines:
                                if line.startswith("data:"):
                                    message_count += 1
                                    if message_count == 2:
                                        response_str: str = line[len("data:") :].strip()
                                        response_json: (
                                            MutableMapping[str, Any] | list
                                        ) = json.loads(response_str)

                                        # _LOGGER.debug(f"[get_from_stream] response_json ({type(response_json).__name__}): {response_json}")
                                        return response_json  # Exit after processing the second message
                else:
                    if response.status == 403:
                        stack = inspect.stack()
                        calling_function = (
                            stack[1].function.strip("_")
                            if len(stack) > 1
                            else "Unknown"
                        )
                        _LOGGER.error(
                            "Permission Error in %s. Path: %s. Ensure the OPNsense user connected to HA has full Admin access",
                            calling_function,
                            url,
                        )
                    else:
                        stack = inspect.stack()
                        calling_function = (
                            stack[1].function.strip("_")
                            if len(stack) > 1
                            else "Unknown"
                        )
                        _LOGGER.error(
                            "Error in %s. Path: %s. Response %s: %s",
                            calling_function,
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
            _LOGGER.error("Client error. %s: %s", e.__class__.__qualname__, e)
            if self._initial:
                raise

        return None

    async def _get(self, path: str) -> MutableMapping[str, Any] | list | None:
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
                    response_json: (
                        MutableMapping[str, Any] | list
                    ) = await response.json(content_type=None)
                    return response_json
                if response.status == 403:
                    stack = inspect.stack()
                    calling_function = (
                        stack[1].function.strip("_") if len(stack) > 1 else "Unknown"
                    )
                    _LOGGER.error(
                        "Permission Error in %s. Path: %s. Ensure the OPNsense user connected to HA has full Admin access",
                        calling_function,
                        url,
                    )
                else:
                    stack = inspect.stack()
                    calling_function = (
                        stack[1].function.strip("_") if len(stack) > 1 else "Unknown"
                    )
                    _LOGGER.error(
                        "Error in %s. Path: %s. Response %s: %s",
                        calling_function,
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
            _LOGGER.error("Client error. %s: %s", e.__class__.__qualname__, e)
            if self._initial:
                raise

        return None

    async def _post(
        self, path: str, payload=None
    ) -> MutableMapping[str, Any] | list | None:
        # /api/<module>/<controller>/<command>/[<param1>/[<param2>/...]]
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
                _LOGGER.debug(
                    "[post] Response %s: %s", response.status, response.reason
                )
                if response.ok:
                    response_json: (
                        MutableMapping[str, Any] | list
                    ) = await response.json(content_type=None)
                    return response_json
                if response.status == 403:
                    stack = inspect.stack()
                    calling_function = (
                        stack[1].function.strip("_") if len(stack) > 1 else "Unknown"
                    )
                    _LOGGER.error(
                        "Permission Error in %s. Path: %s. Ensure the OPNsense user connected to HA has full Admin access",
                        calling_function,
                        url,
                    )
                else:
                    stack = inspect.stack()
                    calling_function = (
                        stack[1].function.strip("_") if len(stack) > 1 else "Unknown"
                    )
                    _LOGGER.error(
                        "Error in %s. Path: %s. Response %s: %s",
                        calling_function,
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
            _LOGGER.error("Client error. %s: %s", e.__class__.__qualname__, e)
            if self._initial:
                raise

        return None

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
        instances = await self._get("/api/interfaces/overview/export")
        if not isinstance(instances, list):
            return None

        mac_addresses = [
            d.get("macaddr_hw")
            for d in instances
            if d.get("is_physical") and "macaddr_hw" in d
        ]

        unique_mac_addresses: list = sorted(set(mac_addresses))
        device_unique_id: str | None = (
            unique_mac_addresses[0] if unique_mac_addresses else None
        )
        if device_unique_id:
            device_unique_id_fmt = device_unique_id.replace(":", "_").strip()
            _LOGGER.debug(
                "[get_device_unique_id] device_unique_id: %s", device_unique_id_fmt
            )
            return device_unique_id_fmt
        _LOGGER.debug("[get_device_unique_id] device_unique_id: None")
        return None

    @_log_errors
    async def get_system_info(self) -> MutableMapping[str, Any]:
        """Return the system info from OPNsense."""
        # TODO: add bios details here
        if not self._firmware_version:
            await self.get_host_firmware_version()
        try:
            if awesomeversion.AwesomeVersion(
                self._firmware_version
            ) < awesomeversion.AwesomeVersion("24.7"):
                _LOGGER.info("Using legacy get_system_info method for OPNsense < 24.7")
                return await self._get_system_info_legacy()
        except awesomeversion.exceptions.AwesomeVersionCompareException:
            pass
        system_info: MutableMapping[str, Any] = {}
        response = await self._get("/api/diagnostics/system/systemInformation")
        if isinstance(response, MutableMapping):
            system_info["name"] = response.get("name", None)
        return system_info

    @_log_errors
    async def _get_system_info_legacy(self) -> MutableMapping[str, Any]:
        # TODO: add bios details here
        script: str = r"""
global $config;

$toreturn = [
  "hostname" => $config["system"]["hostname"],
  "domain" => $config["system"]["domain"],
];
"""
        response: MutableMapping[str, Any] = await self._exec_php(script)
        if not isinstance(response, MutableMapping):
            return {}
        response["name"] = (
            f"{response.pop('hostname', '')}.{response.pop('domain', '')}"
        )
        return response

    @_log_errors
    async def get_firmware_update_info(self):
        """Get the details of available firmware updates."""
        refresh_triggered = False
        refresh_interval = 2 * 60 * 60  # 2 hours

        status = None
        upgradestatus = None

        # GET /api/core/firmware/status
        status = await self._get("/api/core/firmware/status")
        # print(status)

        # if error or too old trigger check (only if check is not already in progress)
        # {'status_msg': 'Firmware status check was aborted internally. Please try again.', 'status': 'error'}
        # error could be because data has not been refreshed at all OR an upgrade is currently in progress
        if (
            not isinstance(status, MutableMapping)
            or status.get("status", None) == "error"
            or "last_check" not in status
            or not isinstance(dict_get(status, "product.product_check"), dict)
            or not dict_get(status, "product.product_check")
        ):
            await self._post("/api/core/firmware/check")
            refresh_triggered = True
        elif "last_check" in status:
            # "last_check": "Wed Dec 22 16:56:20 UTC 2021"
            # "last_check": "Mon Jan 16 00:08:28 CET 2023"
            # "last_check": "Sun Jan 15 22:05:55 UTC 2023"
            # format = "%a %b %d %H:%M:%S %Z %Y"
            try:
                last_check: datetime = parse(
                    status.get("last_check", 0), tzinfos=AMBIGUOUS_TZINFOS
                )
                if last_check.tzinfo is None:
                    last_check = last_check.replace(
                        tzinfo=timezone(
                            datetime.now().astimezone().utcoffset() or timedelta()
                        )
                    )

                last_check_timestamp: float = last_check.timestamp()

            except (ValueError, TypeError, UnknownTimezoneWarning):
                last_check_timestamp = 0

            stale: bool = (
                datetime.now().astimezone().timestamp() - last_check_timestamp
            ) > refresh_interval
            if stale:
                upgradestatus = await self._get("/api/core/firmware/upgradestatus")
                # print(upgradestatus)
                if isinstance(upgradestatus, MutableMapping):
                    # status = running (package refresh in progress OR upgrade in progress)
                    # status = done (refresh/upgrade done)
                    if upgradestatus.get("status", None) == "done":
                        # tigger repo update
                        # should this be /api/core/firmware/upgrade
                        # check = await self._post("/api/core/firmware/check")
                        # print(check)
                        refresh_triggered = True
                    else:
                        # print("upgrade already running")
                        pass

        wait_for_refresh = False
        if refresh_triggered and wait_for_refresh:
            # print("refresh triggered, waiting for it to finish")
            pass

        return status

    @_log_errors
    async def upgrade_firmware(self, type="update"):
        """Trigger a firmware upgrade."""
        # minor updates of the same opnsense version
        if type == "update":
            # can watch the progress on the 'Updates' tab in the UI
            return await self._post("/api/core/firmware/update")

        # major updates to a new opnsense version
        if type == "upgrade":
            # can watch the progress on the 'Updates' tab in the UI
            return await self._post("/api/core/firmware/upgrade")
        return None

    @_log_errors
    async def upgrade_status(self):
        """Return the status of the firmware upgrade."""
        return await self._post("/api/core/firmware/upgradestatus")

    @_log_errors
    async def firmware_changelog(self, version):
        """Return the changelog for the firmware upgrade."""
        return await self._post("/api/core/firmware/changelog/" + version)

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
    async def enable_filter_rule_by_created_time(self, created_time) -> None:
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
    async def disable_filter_rule_by_created_time(self, created_time) -> None:
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
    async def enable_nat_port_forward_rule_by_created_time(self, created_time) -> None:
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
    async def disable_nat_port_forward_rule_by_created_time(self, created_time) -> None:
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
    async def enable_nat_outbound_rule_by_created_time(self, created_time) -> None:
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
    async def disable_nat_outbound_rule_by_created_time(self, created_time) -> None:
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
    async def get_arp_table(self, resolve_hostnames=False) -> list:
        """Return the active ARP table."""
        # [{'hostname': '?', 'ip-address': '<ip>', 'mac-address': '<mac>', 'interface': 'em0', 'expires': 1199, 'type': 'ethernet'}, ...]
        request_body: MutableMapping[str, Any] = {"resolve": "yes"}
        arp_table_info = await self._post(
            "/api/diagnostics/interface/search_arp", payload=request_body
        )
        if not isinstance(arp_table_info, MutableMapping):
            return []
        # _LOGGER.debug(f"[get_arp_table] arp_table_info: {arp_table_info}")
        arp_table: list = arp_table_info.get("rows", [])
        # _LOGGER.debug(f"[get_arp_table] arp_table: {arp_table}")
        return arp_table

    @_log_errors
    async def get_services(self) -> list:
        """Get the list of OPNsense services."""
        response = await self._get("/api/core/service/search")
        if not isinstance(response, MutableMapping):
            _LOGGER.error("Invalid data returned from get_services")
            return []
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
            if (
                svc.get("name", None) == service or svc.get("id", None) == service
            ) and svc.get("status", False):
                return True
        return False

    async def _manage_service(self, action: str, service: str) -> bool:
        if not service:
            return False
        api_addr: str = f"/api/core/service/{action}/{service}"
        response = await self._post(api_addr)
        _LOGGER.debug(
            "[%s_service] service: %s, response: %s", action, service, response
        )
        return (
            isinstance(response, MutableMapping)
            and response.get("result", "failed") == "ok"
        )

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
        )

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
        sorted_leases: MutableMapping[str, Any] = {
            key: leases[key] for key in sorted(leases)
        }
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
        response = await self._get("/api/kea/dhcpv4/get")
        if not isinstance(response, MutableMapping):
            return {}
        lease_interfaces: MutableMapping[str, Any] = {}
        general: MutableMapping[str, Any] = response.get("dhcpv4", {}).get(
            "general", {}
        )
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
        response = await self._get("/api/kea/leases4/search")
        if not isinstance(response, MutableMapping) or not isinstance(
            response.get("rows", None), list
        ):
            return []
        res_resp = await self._get("/api/kea/dhcpv4/searchReservation")
        if not isinstance(res_resp, MutableMapping) or not isinstance(
            res_resp.get("rows", None), list
        ):
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
                and reservations[lease_info.get("hwaddr")]
                == lease_info.get("address", None)
            ):
                lease["type"] = "static"
            else:
                lease["type"] = "dynamic"
            lease["mac"] = lease_info.get("hwaddr", None)
            if OPNsenseClient._try_to_int(lease_info.get("expire", None)):
                lease["expires"] = datetime.fromtimestamp(
                    OPNsenseClient._try_to_int(lease_info.get("expire", None)) or 0,
                    tz=timezone(datetime.now().astimezone().utcoffset() or timedelta()),
                )
                if lease["expires"] < datetime.now().astimezone():
                    continue
            else:
                lease["expires"] = lease_info.get("expire", None)
            leases.append(lease)
        # _LOGGER.debug(f"[get_kea_dhcpv4_leases] leases: {leases}")
        return leases

    async def _get_isc_dhcpv4_leases(self) -> list:
        """Return IPv4 DHCP Leases by ISC."""
        response = await self._get("/api/dhcpv4/leases/searchLease")
        if not isinstance(response, MutableMapping):
            return []
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
                dt: datetime = datetime.strptime(
                    lease_info.get("ends", None), "%Y/%m/%d %H:%M:%S"
                )
                lease["expires"] = dt.replace(
                    tzinfo=timezone(
                        datetime.now().astimezone().utcoffset() or timedelta()
                    )
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
        response = await self._get("/api/dhcpv6/leases/searchLease")
        if not isinstance(response, MutableMapping):
            return []
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
                dt: datetime = datetime.strptime(
                    lease_info.get("ends", None), "%Y/%m/%d %H:%M:%S"
                )
                lease["expires"] = dt.replace(
                    tzinfo=timezone(
                        datetime.now().astimezone().utcoffset() or timedelta()
                    )
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
        response = await self._get("/api/diagnostics/interface/get_vip_status")
        if not isinstance(response, MutableMapping):
            _LOGGER.error("Invalid data returned from get_carp_status")
            return False
        # _LOGGER.debug(f"[get_carp_status] response: {response}")
        return response.get("carp", {}).get("allow", "0") == "1"

    @_log_errors
    async def get_carp_interfaces(self) -> list:
        """Return the interfaces used by Carp."""
        vip_settings_raw = await self._get("/api/interfaces/vip_settings/get")
        if not isinstance(vip_settings_raw, MutableMapping) or not isinstance(
            vip_settings_raw.get("rows", None), list
        ):
            vip_settings: list = []
        else:
            vip_settings = vip_settings_raw.get("rows", [])
        # _LOGGER.debug(f"[get_carp_interfaces] vip_settings: {vip_settings}")

        vip_status_raw = await self._get("/api/diagnostics/interface/get_vip_status")
        if not isinstance(vip_status_raw, MutableMapping) or not isinstance(
            vip_status_raw.get("rows", None), list
        ):
            vip_status: list = []
        else:
            vip_status = vip_status_raw.get("rows", [])
        # _LOGGER.debug(f"[get_carp_interfaces] vip_status: {vip_status}")
        carp = []
        for vip in vip_settings:
            if vip.get("mode", "").lower() != "carp":
                continue

            for status in vip_status:
                if (
                    vip.get("interface", "").lower()
                    == status.get("interface", "_").lower()
                ):
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
        response = await self._post("/api/core/system/reboot")
        _LOGGER.debug("[system_reboot] response: %s", response)
        if isinstance(response, MutableMapping) and response.get("status", "") == "ok":
            return True
        return False

    @_log_errors
    async def system_halt(self) -> None:
        """Shutdown OPNsense."""
        response = await self._post("/api/core/system/halt")
        _LOGGER.debug("[system_halt] response: %s", response)
        if isinstance(response, MutableMapping) and response.get("status", "") == "ok":
            return
        return

    @_log_errors
    async def send_wol(self, interface, mac) -> bool:
        """Send a wake on lan packet to the specified MAC address."""
        payload: MutableMapping[str, Any] = {
            "wake": {"interface": interface, "mac": mac}
        }
        _LOGGER.debug("[send_wol] payload: %s", payload)
        response = await self._post("/api/wol/wol/set", payload)
        _LOGGER.debug("[send_wol] response: %s", response)
        if isinstance(response, MutableMapping) and response.get("status", "") == "ok":
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
        if not self._firmware_version:
            await self.get_host_firmware_version()
        try:
            if awesomeversion.AwesomeVersion(
                self._firmware_version
            ) < awesomeversion.AwesomeVersion("24.7"):
                _LOGGER.info("Using legacy get_telemetry method for OPNsense < 24.7")
                return await self._get_telemetry_legacy()
        except awesomeversion.exceptions.AwesomeVersionCompareException:
            pass
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
        interface_info = await self._get("/api/interfaces/overview/export")
        # _LOGGER.debug(f"[get_interfaces] interface_info: {interface_info}")
        if not isinstance(interface_info, list) or not len(interface_info) > 0:
            return {}
        interfaces: MutableMapping[str, Any] = {}
        for ifinfo in interface_info:
            interface: MutableMapping[str, Any] = {}
            if (
                not isinstance(ifinfo, MutableMapping)
                or ifinfo.get("identifier", "") == ""
            ):
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
            if (
                ifinfo.get("macaddr", None)
                and ifinfo.get("macaddr", None) != "00:00:00:00:00:00"
            ):
                interface["mac"] = ifinfo.get("macaddr", None)
            interface["enabled"] = ifinfo.get("enabled", None)
            interface["vlan_tag"] = ifinfo.get("vlan_tag", None)
            interfaces[ifinfo.get("identifier", "")] = interface
        # _LOGGER.debug(f"[get_interfaces] interfaces: {interfaces}")
        return interfaces

    @_log_errors
    async def _get_telemetry_mbuf(self) -> MutableMapping[str, Any]:
        mbuf_info = await self._post("/api/diagnostics/system/system_mbuf")
        # _LOGGER.debug(f"[get_telemetry_mbuf] mbuf_info: {mbuf_info}")
        if not isinstance(mbuf_info, MutableMapping):
            return {}
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
        pfstate_info = await self._post("/api/diagnostics/firewall/pf_states")
        # _LOGGER.debug(f"[get_telemetry_pfstate] pfstate_info: {pfstate_info}")
        if not isinstance(pfstate_info, MutableMapping):
            return {}
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
        memory_info = await self._post("/api/diagnostics/system/systemResources")
        # _LOGGER.debug(f"[get_telemetry_memory] memory_info: {memory_info}")
        if not isinstance(memory_info, MutableMapping):
            return {}
        memory: MutableMapping[str, Any] = {}
        memory["physmem"] = OPNsenseClient._try_to_int(
            memory_info.get("memory", {}).get("total", None)
        )
        memory["used"] = OPNsenseClient._try_to_int(
            memory_info.get("memory", {}).get("used", None)
        )
        memory["used_percent"] = (
            round(memory["used"] / memory["physmem"] * 100)
            if isinstance(memory["used"], int)
            and isinstance(memory["physmem"], int)
            and memory["physmem"] > 0
            else None
        )
        swap_info = await self._post("/api/diagnostics/system/system_swap")
        if (
            not isinstance(swap_info, MutableMapping)
            or not isinstance(swap_info.get("swap", None), list)
            or not len(swap_info.get("swap", [])) > 0
            or not isinstance(swap_info.get("swap", [])[0], MutableMapping)
        ):
            return memory
        # _LOGGER.debug(f"[get_telemetry_memory] swap_info: {swap_info}")
        memory["swap_total"] = OPNsenseClient._try_to_int(
            swap_info.get("swap", [])[0].get("total", None)
        )
        memory["swap_reserved"] = OPNsenseClient._try_to_int(
            swap_info["swap"][0].get("used", None)
        )
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
        time_info = await self._post("/api/diagnostics/system/systemTime")
        # _LOGGER.debug(f"[get_telemetry_system] time_info: {time_info}")
        if not isinstance(time_info, MutableMapping):
            return {}
        system: MutableMapping[str, Any] = {}
        pattern = re.compile(r"^(?:(\d+)\s+days?,\s+)?(\d{2}):(\d{2}):(\d{2})$")
        match = pattern.match(time_info.get("uptime", ""))
        if match:
            days_str, hours_str, minutes_str, seconds_str = match.groups()
            days = OPNsenseClient._try_to_int(days_str, 0) or 0
            hours = OPNsenseClient._try_to_int(hours_str, 0) or 0
            minutes = OPNsenseClient._try_to_int(minutes_str, 0) or 0
            seconds = OPNsenseClient._try_to_int(seconds_str, 0) or 0
            system["uptime"] = days * 86400 + hours * 3600 + minutes * 60 + seconds

            boottime: datetime = datetime.now() - timedelta(seconds=system["uptime"])
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
        cputype_info = await self._post("/api/diagnostics/cpu_usage/getCPUType")
        # _LOGGER.debug(f"[get_telemetry_cpu] cputype_info: {cputype_info}")
        if not isinstance(cputype_info, list) or not len(cputype_info) > 0:
            return {}
        cpu: MutableMapping[str, Any] = {}
        cores_match = re.search(r"\((\d+) cores", cputype_info[0])
        cpu["count"] = (
            OPNsenseClient._try_to_int(cores_match.group(1)) if cores_match else 0
        )

        cpustream_info = await self._get_from_stream(
            "/api/diagnostics/cpu_usage/stream"
        )
        # {"total":29,"user":2,"nice":0,"sys":27,"intr":0,"idle":70}
        # _LOGGER.debug(f"[get_telemetry_cpu] cpustream_info: {cpustream_info}")
        if not isinstance(cpustream_info, MutableMapping):
            return cpu
        cpu["usage_total"] = OPNsenseClient._try_to_int(
            cpustream_info.get("total", None)
        )
        cpu["usage_user"] = OPNsenseClient._try_to_int(cpustream_info.get("user", None))
        cpu["usage_nice"] = OPNsenseClient._try_to_int(cpustream_info.get("nice", None))
        cpu["usage_system"] = OPNsenseClient._try_to_int(
            cpustream_info.get("sys", None)
        )
        cpu["usage_interrupt"] = OPNsenseClient._try_to_int(
            cpustream_info.get("intr", None)
        )
        cpu["usage_idle"] = OPNsenseClient._try_to_int(cpustream_info.get("idle", None))
        # _LOGGER.debug(f"[get_telemetry_cpu] cpu: {cpu}")
        return cpu

    @_log_errors
    async def _get_telemetry_filesystems(self) -> list:
        filesystems_info = await self._post("/api/diagnostics/system/systemDisk")
        if not isinstance(filesystems_info, MutableMapping):
            return []
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

        sessions_info = await self._get("/api/openvpn/service/searchSessions")

        routes_info = await self._get("/api/openvpn/service/searchRoutes")

        providers_info = await self._get("/api/openvpn/export/providers")

        instances_info = await self._get("/api/openvpn/instances/search")
        # _LOGGER.debug(f"[get_openvpn] sessions_info: {sessions_info}")
        # _LOGGER.debug(f"[get_openvpn] routes_info: {routes_info}")
        # _LOGGER.debug(f"[get_openvpn] providers_info: {providers_info}")
        # _LOGGER.debug(f"[get_openvpn] instances_info: {instances_info}")
        if not isinstance(sessions_info, MutableMapping):
            sessions_info = {}
        if not isinstance(routes_info, MutableMapping):
            routes_info = {}
        if not isinstance(providers_info, MutableMapping):
            providers_info = {}
        if not isinstance(instances_info, MutableMapping):
            instances_info = {}

        openvpn: MutableMapping[str, Any] = {}
        openvpn["servers"] = {}
        openvpn["clients"] = {}

        # Servers
        for instance in instances_info.get("rows", []):
            if (
                not isinstance(instance, MutableMapping)
                or instance.get("role", "").lower() != "server"
            ):
                continue
            if (
                instance.get("uuid", None)
                and instance.get("uuid", None) not in openvpn["servers"]
            ):
                openvpn["servers"][instance.get("uuid")] = {
                    "uuid": instance.get("uuid"),
                    "name": instance.get("description"),
                    "enabled": bool(instance.get("enabled", "0") == "1"),
                    "dev_type": instance.get("dev_type", None),
                    "clients": [],
                }

        for uuid, vpn_info in providers_info.items():
            if not uuid or not isinstance(vpn_info, MutableMapping):
                continue
            if uuid not in openvpn["servers"]:
                openvpn["servers"][uuid] = {
                    "uuid": uuid,
                    "name": vpn_info.get("name"),
                    "clients": [],
                }
            if vpn_info.get("hostname", None) and vpn_info.get("local_port", None):
                openvpn["servers"][uuid]["endpoint"] = (
                    f"{vpn_info.get('hostname')}:{vpn_info.get('local_port')}"
                )

        for session in sessions_info.get("rows", []):
            if session.get("type", None) != "server":
                continue
            server_id = str(session["id"]).split("_", maxsplit=1)[0]

            if server_id not in openvpn["servers"]:
                openvpn["servers"][server_id] = {
                    "uuid": server_id,
                    "clients": [],
                }
            openvpn["servers"][server_id]["name"] = session.get("description", "")

            if not session.get("is_client", False):
                if openvpn["servers"][server_id].get("enabled", True) is False:
                    openvpn["servers"][server_id].update({"status": "disabled"})
                elif session.get("status", None) in {"connected", "ok"}:
                    openvpn["servers"][server_id].update({"status": "up"})
                elif session.get("status", None) == "failed":
                    openvpn["servers"][server_id].update({"status": "failed"})
                elif isinstance(session.get("status", None), str):
                    openvpn["servers"][server_id].update(
                        {"status": session.get("status")}
                    )
                else:
                    openvpn["servers"][server_id].update({"status": "down"})
            else:
                openvpn["servers"][server_id].update(
                    {
                        "status": "up",
                        "latest_handshake": datetime.fromtimestamp(
                            int(session.get("connected_since__time_t_")),
                            tz=timezone(
                                datetime.now().astimezone().utcoffset() or timedelta()
                            ),
                        ),
                        "total_bytes_recv": OPNsenseClient._try_to_int(
                            session.get("bytes_received", 0), 0
                        ),
                        "total_bytes_sent": OPNsenseClient._try_to_int(
                            session.get("bytes_sent", 0), 0
                        ),
                    }
                )

        for route in routes_info.get("rows", []):
            if (
                not isinstance(route, MutableMapping)
                or route.get("id", None) is None
                or route.get("id") not in openvpn.get("servers", {})
            ):
                continue
            openvpn["servers"][route.get("id")]["clients"].append(
                {
                    "name": route.get("common_name", None),
                    "endpoint": route.get("real_address", None),
                    "tunnel_addresses": [route.get("virtual_address")],
                    "latest_handshake": datetime.fromtimestamp(
                        int(route.get("last_ref__time_t_", 0)),
                        tz=timezone(
                            datetime.now().astimezone().utcoffset() or timedelta()
                        ),
                    ),
                }
            )

        for uuid, server in openvpn["servers"].items():
            if "total_bytes_sent" not in server:
                server["total_bytes_sent"] = 0
            if "total_bytes_recv" not in server:
                server["total_bytes_recv"] = 0
            server["connected_clients"] = len(server.get("clients", []))
            details_info = await self._get(f"/api/openvpn/instances/get/{uuid}")
            if isinstance(details_info, MutableMapping) and isinstance(
                details_info.get("instance", None), MutableMapping
            ):
                details = details_info.get("instance", {})
                if details.get("server", None):
                    server["tunnel_addresses"] = [details.get("server")]
                server["dns_servers"] = []
                for dns in details.get("dns_servers", {}).values():
                    if dns.get("selected", 0) == 1 and dns.get("value", None):
                        server["dns_servers"].append(dns.get("value"))

        # Clients
        for instance in instances_info.get("rows", []):
            if (
                not isinstance(instance, MutableMapping)
                or instance.get("role", "").lower() != "client"
            ):
                continue
            if instance.get("uuid", None):
                openvpn["clients"][instance.get("uuid")] = {
                    "name": instance.get("description", None),
                    "uuid": instance.get("uuid", None),
                    "enabled": bool(instance.get("enabled", "0") == "1"),
                }

        _LOGGER.debug("[get_openvpn] openvpn: %s", openvpn)
        return openvpn

    @_log_errors
    async def get_gateways(self) -> MutableMapping[str, Any]:
        """Return OPNsense Gateway details."""
        gateways_info = await self._get("/api/routes/gateway/status")
        # _LOGGER.debug(f"[get_gateways] gateways_info: {gateways_info}")
        if not isinstance(gateways_info, MutableMapping):
            return {}
        gateways: MutableMapping[str, Any] = {}
        for gw_info in gateways_info.get("items", []):
            if isinstance(gw_info, MutableMapping) and "name" in gw_info:
                gateways[gw_info["name"]] = gw_info
        for gateway in gateways.values():
            gateway["status"] = gateway.pop(
                "status_translated", gateway.get("status", "")
            ).lower()
        # _LOGGER.debug(f"[get_gateways] gateways: {gateways}")
        return gateways

    @_log_errors
    async def _get_telemetry_temps(self) -> MutableMapping[str, Any]:
        temps_info = await self._get("/api/diagnostics/system/systemTemperature")
        # _LOGGER.debug(f"[get_telemetry_temps] temps_info: {temps_info}")
        if not isinstance(temps_info, list) or not len(temps_info) > 0:
            return {}
        temps: MutableMapping[str, Any] = {}
        for i, temp_info in enumerate(temps_info):
            temp: MutableMapping[str, Any] = {}
            temp["temperature"] = OPNsenseClient._try_to_float(
                temp_info.get("temperature", 0), 0
            )
            temp["name"] = (
                f"{temp_info.get('type_translated', 'Num')} {temp_info.get('device_seq', i)}"
            )
            temp["device_id"] = temp_info.get("device", str(i))
            temps[temp_info.get("device", str(i)).replace(".", "_")] = temp
        # _LOGGER.debug(f"[get_telemetry_temps] temps: {temps}")
        return temps

    @_log_errors
    async def _get_telemetry_legacy(self) -> MutableMapping[str, Any]:
        script: str = r"""
require_once '/usr/local/www/widgets/api/plugins/system.inc';

$system_api_data = system_api();

// OPNsense 23.1.1: replaced single exec_command() with new shell_safe() wrapper
if (function_exists('exec_command')) {
    $boottime = exec_command("sysctl kern.boottime");
} else {
    $boottime = shell_safe("sysctl kern.boottime");
}

// kern.boottime: { sec = 1634047554, usec = 237429 } Tue Oct 12 08:05:54 2021
preg_match("/sec = [0-9]*/", $boottime, $matches);
$boottime = $matches[0];
$boottime = explode("=", $boottime)[1];
$boottime = (int) trim($boottime);

$toreturn = [
    "pfstate" => [
        "used" => (int) $system_api_data["kernel"]["pf"]["states"],
        "total" => (int) $system_api_data["kernel"]["pf"]["maxstates"],
        "used_percent" => round(floatval($system_api_data["kernel"]["pf"]["states"] / $system_api_data["kernel"]["pf"]["maxstates"]) * 100, 0),
    ],

    "mbuf" => [
        "used" => (int) $system_api_data["kernel"]["mbuf"]["total"],
        "total" => (int) $system_api_data["kernel"]["mbuf"]["max"],
        "used_percent" =>  round(floatval($system_api_data["kernel"]["mbuf"]["total"] / $system_api_data["kernel"]["mbuf"]["max"]) * 100, 0),
    ],

    "memory" => [
        "swap_used_percent" => ($system_api_data["disk"]["swap"][0]["total"] > 0) ? round(floatval($system_api_data["disk"]["swap"][0]["used"] / $system_api_data["disk"]["swap"][0]["total"]) * 100, 0) : 0,
        "used_percent" => round(floatval($system_api_data["kernel"]["memory"]["used"] / $system_api_data["kernel"]["memory"]["total"]) * 100, 0),
        "physmem" => (int) $system_api_data["kernel"]["memory"]["total"],
        "used" => (int) $system_api_data["kernel"]["memory"]["used"],
        "swap_total" => (int) $system_api_data["disk"]["swap"][0]["total"],
        "swap_reserved" => (int) $system_api_data["disk"]["swap"][0]["used"],
    ],

    "system" => [
        "boottime" => $boottime,
        "uptime" => (int) $system_api_data["uptime"],
        "load_average" => [
            "one_minute" => floatval(trim($system_api_data["cpu"]["load"][0])),
            "five_minute" => floatval(trim($system_api_data["cpu"]["load"][1])),
            "fifteen_minute" => floatval(trim($system_api_data["cpu"]["load"][2])),
        ],
    ],

    "cpu" => [
        "count" => (int) $system_api_data["cpu"]["cur.freq"],
    ],

    "filesystems" => $system_api_data["disk"]["devices"],

];

"""
        telemetry: MutableMapping[str, Any] = await self._exec_php(script)
        if not isinstance(telemetry, MutableMapping):
            _LOGGER.error("Invalid data returned from get_telemetry_legacy")
            return {}
        if isinstance(telemetry.get("gateways", []), list):
            telemetry["gateways"] = {}
        if isinstance(telemetry.get("filesystems", []), list):
            for filesystem in telemetry.get("filesystems", []):
                filesystem["blocks"] = filesystem.pop("size", None)
                try:
                    filesystem["used_pct"] = int(
                        filesystem.pop("capacity", "").strip("%")
                    )
                except ValueError:
                    filesystem.pop("capacity", None)
        # _LOGGER.debug(f"[get_telemetry_legacy] telemetry: {telemetry}")
        return telemetry

    @_log_errors
    async def get_notices(self) -> MutableMapping[str, Any]:
        """Get active OPNsense notices."""
        notices_info = await self._get("/api/core/system/status")
        # _LOGGER.debug(f"[get_notices] notices_info: {notices_info}")

        if not isinstance(notices_info, MutableMapping):
            return {}
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
                            datetime.fromtimestamp(
                                int(notice.get("timestamp", 0)),
                                tz=timezone(
                                    datetime.now().astimezone().utcoffset()
                                    or timedelta()
                                ),
                            )
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
    async def close_notice(self, id) -> bool:
        """Close selected notices."""

        # id = "all" to close all notices
        success = True
        if id.lower() == "all":
            notices = await self._get("/api/core/system/status")
            # _LOGGER.debug(f"[close_notice] notices: {notices}")

            if not isinstance(notices, MutableMapping):
                return False
            for key, notice in notices.items():
                if "statusCode" in notice:
                    dismiss = await self._post(
                        "/api/core/system/dismissStatus", payload={"subject": key}
                    )
                    # _LOGGER.debug(f"[close_notice] id: {key}, dismiss: {dismiss}")
                    if (
                        not isinstance(dismiss, MutableMapping)
                        or dismiss.get("status", "failed") != "ok"
                    ):
                        success = False
        else:
            dismiss = await self._post(
                "/api/core/system/dismissStatus", payload={"subject": id}
            )
            _LOGGER.debug("[close_notice] id: %s, dismiss: %s", id, dismiss)
            if (
                not isinstance(dismiss, MutableMapping)
                or dismiss.get("status", "failed") != "ok"
            ):
                success = False
        _LOGGER.debug("[close_notice] success: %s", success)
        return success

    @_log_errors
    async def get_unbound_blocklist(self) -> MutableMapping[str, Any]:
        """Return the Unbound Blocklist details."""
        response = await self._get("/api/unbound/settings/get")
        if not isinstance(response, MutableMapping):
            _LOGGER.error("Invalid data returned from get_unbound_blocklist")
            return {}
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
                        if isinstance(value, MutableMapping)
                        and value.get("selected", 0) == 1
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
        """Get the details of the wireguard services."""
        summary_raw = await self._get("/api/wireguard/service/show")
        clients_raw = await self._get("/api/wireguard/client/get")
        servers_raw = await self._get("/api/wireguard/server/get")
        if (
            not isinstance(summary_raw, MutableMapping)
            or not isinstance(clients_raw, MutableMapping)
            or not isinstance(servers_raw, MutableMapping)
        ):
            return {}
        summary = summary_raw.get("rows", [])
        client_summ = clients_raw.get("client", {}).get("clients", {}).get("client", {})
        server_summ = servers_raw.get("server", {}).get("servers", {}).get("server", {})
        if (
            not isinstance(summary, list)
            or not isinstance(client_summ, MutableMapping)
            or not isinstance(server_summ, MutableMapping)
        ):
            return {}
        servers: MutableMapping[str, Any] = {}
        clients: MutableMapping[str, Any] = {}

        for uid, srv in server_summ.items():
            if not isinstance(srv, MutableMapping):
                continue
            server: MutableMapping[str, Any] = {}
            for attr in ("name", "pubkey", "endpoint", "peer_dns"):
                if srv.get(attr, None):
                    if attr == "peer_dns":
                        server["dns_servers"] = [srv.get(attr)]
                    else:
                        server[attr] = srv.get(attr)
            server["uuid"] = uid
            server["enabled"] = bool(srv.get("enabled", "") == "1")
            server["interface"] = f"wg{srv.get('instance', '')}"
            server["tunnel_addresses"] = []
            for addr in srv.get("tunneladdress", {}).values():
                if addr.get("selected", 0) == 1 and addr.get("value", None):
                    server["tunnel_addresses"].append(addr.get("value"))
            server["clients"] = []
            for peer_id, peer in srv.get("peers", {}).items():
                if peer.get("selected", 0) == 1 and peer.get("value", None):
                    server["clients"].append(
                        {
                            "name": peer.get("value"),
                            "uuid": peer_id,
                            "connected": False,
                        }
                    )
            server["connected_clients"] = 0
            server["total_bytes_recv"] = 0
            server["total_bytes_sent"] = 0
            servers[uid] = server

        for uid, clnt in client_summ.items():
            if not isinstance(clnt, MutableMapping):
                continue
            client: MutableMapping[str, Any] = {}
            for attr in ("name", "pubkey"):
                if clnt.get(attr, None):
                    client[attr] = clnt.get(attr, None)
            client["uuid"] = uid
            client["enabled"] = bool(clnt.get("enabled", "0") == "1")
            client["tunnel_addresses"] = []
            for addr in clnt.get("tunneladdress", {}).values():
                if addr.get("selected", 0) == 1 and addr.get("value", None):
                    client["tunnel_addresses"].append(addr.get("value"))
            client["servers"] = []
            for srv_id, srv in clnt.get("servers", {}).items():
                if srv.get("selected", 0) == 1 and srv.get("value", None):
                    if servers.get(srv_id, None):
                        add_srv: MutableMapping[str, Any] = {
                            "name": servers[srv_id]["name"],
                            "uuid": srv_id,
                            "connected": False,
                        }
                        for attr in ("pubkey", "interface", "tunnel_addresses"):
                            if servers.get(srv_id, {}).get(attr, None):
                                add_srv[attr] = servers[srv_id][attr]
                        client["servers"].append(add_srv)
                    else:
                        client["servers"].append(
                            {
                                "name": srv.get("value"),
                                "uuid": srv_id,
                                "connected": False,
                            }
                        )
            for server in servers.values():
                if isinstance(server, MutableMapping) and isinstance(
                    server.get("clients", None), list
                ):
                    match_cl: MutableMapping[str, Any] = {}
                    for cl in server.get("clients", {}):
                        if (
                            isinstance(cl, MutableMapping)
                            and cl.get("uuid", None) == uid
                        ):
                            match_cl = cl
                            break
                    if match_cl:
                        for attr in ("name", "enabled", "pubkey", "tunnel_addresses"):
                            if client.get(attr, None):
                                match_cl[attr] = client.get(attr)
            client["connected_servers"] = 0
            client["total_bytes_recv"] = 0
            client["total_bytes_sent"] = 0
            clients[uid] = client

        for entry in summary:
            if (
                isinstance(entry, MutableMapping)
                and entry.get("type", "") == "interface"
            ):
                for server in servers.values():
                    if (
                        isinstance(server, MutableMapping)
                        and server.get("pubkey", "") == entry.get("public-key", "-")
                        and entry.get("status", None)
                    ):
                        server["status"] = entry.get("status")
            elif isinstance(entry, MutableMapping) and entry.get("type", "") == "peer":
                for client in clients.values():
                    if (
                        isinstance(client, MutableMapping)
                        and client.get("pubkey", "") == entry.get("public-key", "-")
                        and isinstance(client.get("servers", None), list)
                    ):
                        client["connected_servers"] = 0
                        for srv in client.get("servers", []):
                            if isinstance(srv, MutableMapping) and srv.get(
                                "interface", ""
                            ) == entry.get("if", "-"):
                                if (
                                    entry.get("endpoint", None)
                                    and entry.get("endpoint", None) != "(none)"
                                ):
                                    srv["endpoint"] = entry.get("endpoint")
                                if entry.get("transfer-rx", None):
                                    srv["bytes_recv"] = entry.get("transfer-rx")
                                    client["total_bytes_recv"] = int(
                                        client.get("total_bytes_recv", 0)
                                    ) + int(entry.get("transfer-rx", 0))
                                if entry.get("transfer-tx", None):
                                    srv["bytes_sent"] = entry.get("transfer-tx")
                                    client["total_bytes_sent"] = int(
                                        client.get("total_bytes_sent", 0)
                                    ) + int(entry.get("transfer-tx", 0))
                                if entry.get("latest-handshake", None):
                                    srv["latest_handshake"] = datetime.fromtimestamp(
                                        int(entry.get("latest-handshake", 0)),
                                        tz=timezone(
                                            datetime.now().astimezone().utcoffset()
                                            or timedelta()
                                        ),
                                    )
                                    srv["connected"] = wireguard_is_connected(
                                        srv.get("latest_handshake", datetime.min)
                                    )
                                    if srv["connected"]:
                                        client["connected_servers"] += 1
                                    if client.get(
                                        "latest_handshake", None
                                    ) is None or client.get(
                                        "latest_handshake"
                                    ) < srv.get("latest_handshake", 0):
                                        client["latest_handshake"] = srv.get(
                                            "latest_handshake"
                                        )
                                else:
                                    srv["connected"] = False

                for server in servers.values():
                    if (
                        isinstance(server, MutableMapping)
                        and server.get("interface", "") == entry.get("if", "-")
                        and isinstance(server.get("clients", None), list)
                    ):
                        for clnt in server.get("clients", []):
                            if isinstance(clnt, MutableMapping) and clnt.get(
                                "pubkey", ""
                            ) == entry.get("public-key", "-"):
                                if (
                                    entry.get("endpoint", None)
                                    and entry.get("endpoint", None) != "(none)"
                                ):
                                    clnt["endpoint"] = entry.get("endpoint")
                                if entry.get("transfer-rx", None):
                                    clnt["bytes_recv"] = entry.get("transfer-rx")
                                    server["total_bytes_recv"] = int(
                                        server.get("total_bytes_recv", 0)
                                    ) + int(entry.get("transfer-rx", 0))
                                if entry.get("transfer-tx", None):
                                    clnt["bytes_sent"] = entry.get("transfer-tx")
                                    server["total_bytes_sent"] = int(
                                        server.get("total_bytes_sent", 0)
                                    ) + int(entry.get("transfer-tx", 0))
                                if entry.get("latest-handshake", None):
                                    clnt["latest_handshake"] = datetime.fromtimestamp(
                                        int(entry.get("latest-handshake", 0)),
                                        tz=timezone(
                                            datetime.now().astimezone().utcoffset()
                                            or timedelta()
                                        ),
                                    )
                                    clnt["connected"] = wireguard_is_connected(
                                        clnt.get("latest_handshake", datetime.min)
                                    )
                                    if clnt["connected"]:
                                        server["connected_clients"] += 1
                                    if server.get(
                                        "latest_handshake", None
                                    ) is None or server.get(
                                        "latest_handshake"
                                    ) < clnt.get("latest_handshake", 0):
                                        server["latest_handshake"] = clnt.get(
                                            "latest_handshake"
                                        )
                                else:
                                    clnt["connected"] = False

        wireguard: MutableMapping[str, Any] = {"servers": servers, "clients": clients}
        _LOGGER.debug("[get_wireguard] wireguard: %s", wireguard)
        return wireguard

    async def toggle_vpn_instance(
        self, vpn_type: str, clients_servers: str, uuid: str
    ) -> bool:
        """Toggle the specified VPN instance on or off."""
        if vpn_type == "openvpn":
            success = await self._post(f"/api/openvpn/instances/toggle/{uuid}")
            if not isinstance(success, MutableMapping) or not success.get(
                "changed", False
            ):
                return False
            reconfigure = await self._post("/api/openvpn/service/reconfigure")
            if isinstance(reconfigure, MutableMapping):
                return reconfigure.get("result", "") == "ok"
        elif vpn_type == "wireguard":
            if clients_servers == "clients":
                success = await self._post(f"/api/wireguard/client/toggleClient/{uuid}")
            elif clients_servers == "servers":
                success = await self._post(f"/api/wireguard/server/toggleServer/{uuid}")
            if not isinstance(success, MutableMapping) or not success.get(
                "changed", False
            ):
                return False
            reconfigure = await self._post("/api/wireguard/service/reconfigure")
            if isinstance(reconfigure, MutableMapping):
                return reconfigure.get("result", "") == "ok"
        return False

    async def reload_interface(self, if_name: str) -> bool:
        """Reload the specified interface."""
        reload = await self._post(f"/api/interfaces/overview/reloadInterface/{if_name}")
        if not isinstance(reload, MutableMapping):
            return False
        return reload.get("message", "").startswith("OK")

    async def get_certificates(self) -> MutableMapping[str, Any]:
        """Return the active encryption certificates."""
        certs_raw = await self._get("/api/trust/cert/search")
        if not isinstance(certs_raw, MutableMapping) or not isinstance(
            certs_raw.get("rows", None), list
        ):
            return {}
        certs: MutableMapping[str, Any] = {}
        for cert in certs_raw.get("rows", None):
            if cert.get("descr", None):
                certs[cert.get("descr")] = {
                    "uuid": cert.get("uuid", None),
                    "issuer": cert.get("caref", None),
                    "purpose": cert.get("rfc3280_purpose", None),
                    "in_use": bool(cert.get("in_use", "0") == "1"),
                    "valid_from": datetime.fromtimestamp(
                        OPNsenseClient._try_to_int(cert.get("valid_from", None)) or 0,
                        tz=datetime.now().astimezone().tzinfo,
                    ),
                    "valid_to": datetime.fromtimestamp(
                        OPNsenseClient._try_to_int(cert.get("valid_to", None)) or 0,
                        tz=datetime.now().astimezone().tzinfo,
                    ),
                }
        _LOGGER.debug("[get_certificates] certs: %s", certs)
        return certs

    async def generate_vouchers(self, data: MutableMapping[str, Any]) -> list:
        """Generate vouchers from the Voucher Server."""
        if data.get("voucher_server", None):
            server = data.get("voucher_server")
        else:
            servers = await self._get("/api/captiveportal/voucher/listProviders")
            if not isinstance(servers, list):
                raise VoucherServerError(
                    f"Error getting list of voucher servers: {servers}"
                )
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
        voucher_url: str = f"/api/captiveportal/voucher/generateVouchers/{server_slug}/"
        _LOGGER.debug("[generate_vouchers] url: %s, payload: %s", voucher_url, payload)
        vouchers = await self._post(
            voucher_url,
            payload=payload,
        )
        if not isinstance(vouchers, list):
            raise VoucherServerError(f"Error returned requesting vouchers: {vouchers}")
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
                voucher["validity_str"] = human_friendly_duration(
                    voucher.get("validity")
                )
            if voucher.get("expirytime", None):
                voucher["expiry_timestamp"] = voucher.get("expirytime")
                voucher["expirytime"] = datetime.fromtimestamp(
                    OPNsenseClient._try_to_int(voucher.get("expirytime")) or 0,
                    tz=timezone(datetime.now().astimezone().utcoffset() or timedelta()),
                )

            rearranged_voucher: MutableMapping[str, Any] = {
                key: voucher[key] for key in ordered_keys if key in voucher
            }
            voucher.clear()
            voucher.update(rearranged_voucher)

        _LOGGER.debug("[generate_vouchers] vouchers: %s", vouchers)
        return vouchers

    async def kill_states(self, ip_addr) -> MutableMapping[str, Any]:
        """Kill the active states of the IP address."""
        payload: MutableMapping[str, Any] = {"filter": ip_addr}
        response = await self._post(
            "/api/diagnostics/firewall/kill_states/",
            payload=payload,
        )
        _LOGGER.debug("[kill_states] ip_addr: %s, response: %s", ip_addr, response)
        if not isinstance(response, MutableMapping):
            return {"success": False, "dropped_states": 0}
        return {
            "success": bool(response.get("result", None) == "ok"),
            "dropped_states": response.get("dropped_states", 0),
        }

    async def toggle_alias(self, alias, toggle_on_off) -> bool:
        """Toggle alias on and off."""
        alias_list_resp = await self._get("/api/firewall/alias/searchItem")
        if not isinstance(alias_list_resp, MutableMapping):
            return False
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
        url: str = f"/api/firewall/alias/toggleItem/{uuid}"
        if toggle_on_off == "on":
            url = f"{url}/1"
        elif toggle_on_off == "off":
            url = f"{url}/0"
        response = await self._post(
            url,
            payload=payload,
        )
        _LOGGER.debug(
            "[toggle_alias] alias: %s, uuid: %s, action: %s, " "url: %s, response: %s",
            alias,
            uuid,
            toggle_on_off,
            url,
            response,
        )
        if (
            not isinstance(response, MutableMapping)
            or "result" not in response
            or response.get("result") == "failed"
        ):
            return False

        set_resp = await self._post("/api/firewall/alias/set")
        if (
            not isinstance(set_resp, MutableMapping)
            or set_resp.get("result") != "saved"
        ):
            return False

        reconfigure_resp = await self._post("/api/firewall/alias/reconfigure")
        if (
            not isinstance(reconfigure_resp, MutableMapping)
            or reconfigure_resp.get("status") != "ok"
        ):
            return False

        return True
