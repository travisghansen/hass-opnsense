"""Shared helper utilities for pyopnsense."""

import asyncio
from collections.abc import Callable, MutableMapping
from datetime import datetime, timedelta, timezone
import ipaddress
import logging
import re
import socket
import traceback
from typing import Any

import aiohttp

# value to set as the socket timeout
DEFAULT_TIMEOUT = 60

_LOGGER: logging.Logger = logging.getLogger(__name__)


def log_errors(func: Callable) -> Any:
    """Wrap coroutine methods with shared timeout/error logging behavior."""

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


def xmlrpc_timeout(func: Callable) -> Any:
    """Ensure XMLRPC calls obey the configured socket timeout."""

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
    """Determine whether a Wireguard session is still considered active."""
    if not past_time:
        return False
    return datetime.now().astimezone() - past_time <= timedelta(minutes=3)


def human_friendly_duration(seconds: int) -> str:
    """Convert a duration in seconds into a human-readable string."""
    months, seconds = divmod(seconds, 2419200)
    weeks, seconds = divmod(seconds, 604800)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)

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
    """Produce a sorting key for DHCP leases based on their IP addresses."""
    address = item.get("address", None)

    if not address:
        return (3, "")
    try:
        ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(address)
    except ValueError:
        return (2, "")
    else:
        return (0 if ip_obj.version == 4 else 1, ip_obj)


def dict_get(data: MutableMapping[str, Any], path: str, default: Any | None = None) -> Any | None:
    """Extract a nested value from a mapping using dot notation."""
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
    """Convert a Unix timestamp into a timezone-aware datetime."""
    if timestamp is None:
        return None
    return datetime.fromtimestamp(
        int(timestamp),
        tz=timezone(datetime.now().astimezone().utcoffset() or timedelta()),
    )


def try_to_int(input: Any | None, retval: int | None = None) -> int | None:
    """Return field to int."""
    if input is None:
        return retval
    try:
        return int(input)
    except (ValueError, TypeError):
        return retval


def try_to_float(input: Any | None, retval: float | None = None) -> float | None:
    """Return field to float."""
    if input is None:
        return retval
    try:
        return float(input)
    except (ValueError, TypeError):
        return retval


__all__ = [
    "DEFAULT_TIMEOUT",
    "dict_get",
    "get_ip_key",
    "human_friendly_duration",
    "log_errors",
    "timestamp_to_datetime",
    "try_to_float",
    "try_to_int",
    "wireguard_is_connected",
    "xmlrpc_timeout",
]
