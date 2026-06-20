"""Helper methods for OPNsense."""

from collections.abc import MutableMapping
import ipaddress
import re
from typing import Any
from urllib.parse import urlparse


def dict_get(data: MutableMapping[str, Any], path: str, default: Any | None = None) -> Any | None:
    """Parse the path to get the desired value out of the data."""
    path_list: list = re.split(r"\.", path, flags=re.IGNORECASE)
    result: Any | None = data

    for key in path_list:
        if key.isnumeric():
            key = int(key)
        if isinstance(result, MutableMapping | list) and key in result:
            result = result[key]
        else:
            result = default
            break

    return result


def is_private_ip(url: str) -> bool:
    """Check if the address in the given URL is a private IP address."""
    parsed_url = urlparse(url)
    addr = parsed_url.hostname
    if not addr:
        return False

    try:
        ip_obj = ipaddress.ip_address(addr)
    except ValueError:
        return False
    else:
        return ip_obj.is_private


def coerce_bool(value: Any) -> bool | None:
    """Normalize values that may represent booleans.

    Args:
        value: Arbitrary state value returned by backend APIs.

    Returns:
        bool | None: Parsed boolean interpretation for common numeric/string variants.
            Returns ``None`` when the value is missing or not bool-like.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return value != 0
    if isinstance(value, str):
        normalized_value = value.strip().lower()
        if normalized_value in {"1", "true", "yes", "on"}:
            return True
        if normalized_value in {"0", "false", "no", "off"}:
            return False
    return None
