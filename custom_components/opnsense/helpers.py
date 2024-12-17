"""Helper methods for OPNsense."""

from collections.abc import MutableMapping
import re
from typing import Any


def dict_get(data: MutableMapping[str, Any], path: str, default=None) -> Any | None:
    """Parse the path to get the desired value out of the data."""
    pathList: list = re.split(r"\.", path, flags=re.IGNORECASE)
    result: MutableMapping[str, Any] = data

    for key in pathList:
        if key.isnumeric():
            key = int(key)
        if isinstance(result, (MutableMapping, list)) and key in result:
            result = result[key]
        else:
            result = default
            break

    return result
