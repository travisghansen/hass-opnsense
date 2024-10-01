from collections.abc import Mapping
import re
from typing import Any


def dict_get(data: Mapping[str, Any], path: str, default=None):
    pathList: list = re.split(r"\.", path, flags=re.IGNORECASE)
    result: Mapping[str, Any] = data
    for key in pathList:
        try:
            key: int | str = int(key) if key.isnumeric() else key
            result = result[key]
        except (TypeError, KeyError, AttributeError):
            result = default
            break

    return result
