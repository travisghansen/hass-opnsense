"""Home Assistant test plugin helpers shared across the test suite.

``pytest-homeassistant`` covers Home Assistant 2026.11 and later. Older supported
versions are only covered by its predecessor,
``pytest-homeassistant-custom-component``. Import plugin helpers from here so the
same tests run against either package.
"""

from types import SimpleNamespace
from typing import Any, cast

from homeassistant.helpers import typing as ha_typing
from homeassistant.helpers.device_registry import DeviceInfo

try:
    from pytest_homeassistant.common import MockConfigEntry
except ModuleNotFoundError:
    from pytest_homeassistant_custom_component.common import MockConfigEntry

__all__ = ["UNSET", "MockConfigEntry", "entity_device_info"]

# The value of a device info field that is not set. Home Assistant 2026.12 renamed
# ``UNDEFINED`` to ``Undefined`` and deprecated the old name.
UNSET: Any = ha_typing.Undefined if hasattr(ha_typing, "Undefined") else ha_typing.UNDEFINED


def entity_device_info(device_info: DeviceInfo | None) -> DeviceInfo:
    """Return an entity's device info with its fields readable as attributes.

    Home Assistant 2026.11 made ``DeviceInfo`` a dataclass, and 2026.12 deprecated
    dict-style access to it. Earlier supported releases define it as a ``TypedDict``,
    which this adapts. Remove that branch once ``hacs.json`` requires 2026.11.

    Args:
        device_info (DeviceInfo | None): Device info returned by an entity.

    Returns:
        DeviceInfo: The device info, where fields that are not set read as ``UNSET``.
    """
    assert device_info is not None
    if isinstance(device_info, dict):
        # Home Assistant added via_device_id after the minimum supported release.
        names = {*DeviceInfo.__annotations__, "via_device_id"}
        fields = dict.fromkeys(names, UNSET) | device_info
        return cast("DeviceInfo", SimpleNamespace(**fields))
    return device_info
