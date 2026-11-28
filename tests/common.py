"""Home Assistant test plugin helpers shared across the test suite.

``pytest-homeassistant`` covers Home Assistant 2026.11 and later. Older supported
versions are only covered by its predecessor,
``pytest-homeassistant-custom-component``. Import plugin helpers from here so the
same tests run against either package.
"""

from typing import Any

from homeassistant.helpers.device_registry import DeviceInfo

try:
    from pytest_homeassistant.common import MockConfigEntry
except ModuleNotFoundError:
    from pytest_homeassistant_custom_component.common import MockConfigEntry

__all__ = ["MockConfigEntry", "device_info_dict"]


def device_info_dict(device_info: DeviceInfo | None) -> dict[str, Any]:
    """Return the fields an entity's device info sets.

    Home Assistant 2026.12 made ``DeviceInfo`` a dataclass and deprecated dict-style
    access. Earlier supported releases define it as a ``TypedDict``.

    Args:
        device_info (DeviceInfo | None): Device info returned by an entity.

    Returns:
        dict[str, Any]: The set fields by name.
    """
    assert device_info is not None
    if isinstance(device_info, dict):
        return dict(device_info)
    return device_info.as_dict()
