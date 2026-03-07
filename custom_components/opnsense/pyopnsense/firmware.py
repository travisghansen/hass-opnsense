"""Firmware and version-management methods for OPNsenseClient."""

from .client_methods_part2 import (
    firmware_changelog,
    get_firmware_update_info,
    upgrade_firmware,
    upgrade_status,
)

__all__ = [
    "get_firmware_update_info",
    "upgrade_firmware",
    "upgrade_status",
    "firmware_changelog",
]
