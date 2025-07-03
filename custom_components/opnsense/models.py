"""OPNsense integration models."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from homeassistant.const import Platform

from .coordinator import OPNsenseDataUpdateCoordinator
from .pyopnsense import OPNsenseClient


@dataclass
class OPNsenseData:
    """Runtime data for the OPNsense integration."""

    coordinator: OPNsenseDataUpdateCoordinator
    device_tracker_coordinator: OPNsenseDataUpdateCoordinator | None
    opnsense_client: OPNsenseClient
    undo_update_listener: Callable[[], None]
    loaded_platforms: list[Platform]
    device_unique_id: str | None
    should_reload: bool = True
