import copy
import logging
import time
from collections.abc import Mapping
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import ATTR_UNBOUND_BLOCKLIST
from .helpers import dict_get
from .pyopnsense import OPNsenseClient

_LOGGER: logging.Logger = logging.getLogger(__name__)


class OPNsenseDataUpdateCoordinator(DataUpdateCoordinator):

    def __init__(
        self,
        hass: HomeAssistant,
        client: OPNsenseClient,
        name: str,
        update_interval: timedelta,
        device_unique_id: str,
        device_tracker_coordinator: bool = False,
    ) -> None:
        """Initialize the data object."""
        _LOGGER.info(
            f"Initializing OPNsense Data Update Coordinator {'for Device Tracker' if device_tracker_coordinator else ''}"
        )
        self._client: OPNsenseClient = client
        self._state: Mapping[str, Any] = {}
        self._device_tracker_coordinator: bool = device_tracker_coordinator
        self._device_unique_id: str = device_unique_id
        super().__init__(
            hass,
            _LOGGER,
            name=name,
            update_interval=update_interval,
        )

    async def _get_states(self, categories: list) -> Mapping[str, Any]:
        state: Mapping[str, Any] = {}
        total_time: float = 0
        for cat in categories:
            method = getattr(self._client, cat.get("function", ""), None)
            if method:
                start_time: float = time.perf_counter()
                state[cat.get("state_key")] = await method()
                end_time: float = time.perf_counter()
                elapsed_time: float = end_time - start_time
                total_time += elapsed_time
                _LOGGER.debug(
                    f"[{'DT ' if self._device_tracker_coordinator else ''}Coordinator Timing] {cat.get('function','')}: {elapsed_time:.3f} seconds"
                )
            else:
                _LOGGER.error(f"Method {cat.get('function','')} not found.")

        return state

    async def _async_update_data(self) -> Mapping[str, Any]:
        """Fetch the latest state from OPNsense."""
        _LOGGER.info(
            f"{'DT ' if self._device_tracker_coordinator else ''}Updating Data"
        )
        await self._client.reset_query_counts()

        # copy the old data to have around
        current_time: float = time.time()

        previous_state: Mapping[str, Any] = copy.deepcopy(self._state)
        if "previous_state" in previous_state.keys():
            del previous_state["previous_state"]

        # ensure clean state each interval
        self._state = {}
        self._state["update_time"] = current_time
        self._state["previous_state"] = previous_state

        if self._device_tracker_coordinator:
            categories: list = [
                {"function": "get_device_unique_id", "state_key": "device_unique_id"},
                {
                    "function": "get_host_firmware_version",
                    "state_key": "host_firmware_version",
                },
                {"function": "get_system_info", "state_key": "system_info"},
                {
                    "function": "get_arp_table",
                    "state_key": "arp_table",
                },
            ]
            self._state.update(await self._get_states(categories))
            if self._state.get("device_unique_id") is None:
                _LOGGER.warning(
                    "Coordinator failed to confirm OPNsense Router Unique ID. Will retry"
                )
                return {}
            if self._state.get("device_unique_id") != self._device_unique_id:
                _LOGGER.error(
                    f"Coordinator error. OPNsense Router Device ID ({self._state.get('device_unique_id')}) differs from the one saved in hass-opnsense ({self._device_unique_id})"
                )
                # Create repair task here
                return {}
            restapi_count, xmlrpc_count = await self._client.get_query_counts()
            _LOGGER.debug(
                f"DT Update Complete. REST API Queries: {restapi_count}. XMLRPC Queries: {xmlrpc_count}"
            )
            return self._state

        categories: list = [
            {"function": "get_device_unique_id", "state_key": "device_unique_id"},
            {
                "function": "get_host_firmware_version",
                "state_key": "host_firmware_version",
            },
            {"function": "get_system_info", "state_key": "system_info"},
            {
                "function": "get_firmware_update_info",
                "state_key": "firmware_update_info",
            },
            {"function": "get_telemetry", "state_key": "telemetry"},
            {"function": "get_interfaces", "state_key": "interfaces"},
            {"function": "get_openvpn", "state_key": "openvpn"},
            {"function": "get_gateways", "state_key": "gateways"},
            {"function": "get_config", "state_key": "config"},
            {"function": "get_services", "state_key": "services"},
            {"function": "get_carp_interfaces", "state_key": "carp_interfaces"},
            {"function": "get_carp_status", "state_key": "carp_status"},
            {"function": "get_notices", "state_key": "notices"},
            {
                "function": "get_unbound_blocklist",
                "state_key": ATTR_UNBOUND_BLOCKLIST,
            },
            {"function": "get_dhcp_leases", "state_key": "dhcp_leases"},
        ]

        self._state.update(await self._get_states(categories))
        if self._state.get("device_unique_id") is None:
            _LOGGER.warning(
                "Coordinator failed to confirm OPNsense Router Unique ID. Will retry"
            )
            return {}
        if self._state.get("device_unique_id") != self._device_unique_id:
            _LOGGER.error(
                f"Coordinator error. OPNsense Router Device ID ({self._state.get('device_unique_id')}) differs from the one saved in hass-opnsense ({self._device_unique_id})"
            )
            # Create repair task here
            return {}

        # calcule pps and kbps
        update_time = dict_get(self._state, "update_time")
        previous_update_time = dict_get(self._state, "previous_state.update_time")

        if previous_update_time is not None:
            elapsed_time = update_time - previous_update_time

            for interface_name, interface in dict_get(
                self._state, "interfaces", {}
            ).items():
                previous_interface = dict_get(
                    self._state,
                    f"previous_state.interfaces.{interface_name}",
                )
                if previous_interface is None:
                    continue

                for prop_name in [
                    "inbytes",
                    "outbytes",
                    # "inbytespass",
                    # "outbytespass",
                    # "inbytesblock",
                    # "outbytesblock",
                    "inpkts",
                    "outpkts",
                    # "inpktspass",
                    # "outpktspass",
                    # "inpktsblock",
                    # "outpktsblock",
                ]:
                    try:
                        current_parent_value: float = interface[prop_name]
                        previous_parent_value: float = previous_interface[prop_name]
                        change: float = abs(
                            current_parent_value - previous_parent_value
                        )
                        rate: float = change / elapsed_time
                    except (TypeError, KeyError, ZeroDivisionError):
                        rate: float = 0

                    value: float = 0
                    if "pkts" in prop_name:
                        label = "packets_per_second"
                        value = rate
                    elif "bytes" in prop_name:
                        label = "kilobytes_per_second"
                        # 1 Byte = 8 bits
                        # 1 byte is equal to 0.001 kilobytes
                        KBs: float = rate / 1000
                        # Kbs = KBs * 8
                        value = KBs
                    else:
                        continue

                    new_property = f"{prop_name}_{label}"
                    interface[new_property] = int(round(value, 0))

            for server_name in dict_get(self._state, "openvpn.servers", {}):

                if server_name not in dict_get(
                    self._state, "previous_state.openvpn.servers", {}
                ):
                    continue

                server: Mapping[str, Any] = (
                    self._state.get("openvpn", {})
                    .get("servers", {})
                    .get(server_name, {})
                )
                previous_server: Mapping[str, Any] = (
                    self._state.get("previous_state", {})
                    .get("openvpn", {})
                    .get("servers", {})
                    .get(server_name, {})
                )

                for prop_name in [
                    "total_bytes_recv",
                    "total_bytes_sent",
                ]:
                    try:
                        current_parent_value: float = server[prop_name]
                        previous_parent_value: float = previous_server[prop_name]
                        change: float = abs(
                            current_parent_value - previous_parent_value
                        )
                        rate: float = change / elapsed_time
                    except (TypeError, KeyError, ZeroDivisionError):
                        rate: float = 0

                    value: float = 0
                    if "pkts" in prop_name:
                        label = "packets_per_second"
                        value = rate
                    elif "bytes" in prop_name:
                        label = "kilobytes_per_second"
                        # 1 Byte = 8 bits
                        # 1 byte is equal to 0.001 kilobytes
                        KBs: float = rate / 1000
                        # Kbs = KBs * 8
                        value = KBs
                    else:
                        continue

                    new_property: str = f"{prop_name}_{label}"
                    server[new_property] = round(value)
        restapi_count, xmlrpc_count = await self._client.get_query_counts()
        _LOGGER.debug(
            f"Update Complete. REST API Queries: {restapi_count}. XMLRPC Queries: {xmlrpc_count}"
        )
        return self._state
