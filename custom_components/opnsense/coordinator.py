from collections.abc import Mapping
import copy
import logging
import time
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .helpers import dict_get
from .pyopnsense import OPNsenseClient

_LOGGER: logging.Logger = logging.getLogger(__name__)


class OPNsenseDataUpdateCoordinator(DataUpdateCoordinator):

    def __init__(
        self,
        hass: HomeAssistant,
        client: OPNsenseClient,
        name: str,
        update_interval,
        device_tracker_coordinator: bool = False,
    ) -> None:
        """Initialize the data object."""
        _LOGGER.info(
            f"Initializing OPNsense Data Update Coordinator {'for Device Tracker' if device_tracker_coordinator else ''}"
        )
        self._client: OPNsenseClient = client
        self._state: Mapping[str, Any] = {}
        self._device_tracker_coordinator: bool = device_tracker_coordinator
        super().__init__(
            hass,
            _LOGGER,
            name=name,
            update_interval=update_interval,
        )

    def _log_timing(func):
        async def inner(self, *args, **kwargs):
            begin: float = time.time()
            response = await func(self, *args, **kwargs)
            end: float = time.time()
            elapsed: float = round((end - begin), 3)
            _LOGGER.debug(
                f"[{'DT ' if self._device_tracker_coordinator else ''}Coordinator Timing] {func.__name__.strip('_')}: {elapsed} seconds"
            )
            return response

        return inner

    @_log_timing
    async def _get_system_info(self):
        return await self._client.get_system_info()

    @_log_timing
    async def _get_firmware_update_info(self):
        try:
            return await self._client.get_firmware_update_info()
        except BaseException as e:
            _LOGGER.error(
                f"Error in get_firmware_update_info. {e.__class__.__qualname__}: {e}"
            )
            return None
            # raise err

    @_log_timing
    async def _get_telemetry(self):
        return await self._client.get_telemetry()

    @_log_timing
    async def _get_host_firmware_version(self) -> None | str:
        return await self._client.get_host_firmware_version()

    @_log_timing
    async def _get_config(self):
        return await self._client.get_config()

    @_log_timing
    async def _get_interfaces(self):
        return await self._client.get_interfaces()

    @_log_timing
    async def _get_services(self):
        return await self._client.get_services()

    @_log_timing
    async def _get_carp_interfaces(self):
        return await self._client.get_carp_interfaces()

    @_log_timing
    async def _get_carp_status(self):
        return await self._client.get_carp_status()

    @_log_timing
    async def _get_dhcp_leases(self):
        return await self._client.get_dhcp_leases()

    @_log_timing
    async def _are_notices_pending(self):
        return await self._client.are_notices_pending()

    @_log_timing
    async def _get_notices(self):
        return await self._client.get_notices()

    @_log_timing
    async def _get_arp_table(self):
        return await self._client.get_arp_table(True)

    async def _async_update_data(self):
        """Fetch the latest state from OPNsense."""
        _LOGGER.info(
            f"{'DT ' if self._device_tracker_coordinator else ''}Updating Data"
        )
        # copy the old data to have around
        current_time: float = time.time()

        previous_state: Mapping[str, Any] = copy.deepcopy(self._state)
        if "previous_state" in previous_state.keys():
            del previous_state["previous_state"]

        # ensure clean state each interval
        self._state = {}
        self._state["update_time"] = current_time
        self._state["previous_state"] = previous_state

        self._state["system_info"] = await self._get_system_info()
        self._state["host_firmware_version"] = await self._get_host_firmware_version()

        if self._device_tracker_coordinator:
            try:
                self._state["arp_table"] = await self._get_arp_table()
            except BaseException as e:
                _LOGGER.error(
                    f"Error getting arp table. {e.__class__.__qualname__}: {e}"
                )
        else:
            self._state["firmware_update_info"] = await self._get_firmware_update_info()
            self._state["telemetry"] = await self._get_telemetry()
            self._state["config"] = await self._get_config()
            self._state["interfaces"] = await self._get_interfaces()
            self._state["services"] = await self._get_services()
            self._state["carp_interfaces"] = await self._get_carp_interfaces()
            self._state["carp_status"] = await self._get_carp_status()
            # self._state["dhcp_leases"] = await self._client.get_dhcp_leases()
            self._state["dhcp_leases"] = []
            self._state["dhcp_stats"] = {}
            self._state["notices"] = {}
            self._state["notices"][
                "pending_notices_present"
            ] = await self._are_notices_pending()
            self._state["notices"]["pending_notices"] = await self._get_notices()

            lease_stats: Mapping[str, int] = {"total": 0, "online": 0, "offline": 0}
            for lease in self._state["dhcp_leases"]:
                if "act" in lease.keys() and lease["act"] == "expired":
                    continue

                lease_stats["total"] += 1
                if "online" in lease.keys():
                    if lease["online"] == "online":
                        lease_stats["online"] += 1
                    if lease["online"] == "offline":
                        lease_stats["offline"] += 1

            self._state["dhcp_stats"]["leases"] = lease_stats

            # calcule pps and kbps
            update_time = dict_get(self._state, "update_time")
            previous_update_time = dict_get(self._state, "previous_state.update_time")

            if previous_update_time is not None:
                elapsed_time = update_time - previous_update_time

                for interface_name in dict_get(
                    self._state, "telemetry.interfaces", {}
                ).keys():
                    interface = dict_get(
                        self._state, f"telemetry.interfaces.{interface_name}"
                    )
                    previous_interface = dict_get(
                        self._state,
                        f"previous_state.telemetry.interfaces.{interface_name}",
                    )
                    if previous_interface is None:
                        break

                    for property in [
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
                        current_parent_value = interface[property]
                        previous_parent_value = previous_interface[property]
                        change = abs(current_parent_value - previous_parent_value)
                        rate = change / elapsed_time

                        value = 0
                        if "pkts" in property:
                            label = "packets_per_second"
                            value = rate
                        if "bytes" in property:
                            label = "kilobytes_per_second"
                            # 1 Byte = 8 bits
                            # 1 byte is equal to 0.001 kilobytes
                            KBs = rate / 1000
                            # Kbs = KBs * 8
                            value = KBs

                        new_property = f"{property}_{label}"
                        interface[new_property] = int(round(value, 0))

                for server_name in dict_get(
                    self._state, "telemetry.openvpn.servers", {}
                ).keys():
                    if (
                        server_name
                        not in dict_get(
                            self._state, "telemetry.openvpn.servers", {}
                        ).keys()
                    ):
                        continue

                    if (
                        server_name
                        not in dict_get(
                            self._state, "previous_state.telemetry.openvpn.servers", {}
                        ).keys()
                    ):
                        continue

                    server = self._state["telemetry"]["openvpn"]["servers"][server_name]
                    previous_server = self._state["previous_state"]["telemetry"][
                        "openvpn"
                    ]["servers"][server_name]

                    for property in [
                        "total_bytes_recv",
                        "total_bytes_sent",
                    ]:
                        current_parent_value = server[property]
                        previous_parent_value = previous_server[property]
                        change = abs(current_parent_value - previous_parent_value)
                        rate = change / elapsed_time

                        value = 0
                        if "pkts" in property:
                            label = "packets_per_second"
                            value = rate
                        if "bytes" in property:
                            label = "kilobytes_per_second"
                            # 1 Byte = 8 bits
                            # 1 byte is equal to 0.001 kilobytes
                            KBs = rate / 1000
                            # Kbs = KBs * 8
                            value = KBs

                        new_property: str = f"{property}_{label}"
                        server[new_property] = int(round(value, 0))
        return self._state
