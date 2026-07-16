"""OPNsense Coordinator."""

from collections.abc import Callable, Mapping, MutableMapping
import copy
from datetime import timedelta
import logging
import time
from typing import TYPE_CHECKING, Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import (
    ATTR_UNBOUND_BLOCKLIST,
    CONF_SYNC_CARP,
    CONF_SYNC_CERTIFICATES,
    CONF_SYNC_DHCP_LEASES,
    CONF_SYNC_FIREWALL_AND_NAT,
    CONF_SYNC_FIRMWARE_UPDATES,
    CONF_SYNC_GATEWAYS,
    CONF_SYNC_INTERFACES,
    CONF_SYNC_NOTICES,
    CONF_SYNC_SERVICES,
    CONF_SYNC_SMART,
    CONF_SYNC_SPEEDTEST,
    CONF_SYNC_TELEMETRY,
    CONF_SYNC_UNBOUND,
    CONF_SYNC_VNSTAT,
    CONF_SYNC_VPN,
    DEFAULT_SYNC_OPTION_VALUE,
    DOMAIN,
)
from .helpers import dict_get, get_smart_device_name, is_carp_entry
from .repair_reconciliation import has_repair_marker
from .repairs import async_create_device_id_mismatch_issue, is_valid_device_id

if TYPE_CHECKING:
    from aiopnsense import OPNsenseClient

_LOGGER: logging.Logger = logging.getLogger(__name__)

_PREVIOUS_STATE_KEYS: tuple[str, ...] = (
    "update_time",
    "interfaces",
    "openvpn",
    "wireguard",
)


class OPNsenseDataUpdateCoordinator(DataUpdateCoordinator):
    """Coordinator class for OPNsense."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: OPNsenseClient,
        name: str,
        update_interval: timedelta,
        device_unique_id: str | None,
        config_entry: ConfigEntry,
        device_tracker_coordinator: bool = False,
    ) -> None:
        """Initialize the coordinator for standard or device-tracker polling.

        Args:
            hass: Home Assistant instance.
            client: OPNsense API client used to fetch data.
            name: Coordinator name shown in logs.
            update_interval: Polling interval for coordinator refreshes.
            device_unique_id: Expected router unique ID from the config entry.
            config_entry: Config entry that owns this coordinator.
            device_tracker_coordinator: Whether this coordinator handles device-tracker data.

        Raises:
            ValueError: `config_entry` is required but was not provided.
        """
        _LOGGER.info(
            "Initializing OPNsense Data Update Coordinator %s",
            "for Device Tracker" if device_tracker_coordinator else "",
        )
        if config_entry is None:
            raise ValueError("config_entry is required for OPNsenseDataUpdateCoordinator")
        self._client: OPNsenseClient = client
        self._state: dict[str, Any] = {}
        self._device_tracker_coordinator: bool = device_tracker_coordinator
        self._mismatched_count = 0
        self._device_unique_id: str | None = device_unique_id
        self._updating: bool = False
        super().__init__(
            hass=hass,
            logger=_LOGGER,
            name=name,
            update_interval=update_interval,
            config_entry=config_entry,
        )
        self._categories = self._build_categories()

    async def _async_setup(self) -> None:
        """Prepare coordinator client options before the first refresh."""
        _LOGGER.debug(
            "Setting up %sCoordinator",
            "DT " if self._device_tracker_coordinator else "",
        )
        # await self._client.get_host_firmware_version() # Already triggered in
        # __init__.py async_setup_entry

    def _build_previous_state_snapshot(self) -> dict[str, Any]:
        """Build the previous-state subset used by derived counter rates.

        Returns:
            dict[str, Any]: Deep-copied counter source fields from the current state.
        """
        return {
            key: copy.deepcopy(self._state[key])
            for key in _PREVIOUS_STATE_KEYS
            if key in self._state
        }

    async def _get_states(self, categories: list) -> dict[str, Any]:
        """Fetch state payloads for the requested category call definitions.

        Args:
            categories: Sequence of category mappings with `function` and `state_key` entries.

        Returns:
            dict[str, Any]: State mapping keyed by each category `state_key`.
        """
        state: dict[str, Any] = {}
        total_time: float = 0
        for cat in categories:
            method_name: str = cat.get("function", "")
            method: Callable | None = getattr(self._client, method_name, None)
            if method is not None:
                start_time: float = time.perf_counter()
                if method_name == "get_device_unique_id":
                    state[cat.get("state_key")] = await method(expected_id=self._device_unique_id)
                elif method_name == "get_smart_info":
                    smart_info: dict[str, Any] = {}
                    smart_devices = state.get("smart")
                    if isinstance(smart_devices, list):
                        for smart_device in smart_devices:
                            if not isinstance(smart_device, Mapping):
                                continue
                            device_name = get_smart_device_name(smart_device)
                            if not device_name:
                                continue
                            smart_info[device_name] = await method(
                                device=device_name,
                                info_type=cat.get("info_type", "A"),
                            )
                    state[cat.get("state_key")] = smart_info
                else:
                    state[cat.get("state_key")] = await method()
                end_time: float = time.perf_counter()
                elapsed_time: float = end_time - start_time
                total_time += elapsed_time
                _LOGGER.debug(
                    "[%sCoordinator Timing] %s: %.3f seconds",
                    "DT " if self._device_tracker_coordinator else "",
                    cat.get("function", ""),
                    elapsed_time,
                )
            else:
                _LOGGER.error("Method %s not found", cat.get("function", ""))

        return state

    def _build_categories(self) -> list[dict[str, str]]:
        """Build API call categories based on integration sync options.

        Returns:
            list[dict[str, str]]: Ordered call definitions for coordinator refreshes.
        """
        if not self.config_entry:
            _LOGGER.error("Coordinator build_categories failed. No config entry found.")
            return []
        if is_carp_entry(self.config_entry):
            return [
                {"function": "get_system_info", "state_key": "system_info"},
                {"function": "get_carp", "state_key": "carp"},
            ]

        config: Mapping[str, Any] = self.config_entry.data
        categories: list[dict[str, str]] = [
            {"function": "get_device_unique_id", "state_key": "device_unique_id"},
            {"function": "get_system_info", "state_key": "system_info"},
            {
                "function": "get_host_firmware_version",
                "state_key": "host_firmware_version",
            },
        ]

        if config.get(CONF_SYNC_TELEMETRY, DEFAULT_SYNC_OPTION_VALUE):
            categories.append({"function": "get_telemetry", "state_key": "telemetry"})
        if config.get(CONF_SYNC_VNSTAT, DEFAULT_SYNC_OPTION_VALUE):
            categories.append({"function": "get_vnstat", "state_key": "vnstat"})
        if config.get(CONF_SYNC_SPEEDTEST, DEFAULT_SYNC_OPTION_VALUE):
            categories.append({"function": "get_speedtest", "state_key": "speedtest"})
        if config.get(CONF_SYNC_SMART, DEFAULT_SYNC_OPTION_VALUE):
            if hasattr(self._client, "get_smart"):
                categories.append({"function": "get_smart", "state_key": "smart"})
                if hasattr(self._client, "get_smart_info"):
                    categories.append(
                        {
                            "function": "get_smart_info",
                            "state_key": "smart_info",
                            "info_type": "A",
                        }
                    )
            else:
                _LOGGER.debug("SMART sync requested, but this OPNsense client does not support it")
        if config.get(CONF_SYNC_VPN, DEFAULT_SYNC_OPTION_VALUE):
            categories.extend(
                [
                    {"function": "get_openvpn", "state_key": "openvpn"},
                    {"function": "get_wireguard", "state_key": "wireguard"},
                ]
            )

        if config.get(CONF_SYNC_FIRMWARE_UPDATES, DEFAULT_SYNC_OPTION_VALUE):
            categories.append(
                {
                    "function": "get_firmware_update_info",
                    "state_key": "firmware_update_info",
                }
            )

        if config.get(CONF_SYNC_CARP, DEFAULT_SYNC_OPTION_VALUE):
            categories.append({"function": "get_carp", "state_key": "carp"})
        if config.get(CONF_SYNC_DHCP_LEASES, DEFAULT_SYNC_OPTION_VALUE):
            categories.append({"function": "get_dhcp_leases", "state_key": "dhcp_leases"})
        if config.get(CONF_SYNC_GATEWAYS, DEFAULT_SYNC_OPTION_VALUE):
            categories.append({"function": "get_gateways", "state_key": "gateways"})
        if config.get(CONF_SYNC_SERVICES, DEFAULT_SYNC_OPTION_VALUE):
            categories.append({"function": "get_services", "state_key": "services"})
        if config.get(CONF_SYNC_NOTICES, DEFAULT_SYNC_OPTION_VALUE):
            categories.append({"function": "get_notices", "state_key": "notices"})
        if config.get(CONF_SYNC_FIREWALL_AND_NAT, DEFAULT_SYNC_OPTION_VALUE):
            categories.append({"function": "get_firewall", "state_key": "firewall"})
        if config.get(CONF_SYNC_UNBOUND, DEFAULT_SYNC_OPTION_VALUE):
            categories.append(
                {
                    "function": "get_unbound_blocklist",
                    "state_key": ATTR_UNBOUND_BLOCKLIST,
                }
            )
        if config.get(CONF_SYNC_INTERFACES, DEFAULT_SYNC_OPTION_VALUE):
            categories.append({"function": "get_interfaces", "state_key": "interfaces"})
        if config.get(CONF_SYNC_CERTIFICATES, DEFAULT_SYNC_OPTION_VALUE):
            categories.append({"function": "get_certificates", "state_key": "certificates"})
        _LOGGER.debug(
            "Categories for fetching data: %s", [item["state_key"] for item in categories]
        )
        return categories

    async def _check_device_unique_id(self) -> bool:
        """Validate that the runtime router ID matches the configured device ID.

        Returns:
            bool: `True` when IDs match; otherwise `False` after mismatch handling.
        """
        if (
            self._device_unique_id is None
            and self.config_entry
            and is_carp_entry(self.config_entry)
        ):
            return True
        runtime_device_id = self._state.get("device_unique_id")
        if not is_valid_device_id(self._device_unique_id):
            _LOGGER.warning("Coordinator has a malformed configured OPNsense Router Unique ID")
            self._mismatched_count = 0
            return False
        if not is_valid_device_id(runtime_device_id):
            _LOGGER.warning("Coordinator received malformed OPNsense Router Unique ID. Will retry")
            self._mismatched_count = 0
            return False
        if runtime_device_id != self._device_unique_id:
            _LOGGER.debug(
                "[Coordinator async_update_data]: config device id: %s, router device id: %s",
                self._device_unique_id,
                runtime_device_id,
            )
            _LOGGER.error(
                "Coordinator error. "
                "OPNsense Router Device ID (%s) differs from the one saved in hass-opnsense (%s)",
                runtime_device_id,
                self._device_unique_id,
            )
            self._mismatched_count += 1
            # Trigger repair task and shutdown if this happens 3 times in a row
            if self._mismatched_count == 3:
                repair_issue_created = self.config_entry is not None and (
                    async_create_device_id_mismatch_issue(
                        self.hass,
                        self.config_entry,
                        runtime_device_id,
                    )
                )
                if repair_issue_created:
                    _LOGGER.error(
                        "OPNsense Device ID has changed which indicates new or changed hardware. "
                        "A fixable repair issue is available to rebuild entities for this "
                        "OPNsense device. "
                        "hass-opnsense is shutting down."
                    )
                await self.async_shutdown()
            return False
        config_entry = self.config_entry
        if config_entry is not None and not has_repair_marker(config_entry):
            ir.async_delete_issue(
                self.hass,
                DOMAIN,
                f"{config_entry.entry_id}_device_id_mismatched",
            )
        self._mismatched_count = 0
        return True

    async def _async_update_dt_data(self) -> dict[str, Any]:
        """Refresh the reduced state payload used by the device-tracker coordinator.

        Returns:
            dict[str, Any]: Refreshed device-tracker state, or an empty mapping on
                validation failure.
        """
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
        if not await self._check_device_unique_id():
            return {}
        restapi_count = await self._client.get_query_counts()
        _LOGGER.debug(
            "DT Update Complete. REST API Queries: %s",
            restapi_count,
        )
        return self._state

    async def _calculate_vpn_speeds(self, elapsed_time: float) -> None:
        """Calculate VPN byte-rate metrics for OpenVPN and WireGuard instances.

        Args:
            elapsed_time: Seconds between current and previous coordinator updates.
        """
        for vpn_type in ("openvpn", "wireguard"):
            cs = ["servers"]
            if vpn_type == "wireguard":
                cs = ["clients", "servers"]
            for clients_servers in cs:
                instances = dict_get(self._state, f"{vpn_type}.{clients_servers}", {}) or {}
                if not isinstance(instances, Mapping):
                    continue
                for instance_name, instance in instances.items():
                    if not isinstance(instance, MutableMapping):
                        continue
                    previous_clients_servers = dict_get(
                        self._state,
                        f"previous_state.{vpn_type}.{clients_servers}",
                        {},
                    )
                    if not isinstance(previous_clients_servers, MutableMapping):
                        continue

                    previous_instance = previous_clients_servers.get(instance_name)
                    if not isinstance(previous_instance, Mapping):
                        continue

                    for prop_name in (
                        "total_bytes_recv",
                        "total_bytes_sent",
                    ):
                        if prop_name not in instance or prop_name not in previous_instance:
                            continue
                        (
                            new_property,
                            value,
                        ) = await OPNsenseDataUpdateCoordinator._calculate_speed(
                            prop_name=prop_name,
                            elapsed_time=elapsed_time,
                            current_parent_value=instance[prop_name],
                            previous_parent_value=previous_instance[prop_name],
                        )

                        instance[new_property] = value

    async def _calculate_interface_speeds(self, elapsed_time: float) -> None:
        """Calculate interface packet/byte rate metrics from counter deltas.

        Args:
            elapsed_time: Seconds between current and previous coordinator updates.
        """
        interfaces = dict_get(self._state, "interfaces", {}) or {}
        if not isinstance(interfaces, Mapping):
            return
        for interface_name, interface in interfaces.items():
            if not isinstance(interface, MutableMapping):
                continue
            previous_interface = dict_get(
                self._state,
                f"previous_state.interfaces.{interface_name}",
            )
            if not isinstance(previous_interface, Mapping):
                continue

            for prop_name in (
                "inbytes",
                "outbytes",
                "inpkts",
                "outpkts",
            ):
                if prop_name not in interface or prop_name not in previous_interface:
                    continue
                (
                    new_property,
                    value,
                ) = await OPNsenseDataUpdateCoordinator._calculate_speed(
                    prop_name=prop_name,
                    elapsed_time=elapsed_time,
                    current_parent_value=interface[prop_name],
                    previous_parent_value=previous_interface[prop_name],
                )

                interface[new_property] = value

    async def _calculate_entity_speeds(self) -> None:
        """Populate derived speed metrics for enabled interface and VPN categories."""
        update_time = dict_get(self._state, "update_time")
        previous_update_time = dict_get(self._state, "previous_state.update_time")
        if not previous_update_time or not self.config_entry:
            return

        elapsed_time: float = update_time - previous_update_time
        config: Mapping[str, Any] = self.config_entry.data

        if config.get(CONF_SYNC_INTERFACES, DEFAULT_SYNC_OPTION_VALUE):
            await self._calculate_interface_speeds(elapsed_time=elapsed_time)

        if config.get(CONF_SYNC_VPN, DEFAULT_SYNC_OPTION_VALUE):
            await self._calculate_vpn_speeds(elapsed_time=elapsed_time)

    async def _async_update_data(self) -> dict[str, Any]:
        """Perform one coordinator refresh cycle.

        Returns:
            dict[str, Any]: Latest coordinator state payload for entities.
        """
        if self._updating:
            _LOGGER.warning(
                "Skipping %supdate because the previous update is still in progress",
                "DT " if self._device_tracker_coordinator else "",
            )
            return self._state
        self._updating = True

        try:
            _LOGGER.info(
                "%sUpdating Data",
                "DT " if self._device_tracker_coordinator else "",
            )
            await self._client.reset_query_counts()

            previous_state: dict[str, Any] = self._build_previous_state_snapshot()

            # ensure clean state each interval
            self._state = {}
            self._categories = self._build_categories()
            self._state["update_time"] = time.time()
            self._state["previous_state"] = previous_state

            if self._device_tracker_coordinator:
                return await self._async_update_dt_data()

            self._state.update(await self._get_states(self._categories))

            if not await self._check_device_unique_id():
                return {}

            await self._calculate_entity_speeds()

            restapi_count = await self._client.get_query_counts()
            _LOGGER.debug(
                "Update Complete. REST API Queries: %s",
                restapi_count,
            )
            return self._state
        finally:
            self._updating = False

    @staticmethod
    async def _calculate_speed(
        prop_name: str,
        elapsed_time: float,
        current_parent_value: float,
        previous_parent_value: float,
    ) -> tuple[str, int]:
        """Calculate a rounded per-second rate and derived metric name.

        Args:
            prop_name: Counter property name, such as `inbytes` or `inpkts`.
            elapsed_time: Seconds elapsed between counter samples.
            current_parent_value: Current counter value.
            previous_parent_value: Previous counter value.

        Returns:
            tuple[str, int]: Tuple of derived property name and rounded rate value.
        """
        rate = 0.0
        try:
            if elapsed_time <= 0:
                rate = 0
            else:
                change: float = current_parent_value - previous_parent_value
                rate = max(change, 0) / elapsed_time
        except TypeError, ZeroDivisionError:
            rate = 0

        value: float = 0
        if "pkts" in prop_name:
            label = "packets_per_second"
            value = rate
        elif "bytes" in prop_name:
            label = "kilobytes_per_second"
            value = rate / 1000
        new_property: str = f"{prop_name}_{label}"
        value = round(value)
        return new_property, value
