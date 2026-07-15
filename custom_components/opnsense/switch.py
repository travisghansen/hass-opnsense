"""OPNsense integration."""

from collections.abc import Callable, Mapping, MutableMapping
import logging
from typing import Any

from homeassistant.components.switch import SwitchDeviceClass, SwitchEntity, SwitchEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_call_later

from .const import (
    ATTR_UNBOUND_BLOCKLIST,
    CONF_SYNC_CARP,
    CONF_SYNC_FIREWALL_AND_NAT,
    CONF_SYNC_SERVICES,
    CONF_SYNC_UNBOUND,
    CONF_SYNC_VPN,
    COORDINATOR,
    DEFAULT_SYNC_OPTION_VALUE,
)
from .coordinator import OPNsenseDataUpdateCoordinator
from .entity import OPNsenseEntity
from .helpers import coerce_bool, dict_get, firewall_rule_id_from_payload

_LOGGER: logging.Logger = logging.getLogger(__name__)


def _create_switch[EntityT: OPNsenseSwitch](
    entity_cls: type[EntityT],
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    entity_description: SwitchEntityDescription,
) -> EntityT:
    """Create a switch entity from a description.

    Args:
        entity_cls: Switch entity class to instantiate.
        config_entry: Config entry owning the entity.
        coordinator: Shared OPNsense data coordinator.
        entity_description: Description that defines the entity identity.

    Returns:
        A configured switch entity instance.
    """
    return entity_cls(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=entity_description,
    )


def _build_service_switch_description(service: Mapping[str, Any]) -> SwitchEntityDescription:
    """Build the service switch description.

    Args:
        service: Service record from the OPNsense state payload.

    Returns:
        A switch entity description for the service status toggle.
    """
    prop_name = "status"
    service_id = service.get("id", service.get("name", "unknown"))
    service_name = service.get("description", service.get("name", "Unknown"))
    return SwitchEntityDescription(
        key=f"service.{service_id}.{prop_name}",
        name=f"Service {service_name} {prop_name}",
        icon="mdi:application-cog-outline",
        device_class=SwitchDeviceClass.SWITCH,
        entity_registry_enabled_default=False,
    )


def _build_vpn_switch_description(
    vpn_type: str,
    clients_servers: str,
    uuid: str,
    instance: Mapping[str, Any],
) -> SwitchEntityDescription:
    """Build the VPN switch description.

    Args:
        vpn_type: VPN family name, such as ``openvpn`` or ``wireguard``.
        clients_servers: Section name identifying clients or servers.
        uuid: Unique instance identifier from OPNsense.
        instance: Instance metadata used to build the display name.

    Returns:
        A switch entity description for the VPN instance.
    """
    instance_name = OPNsenseEntity.payload_display_name(
        instance,
        str(uuid),
        "name",
        "description",
        allow_scalar=False,
    )
    return SwitchEntityDescription(
        key=f"{vpn_type}.{clients_servers}.{uuid}",
        name=(
            f"{'OpenVPN' if vpn_type == 'openvpn' else vpn_type.title()} "
            f"{clients_servers.title().rstrip('s')} {instance_name}"
        ),
        icon="mdi:folder-key-network-outline",
        device_class=SwitchDeviceClass.SWITCH,
        entity_registry_enabled_default=False,
    )


def _build_carp_maintenance_switch_description() -> SwitchEntityDescription:
    """Build the CARP maintenance switch description.

    Returns:
        A switch entity description for CARP persistent maintenance mode.
    """
    return SwitchEntityDescription(
        key="carp.maintenance_mode",
        name="CARP Persistent Maintenance Mode",
        icon="mdi:server-network",
        device_class=SwitchDeviceClass.SWITCH,
        entity_registry_enabled_default=False,
    )


def _build_unbound_legacy_switch_description() -> SwitchEntityDescription:
    """Build the legacy Unbound blocklist switch description.

    Returns:
        A switch entity description for the legacy Unbound blocklist toggle.
    """
    return SwitchEntityDescription(
        key="unbound_blocklist.switch",
        name="Unbound Blocklist Switch",
        device_class=SwitchDeviceClass.SWITCH,
        entity_registry_enabled_default=False,
    )


def _build_unbound_switch_description(
    uuid: str, dnsbl: Mapping[str, Any]
) -> SwitchEntityDescription:
    """Build an extended Unbound blocklist switch description.

    Args:
        uuid: DNSBL identifier from OPNsense.
        dnsbl: DNSBL rule data used for naming.

    Returns:
        A switch entity description for the DNSBL rule.
    """
    return SwitchEntityDescription(
        key=f"unbound_blocklist.switch.{uuid}",
        name=f"Unbound Blocklist {dnsbl.get('description', 'Unknown')}",
        icon="mdi:folder-key-network-outline",
        device_class=SwitchDeviceClass.SWITCH,
        entity_registry_enabled_default=False,
    )


def _build_firewall_rule_switch_description(
    rule_id: str,
    rule: Mapping[str, Any],
) -> SwitchEntityDescription:
    """Build the firewall rule switch description.

    Args:
        rule_id: Firewall rule identifier used for entity identity and toggling.
        rule: Firewall rule data from the OPNsense payload.

    Returns:
        A switch entity description for the firewall rule toggle.
    """
    interface = rule.get("%interface", rule.get("interface", ""))
    if not isinstance(interface, str):
        interface = ""
    if "," in interface or interface == "":
        interface = "Floating"
    return SwitchEntityDescription(
        key=f"firewall.rule.{rule_id}",
        name=f"Firewall: {interface}: {rule.get('description', 'unknown')}",
        icon="mdi:play-network-outline",
        device_class=SwitchDeviceClass.SWITCH,
        entity_registry_enabled_default=False,
    )


def _build_nat_rule_switch_description(
    nat_rule_type: str,
    name_prefix: str,
    rule: Mapping[str, Any],
    rule_id: str,
) -> SwitchEntityDescription:
    """Build a NAT rule switch description.

    Args:
        nat_rule_type: NAT section name such as ``source_nat`` or ``d_nat``.
        name_prefix: Human-readable prefix for the entity name.
        rule: NAT rule data from the OPNsense payload.
        rule_id: NAT rule identifier used for entity identity and toggling.

    Returns:
        A switch entity description for the NAT rule toggle.
    """
    return SwitchEntityDescription(
        key=f"firewall.nat.{nat_rule_type}.{rule_id}",
        name=f"{name_prefix}: {rule.get('%interface', '')}: {rule.get('description', 'unknown')}",
        icon="mdi:network-outline",
        device_class=SwitchDeviceClass.SWITCH,
        entity_registry_enabled_default=False,
    )


async def _compile_service_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile service switches from OPNsense state.

    Args:
        config_entry: The Home Assistant config entry.
        coordinator: The data update coordinator.
        state: The current state data from OPNsense.

    Returns:
        list: A list of OPNsenseServiceSwitch entities.
    """
    if not isinstance(state, MutableMapping) or not isinstance(state.get("services"), list):
        return []

    entities: list = []
    for service in state.get("services", []):
        if not isinstance(service, Mapping):
            continue
        if service.get("locked", 1) == 1:
            continue
        entities.append(
            _create_switch(
                OPNsenseServiceSwitch,
                config_entry,
                coordinator,
                _build_service_switch_description(service),
            )
        )
    return entities


async def _compile_vpn_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile VPN switches from OPNsense state.

    Args:
        config_entry: The Home Assistant config entry.
        coordinator: The data update coordinator.
        state: The current state data from OPNsense.

    Returns:
        list: A list of OPNsenseVPNSwitch entities.
    """
    entities: list = []
    for vpn_type in ("openvpn", "wireguard"):
        for clients_servers in ("clients", "servers"):
            if not isinstance(state, MutableMapping):
                return []
            vpn_instances = dict_get(state, f"{vpn_type}.{clients_servers}", {}) or {}
            if not isinstance(vpn_instances, MutableMapping):
                continue
            for uuid, instance in vpn_instances.items():
                if (
                    not isinstance(instance, MutableMapping)
                    or instance.get("enabled", None) is None
                ):
                    continue

                entities.append(
                    _create_switch(
                        OPNsenseVPNSwitch,
                        config_entry,
                        coordinator,
                        _build_vpn_switch_description(vpn_type, clients_servers, uuid, instance),
                    )
                )
    return entities


async def _compile_carp_maintenance_switch(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile the CARP persistent maintenance mode switch.

    Args:
        config_entry: The Home Assistant config entry.
        coordinator: The data update coordinator.
        state: The current state data from OPNsense.

    Returns:
        list: A list containing one OPNsenseCarpMaintenanceSwitch entity when
            CARP summary data is available.
    """
    status_summary = dict_get(state, "carp.status_summary")
    if not isinstance(status_summary, MutableMapping):
        return []

    return [
        _create_switch(
            OPNsenseCarpMaintenanceSwitch,
            config_entry,
            coordinator,
            _build_carp_maintenance_switch_description(),
        )
    ]


async def _compile_unbound_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile Unbound blocklist switches from OPNsense state.

    Args:
        config_entry: The Home Assistant config entry.
        coordinator: The data update coordinator.
        state: The current state data from OPNsense.

    Returns:
        list: A list of legacy or extended OPNsense unbound blocklist switch entities.
    """
    if not isinstance(state, MutableMapping):
        return []
    unbound_blocklist = state.get(ATTR_UNBOUND_BLOCKLIST)
    if not isinstance(unbound_blocklist, MutableMapping):
        return []

    entities: list = []
    if isinstance(unbound_blocklist.get("legacy"), MutableMapping):
        entities.append(
            _create_switch(
                OPNsenseUnboundBlocklistSwitchLegacy,
                config_entry,
                coordinator,
                _build_unbound_legacy_switch_description(),
            )
        )

    for uuid, dnsbl in unbound_blocklist.items():
        if uuid == "legacy":
            continue
        if not isinstance(dnsbl, MutableMapping):
            continue

        entities.append(
            _create_switch(
                OPNsenseUnboundBlocklistSwitch,
                config_entry,
                coordinator,
                _build_unbound_switch_description(uuid, dnsbl),
            )
        )

    return entities


async def _compile_firewall_rules_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile firewall rule switches from OPNsense state.

    Args:
        config_entry: The Home Assistant config entry.
        coordinator: The data update coordinator.
        state: The current state data from OPNsense.

    Returns:
        list: A list of OPNsenseFirewallRuleSwitch entities.
    """
    rules = dict_get(state, "firewall.rules")
    if not isinstance(rules, MutableMapping):
        return []

    entities: list = []
    for rule_key, rule in rules.items():
        if not isinstance(rule, MutableMapping):
            continue
        rule_id = firewall_rule_id_from_payload(rule_key, rule)
        if not rule_id:
            continue
        interface = rule.get("%interface", rule.get("interface", ""))
        if not isinstance(interface, str):
            continue
        entities.append(
            _create_switch(
                OPNsenseFirewallRuleSwitch,
                config_entry,
                coordinator,
                _build_firewall_rule_switch_description(rule_id, rule),
            )
        )
    return entities


async def _compile_nat_rule_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
    nat_rule_type: str,
    name_prefix: str,
) -> list:
    """Compile NAT rule switches from OPNsense state.

    Args:
        config_entry: Config entry owning the entities.
        coordinator: Shared OPNsense data coordinator.
        state: Current OPNsense state payload.
        nat_rule_type: NAT section name such as ``source_nat`` or ``d_nat``.
        name_prefix: Human-readable prefix for the generated entities.

    Returns:
        A list of NAT rule switch entities.
    """
    rules = dict_get(state, f"firewall.nat.{nat_rule_type}")
    if not isinstance(rules, MutableMapping):
        return []

    entities: list = []
    for rule_key, rule in rules.items():
        if not isinstance(rule, MutableMapping):
            continue
        rule_id = firewall_rule_id_from_payload(rule_key, rule)
        if not rule_id:
            continue
        interface = rule.get("%interface", rule.get("interface", ""))
        if not isinstance(interface, str):
            continue
        entities.append(
            _create_switch(
                OPNsenseNATRuleSwitch,
                config_entry,
                coordinator,
                _build_nat_rule_switch_description(nat_rule_type, name_prefix, rule, rule_id),
            )
        )
    return entities


async def _compile_nat_source_rules_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile NAT source rule switches from OPNsense state.

    Args:
        config_entry: The Home Assistant config entry.
        coordinator: The data update coordinator.
        state: The current state data from OPNsense.

    Returns:
        list: A list of OPNsenseNATRuleSwitch entities for source NAT rules.
    """
    return await _compile_nat_rule_switches(
        config_entry, coordinator, state, "source_nat", "NAT Source"
    )


async def _compile_nat_destination_rules_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile NAT destination rule switches from OPNsense state.

    Args:
        config_entry: The Home Assistant config entry.
        coordinator: The data update coordinator.
        state: The current state data from OPNsense.

    Returns:
        list: A list of OPNsenseNATRuleSwitch entities for destination NAT rules.
    """
    return await _compile_nat_rule_switches(
        config_entry, coordinator, state, "d_nat", "NAT Destination"
    )


async def _compile_nat_one_to_one_rules_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile NAT one-to-one rule switches from OPNsense state.

    Args:
        config_entry: The Home Assistant config entry.
        coordinator: The data update coordinator.
        state: The current state data from OPNsense.

    Returns:
        list: A list of OPNsenseNATRuleSwitch entities for one-to-one NAT rules.
    """
    return await _compile_nat_rule_switches(
        config_entry, coordinator, state, "one_to_one", "NAT One to One"
    )


async def _compile_nat_npt_rules_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile NAT NPTv6 rule switches from OPNsense state.

    Args:
        config_entry: The Home Assistant config entry.
        coordinator: The data update coordinator.
        state: The current state data from OPNsense.

    Returns:
        list: A list of OPNsenseNATRuleSwitch entities for NPTv6 NAT rules.
    """
    return await _compile_nat_rule_switches(config_entry, coordinator, state, "npt", "NAT NPTv6")


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the OPNsense switches.

    Args:
        hass: The Home Assistant instance.
        config_entry: The config entry for this integration.
        async_add_entities: Callback to add entities to Home Assistant.
    """
    coordinator: OPNsenseDataUpdateCoordinator = getattr(config_entry.runtime_data, COORDINATOR)
    state: dict[str, Any] = coordinator.data
    if not isinstance(state, MutableMapping):
        _LOGGER.error("Missing state data in switch async_setup_entry")
        return
    config: Mapping[str, Any] = config_entry.data

    entities: list = []

    if config.get(CONF_SYNC_FIREWALL_AND_NAT, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_firewall_rules_switches(config_entry, coordinator, state))
        entities.extend(await _compile_nat_source_rules_switches(config_entry, coordinator, state))
        entities.extend(
            await _compile_nat_destination_rules_switches(config_entry, coordinator, state)
        )
        entities.extend(
            await _compile_nat_one_to_one_rules_switches(config_entry, coordinator, state)
        )
        entities.extend(await _compile_nat_npt_rules_switches(config_entry, coordinator, state))
    if config.get(CONF_SYNC_SERVICES, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_service_switches(config_entry, coordinator, state))
    if config.get(CONF_SYNC_VPN, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_vpn_switches(config_entry, coordinator, state))
    if config.get(CONF_SYNC_CARP, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_carp_maintenance_switch(config_entry, coordinator, state))
    if config.get(CONF_SYNC_UNBOUND, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_unbound_switches(config_entry, coordinator, state))

    _LOGGER.debug("[switch async_setup_entry] entities: %s", len(entities))
    async_add_entities(entities)


class OPNsenseSwitch(OPNsenseEntity, SwitchEntity):
    """Class for OPNsense Switch entities."""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        """Initialize OPNsense Switch entities.

        Args:
            config_entry: The Home Assistant config entry.
            coordinator: The data update coordinator.
            entity_description: The entity description.
        """
        name_suffix: str | None = (
            entity_description.name if isinstance(entity_description.name, str) else None
        )
        unique_id_suffix: str | None = (
            entity_description.key if isinstance(entity_description.key, str) else None
        )
        super().__init__(
            config_entry,
            coordinator,
            unique_id_suffix=unique_id_suffix,
            name_suffix=name_suffix,
        )
        self.entity_description = entity_description
        self._attr_is_on: bool = False
        self._delay_seconds: int = 10
        self._delay_update: bool = False
        self._delay_update_remove: Callable[[], None] | None = None

    @property
    def delay_update(self) -> bool:
        """Return whether to process the coordinator update or not.

        Returns:
            bool: True if updates should be delayed, False otherwise.
        """
        return self._delay_update

    @delay_update.setter
    def delay_update(self, value: bool) -> None:
        """Set whether to delay coordinator updates.

        Args:
            value: True to delay updates, False to allow them.
        """
        if value and not self._delay_update:
            self._delay_update = True
            self._reset_delay()
        elif not value:
            self._delay_update = False
            if self._delay_update_remove:
                self._delay_update_remove()
                self._delay_update_remove = None

    def _reset_delay(self) -> None:
        """Reset the delay timer for coordinator updates."""
        if self._delay_update_remove:
            self._delay_update_remove()

        def _clear(_: Any) -> None:
            """Clear the update delay after the timer fires.

            Args:
                _: Timer callback timestamp, unused.
            """
            self._delay_update = False
            self._delay_update_remove = None

        self._delay_update_remove = async_call_later(
            hass=self.hass, delay=self._delay_seconds, action=_clear
        )


class OPNsenseCarpMaintenanceSwitch(OPNsenseSwitch):
    """Class for the CARP persistent maintenance mode switch."""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        """Initialize CARP maintenance switch state.

        Args:
            config_entry: Config entry owning the entity.
            coordinator: Shared OPNsense data coordinator.
            entity_description: Description that defines the entity identity.
        """
        super().__init__(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=entity_description,
        )
        self._toggle_in_flight: bool = False

    def _opnsense_get_status_summary(self) -> MutableMapping[str, Any] | None:
        """Get the CARP status summary from the coordinator.

        Returns:
            MutableMapping[str, Any] | None: The CARP status summary if available.
        """
        state: dict[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            return None
        status_summary = dict_get(state, "carp.status_summary")
        if not isinstance(status_summary, MutableMapping):
            return None
        return status_summary

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update for the CARP maintenance switch."""
        if self.delay_update:
            _LOGGER.debug("Skipping coordinator update for CARP switch %s due to delay", self.name)
            return
        status_summary = self._opnsense_get_status_summary()
        if status_summary is None:
            self._available = False
            self._attr_extra_state_attributes = {}
            self.async_write_ha_state()
            return

        state = status_summary.get("state")
        maintenance_mode = coerce_bool(status_summary.get("maintenance_mode"))
        if (isinstance(state, str) and state.lower() in {"unknown", "unavailable"}) or (
            maintenance_mode is None
        ):
            self._available = False
            self._attr_is_on = False
            self._attr_extra_state_attributes = {}
            self.async_write_ha_state()
            return

        self._attr_is_on = maintenance_mode
        self._available = True
        self._attr_extra_state_attributes = {
            "state": status_summary.get("state"),
            "enabled": status_summary.get("enabled"),
            "demotion": status_summary.get("demotion"),
            "status_message": status_summary.get("status_message"),
            "vip_count": status_summary.get("vip_count"),
            "master_count": status_summary.get("master_count"),
            "backup_count": status_summary.get("backup_count"),
            "other_count": status_summary.get("other_count"),
            "interfaces": status_summary.get("interfaces"),
        }
        self.async_write_ha_state()

    async def _async_refresh_carp_state(self) -> None:
        """Refresh CARP state before deciding whether the toggle endpoint is needed."""
        self.delay_update = False
        await self.coordinator.async_request_refresh()
        self._handle_coordinator_update()

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn CARP persistent maintenance mode on.

        Args:
            **kwargs: Additional keyword arguments from Home Assistant.
        """
        if self._toggle_in_flight:
            return
        if self.delay_update:
            return
        if self._client is None or not hasattr(self._client, "toggle_carp_maintenance_mode"):
            return
        self._toggle_in_flight = True
        try:
            await self._async_refresh_carp_state()
            if not self.available or self.is_on:
                return
            result = await self._client.toggle_carp_maintenance_mode()
            if result:
                _LOGGER.info("Turned on CARP persistent maintenance mode")
                self._attr_is_on = True
                self.async_write_ha_state()
                self.delay_update = True
            else:
                _LOGGER.error("Failed to turn on CARP persistent maintenance mode")
        finally:
            self._toggle_in_flight = False

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn CARP persistent maintenance mode off.

        Args:
            **kwargs: Additional keyword arguments from Home Assistant.
        """
        if self._toggle_in_flight:
            return
        if self.delay_update:
            return
        if self._client is None or not hasattr(self._client, "toggle_carp_maintenance_mode"):
            return
        self._toggle_in_flight = True
        try:
            await self._async_refresh_carp_state()
            if not self.available or not self.is_on:
                return
            result = await self._client.toggle_carp_maintenance_mode()
            if result:
                _LOGGER.info("Turned off CARP persistent maintenance mode")
                self._attr_is_on = False
                self.async_write_ha_state()
                self.delay_update = True
            else:
                _LOGGER.error("Failed to turn off CARP persistent maintenance mode")
        finally:
            self._toggle_in_flight = False

    @property
    def icon(self) -> str | None:
        """Return the icon for the entity.

        Returns:
            Icon name for the entity, or the base icon when inactive.
        """
        if self.available and self.is_on:
            return "mdi:server-network-off"
        return super().icon


class OPNsenseFirewallRuleSwitch(OPNsenseSwitch):
    """Class for OPNsense Firewall Rule Switch entities."""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        """Initialize switch entity.

        Args:
            config_entry: The Home Assistant config entry.
            coordinator: The data update coordinator.
            entity_description: The entity description.
        """
        super().__init__(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=entity_description,
        )
        self._rule_id: str = self._opnsense_get_rule_id()

    def _opnsense_get_rule_id(self) -> str:
        """Get the rule ID from the entity description.

        Returns:
            str: The rule ID.
        """
        return self.entity_description.key.split(".")[-1]

    def _opnsense_get_rule(self) -> MutableMapping[str, Any] | None:
        """Get the firewall rule data from the coordinator.

        Returns:
            MutableMapping[str, Any] | None: The rule data if available, None otherwise.
        """
        rules = self._mapping_at("firewall.rules")
        if rules is None:
            return None
        rule = rules.get(self._rule_id)
        return rule if isinstance(rule, MutableMapping) else None

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update for the firewall rule switch."""
        if self.delay_update:
            _LOGGER.debug(
                "Skipping coordinator update for firewall rule switch %s due to delay", self.name
            )
            return
        rule = self._opnsense_get_rule()
        if not rule:
            self._mark_unavailable()
            return
        try:
            self._attr_is_on = bool(rule.get("enabled", "1") == "1")
        except TypeError, KeyError, AttributeError:
            self._mark_unavailable()
            return
        self._available = True
        self._attr_extra_state_attributes = {}
        properties: dict[str, str] = {
            "description": "description",
            "categories": "categories",
            "state": "%statetype",
            "action": "%action",
            "direction": "%direction",
            "interfaces": "%interface",
            "version": "%ipprotocol",
            "protocol": "protocol",
            "source": "source_net",
            "source_port": "source_port",
            "destination": "destination_net",
            "destination_port": "destination_port",
            "gateway": "gateway",
        }
        for name, attr in properties.items():
            self._attr_extra_state_attributes[name] = rule.get(attr, None)
        self.async_write_ha_state()

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the entity on.

        Args:
            **kwargs: Additional keyword arguments from Home Assistant.
        """
        if self._rule_id is None or not self._client:
            return
        result = await self._client.toggle_firewall_rule(self._rule_id, "on")
        if result:
            _LOGGER.info("Turned on firewall rule: %s", self.name)
            self._attr_is_on = True
            self.async_write_ha_state()
            self.delay_update = True
        else:
            _LOGGER.error("Failed to turn on firewall rule: %s", self.name)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the entity off.

        Args:
            **kwargs: Additional keyword arguments from Home Assistant.
        """
        if self._rule_id is None or not self._client:
            return
        result = await self._client.toggle_firewall_rule(self._rule_id, "off")
        if result:
            _LOGGER.info("Turned off firewall rule: %s", self.name)
            self._attr_is_on = False
            self.async_write_ha_state()
            self.delay_update = True
        else:
            _LOGGER.error("Failed to turn off firewall rule: %s", self.name)

    @property
    def icon(self) -> str | None:
        """Return the icon for the entity.

        Returns:
            Icon name for the entity, or the base icon when inactive.
        """
        if self.available and self.is_on:
            return "mdi:play-network"
        return super().icon


class OPNsenseNATRuleSwitch(OPNsenseSwitch):
    """Class for OPNsense NAT Rule Switch entities."""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        """Initialize switch entity.

        Args:
            config_entry: The Home Assistant config entry.
            coordinator: The data update coordinator.
            entity_description: The entity description.
        """
        super().__init__(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=entity_description,
        )
        self._rule_id: str = self._opnsense_get_rule_id()
        self._nat_rule_type: str = self._get_nat_rule_type()

    def _get_nat_rule_type(self) -> str:
        """Get the NAT rule type from the entity description.

        Returns:
            str: The NAT rule type.
        """
        return self.entity_description.key.split(".")[2]

    def _opnsense_get_rule_id(self) -> str:
        """Get the rule ID from the entity description.

        Returns:
            str: The rule ID.
        """
        parts = self.entity_description.key.split(".", maxsplit=3)
        if len(parts) == 4:
            return parts[3]
        return self.entity_description.key.rsplit(".", maxsplit=1)[-1]

    def _opnsense_get_rule(self) -> MutableMapping[str, Any] | None:
        """Get the NAT rule data from the coordinator.

        Returns:
            MutableMapping[str, Any] | None: The rule data if available, None otherwise.
        """
        rules = self._mapping_at(f"firewall.nat.{self._nat_rule_type}")
        if rules is None:
            return None
        rule = rules.get(self._rule_id)
        return rule if isinstance(rule, MutableMapping) else None

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update for the NAT rule switch."""
        if self.delay_update:
            _LOGGER.debug("Skipping coordinator update for NAT switch %s due to delay", self.name)
            return
        rule = self._opnsense_get_rule()
        if not rule:
            self._mark_unavailable()
            return
        try:
            self._attr_is_on = bool(rule.get("enabled", "1") == "1")
        except TypeError, KeyError, AttributeError:
            self._mark_unavailable()
            return
        self._available = True
        self._attr_extra_state_attributes = {}
        properties: dict[str, str] = {
            "description": "description",
            "categories": "categories",
            "interface": "%interface",
        }
        match self._nat_rule_type:
            case "d_nat":
                properties.update(
                    {
                        "version": "%ipprotocol",
                        "protocol": "%protocol",
                        "source": "source.network",
                        "source_port": "source.port",
                        "destination": "destination.%network",
                        "destination_port": "destination.port",
                        "redirect_target": "target",
                        "redirect_target_port": "local-port",
                    }
                )
            case "source_nat":
                properties.update(
                    {
                        "version": "%ipprotocol",
                        "protocol": "protocol",
                        "source": "source_net",
                        "source_port": "source_port",
                        "destination": "destination_net",
                        "destination_port": "destination_port",
                        "translate_source": "%target",
                        "translate_source_port": "target_port",
                    }
                )
            case "one_to_one":
                properties.update(
                    {
                        "type": "%type",
                        "external_network": "external",
                        "source": "source_net",
                        "destination": "destination_net",
                    }
                )
            case "npt":
                properties.update(
                    {
                        "internal_ipv6_prefix": "source_net",
                        "external_ipv6_prefix": "destination_net",
                        "track_interface": "trackif",
                    }
                )
        for name, attr in properties.items():
            self._attr_extra_state_attributes[name] = rule.get(attr, None)

        self.async_write_ha_state()

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the entity on.

        Args:
            **kwargs: Additional keyword arguments from Home Assistant.
        """
        if self._rule_id is None or not self._client:
            return
        result = await self._client.toggle_nat_rule(self._nat_rule_type, self._rule_id, "on")
        if result:
            _LOGGER.info("Turned on NAT rule: %s", self.name)
            self._attr_is_on = True
            self.async_write_ha_state()
            self.delay_update = True
        else:
            _LOGGER.error("Failed to turn on NAT rule: %s", self.name)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the entity off.

        Args:
            **kwargs: Additional keyword arguments from Home Assistant.
        """
        if self._rule_id is None or not self._client:
            return
        result = await self._client.toggle_nat_rule(self._nat_rule_type, self._rule_id, "off")
        if result:
            _LOGGER.info("Turned off NAT rule: %s", self.name)
            self._attr_is_on = False
            self.async_write_ha_state()
            self.delay_update = True
        else:
            _LOGGER.error("Failed to turn off NAT rule: %s", self.name)

    @property
    def icon(self) -> str | None:
        """Return the icon for the entity.

        Returns:
            Icon name for the entity, or the base icon when inactive.
        """
        if self.available and self.is_on:
            return "mdi:network"
        return super().icon


class OPNsenseServiceSwitch(OPNsenseSwitch):
    """Class for OPNsense Service Switch entities."""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        """Initialize switch entity.

        Args:
            config_entry: The Home Assistant config entry.
            coordinator: The data update coordinator.
            entity_description: The entity description.
        """
        super().__init__(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=entity_description,
        )
        self._service: MutableMapping[str, Any] | None = None
        self._prop_name: str = self._opnsense_get_property_name()

    def _opnsense_get_property_name(self) -> str:
        """Get the property name from the entity description.

        Returns:
            str: The property name.
        """
        return self.entity_description.key.split(".")[2]

    def _opnsense_get_service_id(self) -> str:
        """Get the service ID from the entity description.

        Returns:
            str: The service ID.
        """
        return self.entity_description.key.split(".")[1]

    def _opnsense_get_service(self) -> MutableMapping[str, Any] | None:
        """Get the service data from the coordinator.

        Returns:
            MutableMapping[str, Any] | None: The service data if available, None otherwise.
        """
        state = self._coordinator_mapping()
        if state is None:
            return None
        service_id: str = self._opnsense_get_service_id()
        services = state.get("services")
        if not isinstance(services, list):
            return None
        for service in services:
            if not isinstance(service, MutableMapping):
                continue
            if service.get("id", None) == service_id:
                return service
        return None

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update for the service switch."""
        if self.delay_update:
            _LOGGER.debug(
                "Skipping coordinator update for service switch %s due to delay", self.name
            )
            return
        self._service = self._opnsense_get_service()
        if not isinstance(self._service, MutableMapping):
            self._mark_unavailable()
            return
        try:
            self._attr_is_on = self._service[self._prop_name]
        except TypeError, KeyError, AttributeError:
            self._mark_unavailable()
            return
        self._available = True
        self._attr_extra_state_attributes = {}
        for attr in ("id", "name"):
            self._attr_extra_state_attributes[f"service_{attr}"] = self._service.get(attr, None)
        self.async_write_ha_state()

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the entity on.

        Args:
            **kwargs: Additional keyword arguments from Home Assistant.
        """
        if not isinstance(self._service, MutableMapping) or not self._client:
            return

        result: bool = await self._client.start_service(
            self._service.get("id", self._service.get("name", None))
        )
        if result:
            _LOGGER.info("Turned on service: %s", self.name)
            self._attr_is_on = True
            self.async_write_ha_state()
            self.delay_update = True
        else:
            _LOGGER.error("Failed to turn on service: %s", self.name)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the entity off.

        Args:
            **kwargs: Additional keyword arguments from Home Assistant.
        """
        if not isinstance(self._service, MutableMapping) or not self._client:
            return

        result: bool = await self._client.stop_service(
            self._service.get("id", self._service.get("name", None))
        )
        if result:
            _LOGGER.info("Turned off service: %s", self.name)
            self._attr_is_on = False
            self.async_write_ha_state()
            self.delay_update = True
        else:
            _LOGGER.error("Failed to turn off service: %s", self.name)

    @property
    def icon(self) -> str | None:
        """Return the icon for the entity.

        Returns:
            Icon name for the entity, or the base icon when inactive.
        """
        if self.available and self.is_on:
            return "mdi:application-cog"
        return super().icon


class OPNsenseUnboundBlocklistSwitchLegacy(OPNsenseSwitch):
    """Class for legacy OPNsense Unbound Blocklist Switch entity."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if self.delay_update:
            _LOGGER.debug(
                "Skipping coordinator update for unbound blocklist switch %s due to delay",
                self.name,
            )
            return
        dnsbl = self._mapping_at(f"{ATTR_UNBOUND_BLOCKLIST}.legacy")
        if not isinstance(dnsbl, MutableMapping) or len(dnsbl) == 0:
            self._mark_unavailable()
            return
        self._available = True
        self._attr_is_on = dnsbl.get("enabled", "0") == "1"
        self._attr_extra_state_attributes: dict[str, Any] = {
            "Force SafeSearch": bool(dnsbl.get("safesearch", "0") == "1"),
            "Type of DNSBL": dnsbl.get("type", ""),
            "URLs of Blocklists": dnsbl.get("lists", ""),
            "Whitelist Domains": dnsbl.get("whitelists", ""),
            "Blocklist Domains": dnsbl.get("blocklists", ""),
            "Wildcard Domains": dnsbl.get("wildcards", ""),
            "Destination Address": dnsbl.get("address", ""),
            "Return NXDOMAIN": bool(dnsbl.get("nxdomain", "0") == "1"),
        }
        self.async_write_ha_state()

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the entity on.

        Args:
            **kwargs: Additional keyword arguments from Home Assistant.
        """
        if not self._client:
            return
        result: bool = await self._client.enable_unbound_blocklist()
        if result:
            _LOGGER.info("Turned on Unbound Blocklist: %s", self.name)
            self._attr_is_on = True
            self.async_write_ha_state()
            self.delay_update = True
        else:
            _LOGGER.error("Failed to turn on Unbound Blocklist: %s", self.name)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the entity off.

        Args:
            **kwargs: Additional keyword arguments from Home Assistant.
        """
        if not self._client:
            return
        result: bool = await self._client.disable_unbound_blocklist()
        if result:
            _LOGGER.info("Turned off Unbound Blocklist: %s", self.name)
            self._attr_is_on = False
            self.async_write_ha_state()
            self.delay_update = True
        else:
            _LOGGER.error("Failed to turn off Unbound Blocklist: %s", self.name)


class OPNsenseUnboundBlocklistSwitch(OPNsenseSwitch):
    """Class for OPNsense Unbound Blocklist Switch entities."""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        """Initialize switch entity.

        Args:
            config_entry: The Home Assistant config entry.
            coordinator: The data update coordinator.
            entity_description: The entity description.
        """
        super().__init__(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=entity_description,
        )
        self._uuid = self.entity_description.key.split(".")[2]
        _LOGGER.debug("[OPNsenseUnboundBlocklistSwitch init] Name: %s", self.name)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if self.delay_update:
            _LOGGER.debug(
                "Skipping coordinator update for unbound blocklist switch %s due to delay",
                self.name,
            )
            return
        dnsbl = self._mapping_at(f"{ATTR_UNBOUND_BLOCKLIST}.{self._uuid}")
        if dnsbl is None or len(dnsbl) == 0:
            self._mark_unavailable()
            return
        self._available = True
        self._attr_is_on = dnsbl.get("enabled", "0") == "1"
        self._attr_extra_state_attributes: dict[str, Any] = {
            "Name": dnsbl.get("description", ""),
            "Type of DNSBL": dnsbl.get("%type", ""),
            "URLs of Blocklists": dnsbl.get("lists", ""),
            "Allowlist Domains": dnsbl.get("allowlists", ""),
            "Blocklist Domains": dnsbl.get("blocklists", ""),
            "Wildcard Domains": dnsbl.get("wildcards", ""),
            "Source Net(s)": dnsbl.get("source_nets", ""),
            "Destination Address": dnsbl.get("address", ""),
            "Return NXDOMAIN": bool(dnsbl.get("nxdomain", "0") == "1"),
        }
        self.async_write_ha_state()

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the entity on.

        Args:
            **kwargs: Additional keyword arguments from Home Assistant.
        """
        if not self._client:
            return
        result: bool = await self._client.enable_unbound_blocklist(self._uuid)
        if result:
            _LOGGER.info("Turned on Unbound Blocklist: %s", self.name)
            self._attr_is_on = True
            self.async_write_ha_state()
            self.delay_update = True
        else:
            _LOGGER.error("Failed to turn on Unbound Blocklist: %s", self.name)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the entity off.

        Args:
            **kwargs: Additional keyword arguments from Home Assistant.
        """
        if not self._client:
            return
        result: bool = await self._client.disable_unbound_blocklist(self._uuid)
        if result:
            _LOGGER.info("Turned off Unbound Blocklist: %s", self.name)
            self._attr_is_on = False
            self.async_write_ha_state()
            self.delay_update = True
        else:
            _LOGGER.error("Failed to turn off Unbound Blocklist: %s", self.name)


class OPNsenseVPNSwitch(OPNsenseSwitch):
    """Class for OPNsense VPN Switch entities."""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        """Initialize switch entity.

        Args:
            config_entry: The Home Assistant config entry.
            coordinator: The data update coordinator.
            entity_description: The entity description.
        """
        super().__init__(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=entity_description,
        )
        self._vpn_type = self.entity_description.key.split(".")[0]
        self._clients_servers = self.entity_description.key.split(".")[1]
        self._uuid = self.entity_description.key.split(".")[2]

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update for the VPN switch."""
        if self.delay_update:
            _LOGGER.debug("Skipping coordinator update for VPN switch %s due to delay", self.name)
            return
        vpn_instances = self._mapping_at(f"{self._vpn_type}.{self._clients_servers}")
        if vpn_instances is None:
            self._mark_unavailable()
            return
        instance = vpn_instances.get(self._uuid)
        if not isinstance(instance, MutableMapping):
            self._mark_unavailable()
            return
        try:
            self._attr_is_on = instance["enabled"]
        except TypeError, KeyError, AttributeError:
            self._mark_unavailable()
            return
        self._available = True
        self._attr_extra_state_attributes = {}
        if self._clients_servers == "servers":
            properties: list = [
                "uuid",
                "name",
                "status",
                "connected_clients",
                "endpoint",
                "interface",
                "dev_type",
                "pubkey",
                "tunnel_addresses",
                "dns_servers",
                "latest_handshake",
                "clients",
            ]
        elif self._clients_servers == "clients":
            properties = [
                "uuid",
                "name",
                "connected_servers",
                "endpoint",
                "interface",
                "pubkey",
                "tunnel_addresses",
                "latest_handshake",
                "servers",
            ]
        else:
            properties = ["uuid", "name"]

        for attr in properties:
            if instance.get(attr):
                self._attr_extra_state_attributes[attr] = instance.get(attr)
        self.async_write_ha_state()

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on the VPN switch.

        Args:
            **kwargs: Additional keyword arguments.
        """
        if self.is_on or not self._client:
            return

        result: bool = await self._client.toggle_vpn_instance(
            self._vpn_type, self._clients_servers, self._uuid
        )
        if result:
            _LOGGER.info("Turned on VPN: %s", self.name)
            self._attr_is_on = True
            self.async_write_ha_state()
            self.delay_update = True
        else:
            _LOGGER.error("Failed to turn on VPN: %s", self.name)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off the VPN switch.

        Args:
            **kwargs: Additional keyword arguments.
        """
        if not self.is_on or not self._client:
            return

        result: bool = await self._client.toggle_vpn_instance(
            self._vpn_type, self._clients_servers, self._uuid
        )
        if result:
            _LOGGER.info("Turned off VPN: %s", self.name)
            self._attr_is_on = False
            self.async_write_ha_state()
            self.delay_update = True
        else:
            _LOGGER.error("Failed to turn off VPN: %s", self.name)

    @property
    def icon(self) -> str | None:
        """Return the icon for the entity.

        Returns:
            Icon name for the entity, or the base icon when inactive.
        """
        if self.available and self.is_on:
            return "mdi:folder-key-network"
        return super().icon
