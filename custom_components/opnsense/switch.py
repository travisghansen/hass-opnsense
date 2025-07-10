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
    ATTR_NAT_OUTBOUND,
    ATTR_NAT_PORT_FORWARD,
    ATTR_UNBOUND_BLOCKLIST,
    CONF_SYNC_FILTERS_AND_NAT,
    CONF_SYNC_SERVICES,
    CONF_SYNC_UNBOUND,
    CONF_SYNC_VPN,
    COORDINATOR,
    DEFAULT_SYNC_OPTION_VALUE,
)
from .coordinator import OPNsenseDataUpdateCoordinator
from .entity import OPNsenseEntity
from .helpers import dict_get

_LOGGER: logging.Logger = logging.getLogger(__name__)


async def _compile_filter_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    if not isinstance(state, MutableMapping) or not isinstance(state.get("config"), MutableMapping):
        return []
    entities: list = []
    # filter rules
    if "filter" in state.get("config", {}):
        rules = dict_get(state, "config.filter.rule")
        if isinstance(rules, list):
            for rule in rules:
                if not isinstance(rule, dict):
                    continue

                # do NOT add rules that are NAT rules
                if "associated-rule-id" in rule:
                    continue

                # not possible to disable these rules
                if rule.get("descr", "") == "Anti-Lockout Rule":
                    continue

                tracker = dict_get(rule, "created.time")
                # we use tracker as the unique id
                if tracker is None or len(tracker) < 1:
                    continue

                entities.append(
                    OPNsenseFilterSwitch(
                        config_entry=config_entry,
                        coordinator=coordinator,
                        entity_description=SwitchEntityDescription(
                            key=f"filter.{tracker}",
                            name=f"Filter Rule {tracker} ({rule.get('descr', '')})",
                            icon="mdi:play-network-outline",
                            # entity_category=entity_category,
                            device_class=SwitchDeviceClass.SWITCH,
                            entity_registry_enabled_default=False,
                        ),
                    )
                )
    return entities


async def _compile_port_forward_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    if not isinstance(state, MutableMapping) or not isinstance(state.get("config"), MutableMapping):
        return []

    entities: list = []
    # nat port forward rules
    if "nat" in state.get("config", {}):
        rules = dict_get(state, "config.nat.rule")
        if isinstance(rules, list):
            for rule in rules:
                if not isinstance(rule, dict):
                    continue

                tracker = dict_get(rule, "created.time")
                # we use tracker as the unique id
                if tracker is None or len(tracker) < 1:
                    continue

                entity = OPNsenseNatSwitch(
                    config_entry=config_entry,
                    coordinator=coordinator,
                    entity_description=SwitchEntityDescription(
                        key=f"nat_port_forward.{tracker}".format(tracker),
                        name=f"NAT Port Forward Rule {tracker} ({rule.get('descr', '')})",
                        icon="mdi:network-outline",
                        # entity_category=ENTITY_CATEGORY_CONFIG,
                        device_class=SwitchDeviceClass.SWITCH,
                        entity_registry_enabled_default=False,
                    ),
                )
                entities.append(entity)
    return entities


async def _compile_nat_outbound_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    if not isinstance(state, MutableMapping) or not isinstance(state.get("config"), MutableMapping):
        return []
    entities: list = []
    # nat outbound rules
    if "nat" in state.get("config", {}):
        # to actually be applicable mode must by "hybrid" or "advanced"
        rules = dict_get(state, "config.nat.outbound.rule")
        if isinstance(rules, list):
            for rule in rules:
                if not isinstance(rule, dict):
                    continue

                tracker = dict_get(rule, "created.time")
                # we use tracker as the unique id
                if tracker is None or len(tracker) < 1:
                    continue

                if "Auto created rule" in rule.get("descr", ""):
                    continue

                entity = OPNsenseNatSwitch(
                    config_entry=config_entry,
                    coordinator=coordinator,
                    entity_description=SwitchEntityDescription(
                        key=f"nat_outbound.{tracker}",
                        name=f"NAT Outbound Rule {tracker} ({rule.get('descr', '')})",
                        icon="mdi:network-outline",
                        # entity_category=ENTITY_CATEGORY_CONFIG,
                        device_class=SwitchDeviceClass.SWITCH,
                        entity_registry_enabled_default=False,
                    ),
                )
                entities.append(entity)
    return entities


async def _compile_service_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    if not isinstance(state, MutableMapping) or not isinstance(state.get("services"), list):
        return []

    entities: list = []
    # services
    for service in state.get("services", []):
        if service.get("locked", 1) == 1:
            continue
        for prop_name in ["status"]:
            entity = OPNsenseServiceSwitch(
                config_entry=config_entry,
                coordinator=coordinator,
                entity_description=SwitchEntityDescription(
                    key=f"service.{service.get('id', service.get('name', 'unknown'))}.{prop_name}",
                    name=f"Service {service.get('description', service.get('name', 'Unknown'))} {prop_name}",
                    icon="mdi:application-cog-outline",
                    # entity_category=ENTITY_CATEGORY_CONFIG,
                    device_class=SwitchDeviceClass.SWITCH,
                    entity_registry_enabled_default=False,
                ),
            )
            entities.append(entity)
    return entities


async def _compile_vpn_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    entities: list = []
    for vpn_type in ("openvpn", "wireguard"):
        for clients_servers in ("clients", "servers"):
            if not isinstance(state, MutableMapping):
                return []
            for uuid, instance in state.get(vpn_type, {}).get(clients_servers, {}).items():
                if (
                    not isinstance(instance, MutableMapping)
                    or instance.get("enabled", None) is None
                ):
                    continue

                entity = OPNsenseVPNSwitch(
                    config_entry=config_entry,
                    coordinator=coordinator,
                    entity_description=SwitchEntityDescription(
                        key=f"{vpn_type}.{clients_servers}.{uuid}",
                        name=f"{'OpenVPN' if vpn_type == 'openvpn' else vpn_type.title()} {clients_servers.title().rstrip('s')} {instance['name']}",
                        icon="mdi:folder-key-network-outline",
                        # entity_category=ENTITY_CATEGORY_CONFIG,
                        device_class=SwitchDeviceClass.SWITCH,
                        entity_registry_enabled_default=False,
                    ),
                )
                entities.append(entity)
    return entities


async def _compile_static_unbound_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    if not isinstance(state, MutableMapping):
        return []
    entities: list = []
    entity = OPNsenseUnboundBlocklistSwitch(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=SwitchEntityDescription(
            key="unbound_blocklist.switch",
            name="Unbound Blocklist Switch",
            # icon=icon,
            # entity_category=ENTITY_CATEGORY_CONFIG,
            device_class=SwitchDeviceClass.SWITCH,
            entity_registry_enabled_default=False,
        ),
    )
    entities.append(entity)

    return entities


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the OPNsense switches."""
    coordinator: OPNsenseDataUpdateCoordinator = getattr(config_entry.runtime_data, COORDINATOR)
    state: MutableMapping[str, Any] = coordinator.data
    if not isinstance(state, MutableMapping):
        _LOGGER.error("Missing state data in switch async_setup_entry")
        return
    config: Mapping[str, Any] = config_entry.data

    entities: list = []

    if config.get(CONF_SYNC_FILTERS_AND_NAT, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_filter_switches(config_entry, coordinator, state))
        entities.extend(await _compile_port_forward_switches(config_entry, coordinator, state))
        entities.extend(await _compile_nat_outbound_switches(config_entry, coordinator, state))
    if config.get(CONF_SYNC_SERVICES, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_service_switches(config_entry, coordinator, state))
    if config.get(CONF_SYNC_VPN, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_vpn_switches(config_entry, coordinator, state))
    if config.get(CONF_SYNC_UNBOUND, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_static_unbound_switches(config_entry, coordinator, state))

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
        """Initialize OPNsense Switch entities."""
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
        """Return whether to process the coordinator update or not."""
        return self._delay_update

    @delay_update.setter
    def delay_update(self, value: bool) -> None:
        if value and not self._delay_update:
            self._delay_update = True
            self._reset_delay()
        elif not value:
            self._delay_update = False
            if self._delay_update_remove:
                self._delay_update_remove()
                self._delay_update_remove = None

    def _reset_delay(self) -> None:
        if self._delay_update_remove:
            self._delay_update_remove()

        def _clear(_: Any) -> None:
            self._delay_update = False
            self._delay_update_remove = None

        self._delay_update_remove = async_call_later(
            hass=self.hass, delay=self._delay_seconds, action=_clear
        )


class OPNsenseFilterSwitch(OPNsenseSwitch):
    """Class for OPNsense Filter Switch entities."""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        """Initialize switch entity."""
        super().__init__(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=entity_description,
        )
        self._tracker: str = self._opnsense_get_tracker()
        self._rule: MutableMapping[str, Any] | None = None
        # _LOGGER.debug(f"[OPNsenseFilterSwitch init] Name: {self.name}, tracker: {self._tracker}")

    def _opnsense_get_tracker(self) -> str:
        parts = self.entity_description.key.split(".")
        parts.pop(0)
        return ".".join(parts)

    def _opnsense_get_rule(self) -> MutableMapping[str, Any] | None:
        state: MutableMapping[str, Any] = self.coordinator.data
        tracker: str = self._opnsense_get_tracker()
        if not isinstance(state, MutableMapping):
            return None
        for rule in state.get("config", {}).get("filter", {}).get("rule", {}):
            if dict_get(rule, "created.time") == tracker:
                return rule
        return None

    @callback
    def _handle_coordinator_update(self) -> None:
        if self.delay_update:
            _LOGGER.debug(
                "Skipping coordinator update for filter switch %s due to delay", self.name
            )
            return
        self._rule = self._opnsense_get_rule()
        if not self._rule:
            self._available = False
            self.async_write_ha_state()
            return
        try:
            self._attr_is_on = bool(self._rule.get("disabled", "0") != "1")
        except (TypeError, KeyError, AttributeError):
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True
        self.async_write_ha_state()
        # _LOGGER.debug(f"[OPNsenseFilterSwitch handle_coordinator_update] Name: {self.name}, available: {self.available}, is_on: {self.is_on}, extra_state_attributes: {self.extra_state_attributes}")

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the entity on."""
        if self._rule is None or not self._client:
            return
        await self._client.enable_filter_rule_by_created_time(self._tracker)
        _LOGGER.info("Turned on filter rule: %s", self.name)
        self._attr_is_on = True
        self.async_write_ha_state()
        self.delay_update = True

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the entity off."""
        if self._rule is None or not self._client:
            return
        await self._client.disable_filter_rule_by_created_time(self._tracker)
        _LOGGER.info("Turned off filter rule: %s", self.name)
        self._attr_is_on = False
        self.async_write_ha_state()
        self.delay_update = True

    @property
    def icon(self) -> str | None:
        """Return the icon for the entity."""
        if self.available and self.is_on:
            return "mdi:play-network"
        return super().icon


class OPNsenseNatSwitch(OPNsenseSwitch):
    """Class for OPNsense NAT Switch entities."""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        """Initialize switch entity."""
        super().__init__(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=entity_description,
        )
        self._rule_type: str = self._opnsense_get_rule_type()
        self._tracker: str = self._opnsense_get_tracker()
        self._rule: MutableMapping[str, Any] | None = None
        # _LOGGER.debug(f"[OPNsenseNatSwitch init] Name: {self.name}, tracker: {self._tracker}, rule_type: {self._rule_type}")

    def _opnsense_get_rule_type(self) -> str:
        return self.entity_description.key.split(".")[0]

    def _opnsense_get_tracker(self) -> str:
        parts = self.entity_description.key.split(".")
        parts.pop(0)
        return ".".join(parts)

    def _opnsense_get_rule(self) -> MutableMapping[str, Any] | None:
        state: MutableMapping[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            return None
        rules: list = []
        if self._rule_type == ATTR_NAT_PORT_FORWARD:
            rules = state.get("config", {}).get("nat", {}).get("rule", [])
        if self._rule_type == ATTR_NAT_OUTBOUND:
            rules = state.get("config", {}).get("nat", {}).get("outbound", {}).get("rule", [])

        for rule in rules:
            if dict_get(rule, "created.time") == self._tracker:
                return rule
        return None

    @callback
    def _handle_coordinator_update(self) -> None:
        if self.delay_update:
            _LOGGER.debug("Skipping coordinator update for NAT switch %s due to delay", self.name)
            return
        self._rule = self._opnsense_get_rule()
        if not isinstance(self._rule, MutableMapping):
            return
        try:
            self._attr_is_on = "disabled" not in self._rule
        except (TypeError, KeyError, AttributeError):
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True
        self.async_write_ha_state()
        # _LOGGER.debug(f"[OPNsenseNatSwitch handle_coordinator_update] Name: {self.name}, available: {self.available}, is_on: {self.is_on}, extra_state_attributes: {self.extra_state_attributes}")

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the entity on."""
        if not isinstance(self._rule, MutableMapping) or not self._client:
            return
        if self._rule_type == ATTR_NAT_PORT_FORWARD:
            method = self._client.enable_nat_port_forward_rule_by_created_time
        elif self._rule_type == ATTR_NAT_OUTBOUND:
            method = self._client.enable_nat_outbound_rule_by_created_time
        else:
            return
        await method(self._tracker)
        _LOGGER.info("Turned on NAT rule: %s", self.name)
        self._attr_is_on = True
        self.async_write_ha_state()
        self.delay_update = True

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the entity off."""
        if not isinstance(self._rule, MutableMapping) or not self._client:
            return
        if self._rule_type == ATTR_NAT_PORT_FORWARD:
            method = self._client.disable_nat_port_forward_rule_by_created_time
        elif self._rule_type == ATTR_NAT_OUTBOUND:
            method = self._client.disable_nat_outbound_rule_by_created_time
        else:
            return
        await method(self._tracker)
        _LOGGER.info("Turned off NAT rule: %s", self.name)
        self._attr_is_on = False
        self.async_write_ha_state()
        self.delay_update = True

    @property
    def icon(self) -> str | None:
        """Return the icon for the entity."""
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
        """Initialize switch entity."""
        super().__init__(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=entity_description,
        )
        self._service: MutableMapping[str, Any] | None = None
        self._prop_name: str = self._opnsense_get_property_name()
        # _LOGGER.debug(f"[OPNsenseServiceSwitch init] Name: {self.name}, prop_name: {self._prop_name}")

    def _opnsense_get_property_name(self) -> str:
        return self.entity_description.key.split(".")[2]

    def _opnsense_get_service_id(self) -> str:
        return self.entity_description.key.split(".")[1]

    def _opnsense_get_service(self) -> MutableMapping[str, Any] | None:
        state: MutableMapping[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            return None
        service_id: str = self._opnsense_get_service_id()
        for service in state.get("services", []):
            if service.get("id", None) == service_id:
                return service
        return None

    @callback
    def _handle_coordinator_update(self) -> None:
        if self.delay_update:
            _LOGGER.debug(
                "Skipping coordinator update for service switch %s due to delay", self.name
            )
            return
        self._service = self._opnsense_get_service()
        if not isinstance(self._service, MutableMapping):
            return
        try:
            self._attr_is_on = self._service[self._prop_name]
        except (TypeError, KeyError, AttributeError):
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True
        self._attr_extra_state_attributes = {}
        for attr in ("id", "name"):
            self._attr_extra_state_attributes[f"service_{attr}"] = self._service.get(attr, None)
        self.async_write_ha_state()
        # _LOGGER.debug(f"[OPNsenseServiceSwitch handle_coordinator_update] Name: {self.name}, available: {self.available}, is_on: {self.is_on}, extra_state_attributes: {self.extra_state_attributes}")

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the entity on."""
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
        """Turn the entity off."""
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
        """Return the icon for the entity."""
        if self.available and self.is_on:
            return "mdi:application-cog"
        return super().icon


class OPNsenseUnboundBlocklistSwitch(OPNsenseSwitch):
    """Class for OPNsense Unbound Blocklist Switch entities."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if self.delay_update:
            _LOGGER.debug(
                "Skipping coordinator update for unbound blocklist switch %s due to delay",
                self.name,
            )
            return
        dnsbl = self.coordinator.data.get(ATTR_UNBOUND_BLOCKLIST, {})
        if not isinstance(dnsbl, MutableMapping) or len(dnsbl) == 0:
            self._available = False
            self.async_write_ha_state()
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
        # _LOGGER.debug(f"[OPNsenseUnboundBlocklistSwitch handle_coordinator_update] Name: {self.name}, available: {self.available}, is_on: {self.is_on}, extra_state_attributes: {self.extra_state_attributes}")

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the entity on."""
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
        """Turn the entity off."""
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


class OPNsenseVPNSwitch(OPNsenseSwitch):
    """Class for OPNsense VPN Switch entities."""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        """Initialize switch entity."""
        super().__init__(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=entity_description,
        )
        self._vpn_type = self.entity_description.key.split(".")[0]
        self._clients_servers = self.entity_description.key.split(".")[1]
        self._uuid = self.entity_description.key.split(".")[2]
        # _LOGGER.debug(f"[OPNsenseVPNSwitch init] Name: {self.name}")

    @callback
    def _handle_coordinator_update(self) -> None:
        if self.delay_update:
            _LOGGER.debug("Skipping coordinator update for VPN switch %s due to delay", self.name)
            return
        state: MutableMapping[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            self._available = False
            self.async_write_ha_state()
            return
        instance: MutableMapping[str, Any] = (
            state.get(self._vpn_type, {}).get(self._clients_servers, {}).get(self._uuid, {})
        )
        if not isinstance(instance, MutableMapping):
            self._available = False
            self.async_write_ha_state()
            return
        try:
            self._attr_is_on = instance["enabled"]
        except (TypeError, KeyError, AttributeError):
            self._available = False
            self.async_write_ha_state()
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
                "iterface",
                "pubkey",
                "tunnel_addresses",
                "latest_handshake",
                "servers",
            ]
        else:
            properties = ["uuid", "name"]

        for attr in properties:
            if instance.get(attr, None):
                self._attr_extra_state_attributes[attr] = instance.get(attr)
        self.async_write_ha_state()
        # _LOGGER.debug(f"[OPNsenseVPNSwitch handle_coordinator_update] Name: {self.name}, available: {self.available}, is_on: {self.is_on}, extra_state_attributes: {self.extra_state_attributes}")

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the entity on."""

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
        """Turn the entity off."""

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
        """Return the icon for the entity."""
        if self.available and self.is_on:
            return "mdi:folder-key-network"
        return super().icon
