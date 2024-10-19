"""OPNsense integration."""

import asyncio
import logging
import traceback
from collections.abc import Mapping
from typing import Any

from homeassistant.components.switch import (
    SwitchDeviceClass,
    SwitchEntity,
    SwitchEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform

from . import OPNsenseEntity
from .const import (
    ATTR_NAT_OUTBOUND,
    ATTR_NAT_PORT_FORWARD,
    ATTR_UNBOUND_BLOCKLIST,
    COORDINATOR,
    DOMAIN,
)
from .coordinator import OPNsenseDataUpdateCoordinator
from .helpers import dict_get

_LOGGER: logging.Logger = logging.getLogger(__name__)


async def _compile_filter_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: Mapping[str, Any],
) -> list:
    if not isinstance(state, Mapping):
        return []
    entities: list = []
    # filter rules
    if "filter" in state.get("config", {}):
        rules = dict_get(state, "config.filter.rule")
        if isinstance(rules, list):
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                icon = "mdi:security-network"
                # likely only want very specific rules to manipulate from actions
                enabled_default = False
                # entity_category = ENTITY_CATEGORY_CONFIG
                device_class = SwitchDeviceClass.SWITCH

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

                entity = OPNsenseFilterSwitch(
                    config_entry=config_entry,
                    coordinator=coordinator,
                    entity_description=SwitchEntityDescription(
                        key=f"filter.{tracker}",
                        name=f"Filter Rule {tracker} ({rule.get('descr', '')})",
                        icon=icon,
                        # entity_category=entity_category,
                        device_class=device_class,
                        entity_registry_enabled_default=enabled_default,
                    ),
                )
                entities.append(entity)
    return entities


async def _compile_port_forward_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: Mapping[str, Any],
) -> list:
    if not isinstance(state, Mapping):
        return []
    entities: list = []
    # nat port forward rules
    if "nat" in state.get("config", {}):
        rules = dict_get(state, "config.nat.rule")
        if isinstance(rules, list):
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                icon = "mdi:network"
                # likely only want very specific rules to manipulate from actions
                enabled_default = False
                # entity_category = ENTITY_CATEGORY_CONFIG
                device_class = SwitchDeviceClass.SWITCH
                tracker = dict_get(rule, "created.time")
                # we use tracker as the unique id
                if tracker is None or len(tracker) < 1:
                    continue

                entity = OPNsenseNatSwitch(
                    config_entry=config_entry,
                    coordinator=coordinator,
                    entity_description=SwitchEntityDescription(
                        key=f"nat_port_forward.{tracker}".format(tracker),
                        name=f"NAT Port Forward Rule {tracker} ({rule.get('descr','')})",
                        icon=icon,
                        # entity_category=entity_category,
                        device_class=device_class,
                        entity_registry_enabled_default=enabled_default,
                    ),
                )
                entities.append(entity)
    return entities


async def _compile_nat_outbound_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: Mapping[str, Any],
) -> list:
    if not isinstance(state, Mapping):
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
                icon = "mdi:network"
                # likely only want very specific rules to manipulate from actions
                enabled_default = False
                # entity_category = ENTITY_CATEGORY_CONFIG
                device_class = SwitchDeviceClass.SWITCH
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
                        name=f"NAT Outbound Rule {tracker} ({rule.get('descr','')})",
                        icon=icon,
                        # entity_category=entity_category,
                        device_class=device_class,
                        entity_registry_enabled_default=enabled_default,
                    ),
                )
                entities.append(entity)
    return entities


async def _compile_service_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: Mapping[str, Any],
) -> list:
    if not isinstance(state, Mapping):
        return []
    entities: list = []
    # services
    for service in state.get("services", []):
        if service.get("locked", 1) == 1:
            continue
        for prop_name in ["status"]:
            icon = "mdi:application-cog-outline"
            # likely only want very specific services to manipulate from actions
            enabled_default = False
            # entity_category = ENTITY_CATEGORY_CONFIG
            device_class = SwitchDeviceClass.SWITCH

            entity = OPNsenseServiceSwitch(
                config_entry=config_entry,
                coordinator=coordinator,
                entity_description=SwitchEntityDescription(
                    key=f"service.{service.get('id', service.get('name', 'unknown'))}.{prop_name}",
                    name=f"Service {service.get('description', service.get('name', 'Unknown'))} {prop_name}",
                    icon=icon,
                    # entity_category=entity_category,
                    device_class=device_class,
                    entity_registry_enabled_default=enabled_default,
                ),
            )
            entities.append(entity)
    return entities


async def _compile_static_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: Mapping[str, Any],
) -> list:
    if not isinstance(state, Mapping):
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
    async_add_entities: entity_platform.AddEntitiesCallback,
) -> None:
    """Set up the OPNsense switches."""
    coordinator: OPNsenseDataUpdateCoordinator = hass.data[DOMAIN][
        config_entry.entry_id
    ][COORDINATOR]
    state: Mapping[str, Any] = coordinator.data
    if not isinstance(state, Mapping):
        _LOGGER.error("Missing state data in switch async_setup_entry")
        return
    results: list = await asyncio.gather(
        _compile_filter_switches(config_entry, coordinator, state),
        _compile_port_forward_switches(config_entry, coordinator, state),
        _compile_nat_outbound_switches(config_entry, coordinator, state),
        _compile_service_switches(config_entry, coordinator, state),
        _compile_static_switches(config_entry, coordinator, state),
        return_exceptions=True,
    )

    entities: list = []
    for result in results:
        if isinstance(result, list):
            entities += result
        else:
            _LOGGER.error(
                f"Error in switch async_setup_entry. {result.__class__.__qualname__}: {result}\n{''.join(traceback.format_tb(result.__traceback__))}"
            )
    _LOGGER.debug(f"[switch async_setup_entry] entities: {len(entities)}")
    async_add_entities(entities)


class OPNsenseSwitch(OPNsenseEntity, SwitchEntity):

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        super().__init__(
            config_entry,
            coordinator,
            unique_id_suffix=entity_description.key,
            name_suffix=entity_description.name,
        )
        self.entity_description = entity_description
        self._attr_is_on: bool = False


class OPNsenseFilterSwitch(OPNsenseSwitch):

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        super().__init__(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=entity_description,
        )
        self._tracker: str = self._opnsense_get_tracker()
        self._rule: Mapping[str, Any] | None = None
        # _LOGGER.debug(f"[OPNsenseFilterSwitch init] Name: {self.name}, tracker: {self._tracker}")

    def _opnsense_get_tracker(self) -> str:
        parts = self.entity_description.key.split(".")
        parts.pop(0)
        return ".".join(parts)

    def _opnsense_get_rule(self):
        state: Mapping[str, Any] = self.coordinator.data
        tracker: str = self._opnsense_get_tracker()
        if not isinstance(state, Mapping):
            return None
        for rule in state.get("config", {}).get("filter", {}).get("rule", []):
            if dict_get(rule, "created.time") == tracker:
                return rule
        return None

    @callback
    def _handle_coordinator_update(self) -> None:
        self._rule = self._opnsense_get_rule()
        try:
            self._attr_is_on = bool(self._rule.get("disabled", "0") != "1")
        except (TypeError, KeyError, AttributeError):
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True
        self.async_write_ha_state()
        _LOGGER.debug(
            f"[OPNsenseFilterSwitch handle_coordinator_update] Name: {self.name}, available: {self.available}, is_on: {self.is_on}, extra_state_attributes: {self.extra_state_attributes}"
        )

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the entity on."""
        if self._rule is None:
            return
        await self._client.enable_filter_rule_by_created_time(self._tracker)
        await self.coordinator.async_refresh()

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the entity off."""
        if self._rule is None:
            return
        await self._client.disable_filter_rule_by_created_time(self._tracker)
        await self.coordinator.async_refresh()


class OPNsenseNatSwitch(OPNsenseSwitch):

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        super().__init__(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=entity_description,
        )
        self._rule_type: str = self._opnsense_get_rule_type()
        self._tracker: str = self._opnsense_get_tracker()
        self._rule: Mapping[str, Any] | None = None
        # _LOGGER.debug(f"[OPNsenseNatSwitch init] Name: {self.name}, tracker: {self._tracker}, rule_type: {self._rule_type}")

    def _opnsense_get_rule_type(self) -> str:
        return self.entity_description.key.split(".")[0]

    def _opnsense_get_tracker(self) -> str:
        parts = self.entity_description.key.split(".")
        parts.pop(0)
        return ".".join(parts)

    def _opnsense_get_rule(self):
        state: Mapping[str, Any] = self.coordinator.data
        if not isinstance(state, Mapping):
            return None
        rules: list = []
        if self._rule_type == ATTR_NAT_PORT_FORWARD:
            rules = state.get("config", {}).get("nat", {}).get("rule", [])
        if self._rule_type == ATTR_NAT_OUTBOUND:
            rules = (
                state.get("config", {})
                .get("nat", {})
                .get("outbound", {})
                .get("rule", [])
            )

        for rule in rules:
            if dict_get(rule, "created.time") == self._tracker:
                return rule
        return None

    @callback
    def _handle_coordinator_update(self) -> None:
        self._rule = self._opnsense_get_rule()
        try:
            self._attr_is_on = "disabled" not in self._rule
        except (TypeError, KeyError, AttributeError):
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True
        self.async_write_ha_state()
        _LOGGER.debug(
            f"[OPNsenseNatSwitch handle_coordinator_update] Name: {self.name}, available: {self.available}, is_on: {self.is_on}, extra_state_attributes: {self.extra_state_attributes}"
        )

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the entity on."""
        if not isinstance(self._rule, Mapping):
            return
        if self._rule_type == ATTR_NAT_PORT_FORWARD:
            method = self._client.enable_nat_port_forward_rule_by_created_time
        elif self._rule_type == ATTR_NAT_OUTBOUND:
            method = self._client.enable_nat_outbound_rule_by_created_time
        else:
            return
        await method(self._tracker)
        await self.coordinator.async_refresh()

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the entity off."""
        if not isinstance(self._rule, Mapping):
            return
        if self._rule_type == ATTR_NAT_PORT_FORWARD:
            method = self._client.disable_nat_port_forward_rule_by_created_time
        elif self._rule_type == ATTR_NAT_OUTBOUND:
            method = self._client.disable_nat_outbound_rule_by_created_time
        else:
            return
        await method(self._tracker)
        await self.coordinator.async_refresh()


class OPNsenseServiceSwitch(OPNsenseSwitch):

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        super().__init__(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=entity_description,
        )
        self._service: Mapping[str, Any] | None = None
        self._prop_name: str = self._opnsense_get_property_name()
        # _LOGGER.debug(f"[OPNsenseServiceSwitch init] Name: {self.name}, prop_name: {self._prop_name}")

    def _opnsense_get_property_name(self) -> str:
        return self.entity_description.key.split(".")[2]

    def _opnsense_get_service_id(self) -> str:
        return self.entity_description.key.split(".")[1]

    def _opnsense_get_service(self) -> Mapping[str, Any] | None:
        state: Mapping[str, Any] = self.coordinator.data
        if not isinstance(state, Mapping):
            return None
        service_id: str = self._opnsense_get_service_id()
        for service in state.get("services", []):
            if service.get("id", None) == service_id:
                return service
        return None

    @callback
    def _handle_coordinator_update(self) -> None:
        self._service = self._opnsense_get_service()
        try:
            self._attr_is_on = self._service[self._prop_name]
        except (TypeError, KeyError, AttributeError):
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True
        self._attr_extra_state_attributes = {}
        for attr in ["id", "name"]:
            self._attr_extra_state_attributes[f"service_{attr}"] = self._service.get(
                attr, None
            )
        self.async_write_ha_state()
        _LOGGER.debug(
            f"[OPNsenseServiceSwitch handle_coordinator_update] Name: {self.name}, available: {self.available}, is_on: {self.is_on}, extra_state_attributes: {self.extra_state_attributes}"
        )

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the entity on."""
        if not isinstance(self._service, Mapping):
            return

        result: bool = await self._client.start_service(
            self._service.get("id", self._service.get("name", None))
        )
        if result:
            await self.coordinator.async_refresh()

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the entity off."""
        if not isinstance(self._service, Mapping):
            return

        result: bool = await self._client.stop_service(
            self._service.get("id", self._service.get("name", None))
        )
        if result:
            await self.coordinator.async_refresh()


class OPNsenseUnboundBlocklistSwitch(OPNsenseSwitch):

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        dnsbl = self.coordinator.data.get(ATTR_UNBOUND_BLOCKLIST, {})
        if not isinstance(dnsbl, Mapping) or len(dnsbl) == 0:
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True
        self._attr_is_on = dnsbl.get("enabled", "0") == "1"
        self._attr_extra_state_attributes: Mapping[str, Any] = {
            "Force SafeSearch": (
                True if dnsbl.get("safesearch", "0") == "1" else False
            ),
            "Type of DNSBL": dnsbl.get("type", ""),
            "URLs of Blocklists": dnsbl.get("lists", ""),
            "Whitelist Domains": dnsbl.get("whitelists", ""),
            "Blocklist Domains": dnsbl.get("blocklists", ""),
            "Wildcard Domains": dnsbl.get("wildcards", ""),
            "Destination Address": dnsbl.get("address", ""),
            "Return NXDOMAIN": (True if dnsbl.get("nxdomain", "0") == "1" else False),
        }
        self.async_write_ha_state()
        _LOGGER.debug(
            f"[OPNsenseUnboundBlocklistSwitch handle_coordinator_update] Name: {self.name}, available: {self.available}, is_on: {self.is_on}, extra_state_attributes: {self.extra_state_attributes}"
        )

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the entity on."""
        result: bool = await self._client.enable_unbound_blocklist()
        if result:
            await self.coordinator.async_refresh()

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the entity off."""
        result: bool = await self._client.disable_unbound_blocklist()
        if result:
            await self.coordinator.async_refresh()
