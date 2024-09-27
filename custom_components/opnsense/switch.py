"""OPNsense integration."""

import asyncio
from collections.abc import Mapping
import logging
from typing import Any

from homeassistant.components.switch import (
    SwitchDeviceClass,
    SwitchEntity,
    SwitchEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import STATE_UNKNOWN  # ENTITY_CATEGORY_CONFIG,
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
from homeassistant.util import slugify

from custom_components.opnsense.pyopnsense import OPNsenseClient

from . import OPNsenseEntity
from .const import ATTR_UNBOUND_BLOCKLIST, COORDINATOR, DOMAIN
from .coordinator import OPNsenseDataUpdateCoordinator
from .helpers import dict_get

_LOGGER: logging.Logger = logging.getLogger(__name__)


async def _compile_filter_switches(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: Mapping[str, Any],
) -> list:
    entities: list = []
    # filter rules
    if "filter" in state["config"]:
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

                if "descr" not in rule.keys():
                    rule["descr"] = ""

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
    entities: list = []
    entity = OPNsenseUnboundBlocklistSwitch(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=SwitchEntityDescription(
            key=f"unbound_blocklist.switch",
            name=f"Unbound Blocklist Switch",
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

    _LOGGER.debug(f"[switch async_setup_entry] coordinator: {coordinator}")
    _LOGGER.debug(f"[switch async_setup_entry] state length: {len(state)}")
    _LOGGER.debug(f"[switch async_setup_entry] state keys: {state.keys()}")

    # entities = await _compile_static_switches(config_entry, coordinator, state)

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
                f"Error in switch async_setup_entry. {result.__class__.__qualname__}: {result}"
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
        """Initialize the entity."""
        self.config_entry = config_entry
        self.entity_description = entity_description
        self.coordinator: OPNsenseDataUpdateCoordinator = coordinator
        self._attr_name = f"{self.opnsense_device_name} {entity_description.name}"
        self._attr_unique_id = slugify(
            f"{self.opnsense_device_unique_id}_{entity_description.key}"
        )

    # @property
    # def is_on(self):
    #     return False

    # @property
    # def extra_state_attributes(self):
    #     return None


class OPNsenseFilterSwitch(OPNsenseSwitch):
    def _opnsense_get_tracker(self) -> str:
        parts = self.entity_description.key.split(".")
        parts.pop(0)
        return ".".join(parts)

    def _opnsense_get_rule(self):
        state: Mapping[str, Any] = self.coordinator.data
        tracker: str = self._opnsense_get_tracker()
        for rule in state["config"]["filter"]["rule"]:
            if dict_get(rule, "created.time") == tracker:
                return rule
        return None

    @property
    def available(self) -> bool:
        rule = self._opnsense_get_rule()
        if rule is None:
            return False

        return super().available

    @property
    def is_on(self):
        rule = self._opnsense_get_rule()
        if rule is None:
            return STATE_UNKNOWN
        try:
            if "disabled" not in rule.keys():
                return True
            return bool(rule["disabled"] != "1")
        except KeyError:
            return STATE_UNKNOWN

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the entity on."""
        rule = self._opnsense_get_rule()
        if rule is None:
            return
        tracker: str = self._opnsense_get_tracker()
        client: OPNsenseClient = self._get_opnsense_client()
        await client.enable_filter_rule_by_created_time(tracker)
        await self.coordinator.async_refresh()

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the entity off."""
        rule = self._opnsense_get_rule()
        if rule is None:
            return
        tracker: str = self._opnsense_get_tracker()
        client: OPNsenseClient = self._get_opnsense_client()
        await client.disable_filter_rule_by_created_time(tracker)
        await self.coordinator.async_refresh()


class OPNsenseNatSwitch(OPNsenseSwitch):
    def _opnsense_get_rule_type(self) -> str:
        return self.entity_description.key.split(".")[0]

    def _opnsense_get_tracker(self) -> str:
        parts = self.entity_description.key.split(".")
        parts.pop(0)
        return ".".join(parts)

    def _opnsense_get_rule(self):
        state: Mapping[str, Any] = self.coordinator.data
        tracker: str = self._opnsense_get_tracker()
        rule_type: str = self._opnsense_get_rule_type()
        rules: list = []
        if rule_type == "nat_port_forward":
            rules = state["config"]["nat"]["rule"]
        if rule_type == "nat_outbound":
            rules = state["config"]["nat"]["outbound"]["rule"]

        for rule in rules:
            if dict_get(rule, "created.time") == tracker:
                return rule
        return None

    @property
    def available(self) -> bool:
        rule = self._opnsense_get_rule()
        if rule is None:
            return False

        return super().available

    @property
    def is_on(self):
        rule = self._opnsense_get_rule()
        if rule is None:
            return STATE_UNKNOWN
        try:
            return "disabled" not in rule.keys()
        except KeyError:
            return STATE_UNKNOWN

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the entity on."""
        rule = self._opnsense_get_rule()
        if rule is None:
            return
        tracker: str = self._opnsense_get_tracker()
        client: OPNsenseClient = self._get_opnsense_client()
        rule_type: str = self._opnsense_get_rule_type()
        if rule_type == "nat_port_forward":
            method = client.enable_nat_port_forward_rule_by_created_time
        if rule_type == "nat_outbound":
            method = client.enable_nat_outbound_rule_by_created_time

        await method(tracker)
        await self.coordinator.async_refresh()

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the entity off."""
        rule = self._opnsense_get_rule()
        if rule is None:
            return
        tracker: str = self._opnsense_get_tracker()
        client: OPNsenseClient = self._get_opnsense_client()
        rule_type: str = self._opnsense_get_rule_type()
        if rule_type == "nat_port_forward":
            method = client.disable_nat_port_forward_rule_by_created_time
        if rule_type == "nat_outbound":
            method = client.disable_nat_outbound_rule_by_created_time

        await method(tracker)
        await self.coordinator.async_refresh()


class OPNsenseServiceSwitch(OPNsenseSwitch):
    def _opnsense_get_property_name(self) -> str:
        return self.entity_description.key.split(".")[2]

    def _opnsense_get_service_id(self) -> str:
        return self.entity_description.key.split(".")[1]

    def _opnsense_get_service(self) -> Mapping[str, Any] | None:
        state: Mapping[str, Any] = self.coordinator.data
        service_id: str = self._opnsense_get_service_id()
        for service in state["services"]:
            if service["id"] == service_id:
                return service
        return None

    @property
    def available(self) -> bool:
        service: Mapping[str, Any] | None = self._opnsense_get_service()
        prop_name: str = self._opnsense_get_property_name()
        if service is None or prop_name not in service:
            return False

        return super().available

    @property
    def is_on(self):
        service: Mapping[str, Any] | None = self._opnsense_get_service()
        prop_name: str = self._opnsense_get_property_name()
        try:
            return service[prop_name]
        except (TypeError, KeyError):
            return STATE_UNKNOWN

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the entity on."""
        service: Mapping[str, Any] | None = self._opnsense_get_service()
        if isinstance(service, Mapping):
            client: OPNsenseClient = self._get_opnsense_client()
            result: bool = await client.start_service(
                service.get("id", service.get("name", None))
            )
            if result:
                await self.coordinator.async_refresh()

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the entity off."""
        service: Mapping[str, Any] | None = self._opnsense_get_service()
        if isinstance(service, Mapping):
            client: OPNsenseClient = self._get_opnsense_client()
            result: bool = await client.stop_service(
                service.get("id", service.get("name", None))
            )
            if result:
                await self.coordinator.async_refresh()

    @property
    def extra_state_attributes(self) -> Mapping[str, Any]:
        service: Mapping[str, Any] | None = self._opnsense_get_service()
        attributes = {}
        for attr in ["id", "name"]:
            attributes[f"service_{attr}"] = service.get(attr, None)
        return attributes


class OPNsenseUnboundBlocklistSwitch(OPNsenseSwitch):

    def __init__(
        self,
        config_entry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        super().__init__(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=entity_description,
        )
        self._attr_is_on = STATE_UNKNOWN
        self._attr_extra_state_attributes = {}
        self._attr_available = False

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        dnsbl = self.coordinator.data.get(ATTR_UNBOUND_BLOCKLIST, {})
        if not isinstance(dnsbl, Mapping) or len(dnsbl) == 0:
            self._attr_available = False
            return
        self._attr_available = True
        self._attr_is_on = True if dnsbl.get("enabled", "0") == "1" else False
        self._attr_extra_state_attributes = {
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

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the entity on."""
        client: OPNsenseClient = self._get_opnsense_client()
        result: bool = await client.enable_unbound_blocklist()
        if result:
            await self.coordinator.async_refresh()

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the entity off."""
        client: OPNsenseClient = self._get_opnsense_client()
        result: bool = await client.disable_unbound_blocklist()
        if result:
            await self.coordinator.async_refresh()
