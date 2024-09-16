"""OPNsense integration."""

import logging

from homeassistant.components.switch import (
    SwitchDeviceClass,
    SwitchEntity,
    SwitchEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import STATE_UNKNOWN  # ENTITY_CATEGORY_CONFIG,
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import slugify

from . import CoordinatorEntityManager, OPNsenseEntity
from .const import COORDINATOR, DOMAIN
from .helpers import dict_get

_LOGGER: logging.Logger = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: entity_platform.AddEntitiesCallback,
):
    """Set up the OPNsense binary sensors."""

    @callback
    def process_entities_callback(hass, config_entry):
        data = hass.data[DOMAIN][config_entry.entry_id]
        coordinator = data[COORDINATOR]
        state = coordinator.data

        entities = []

        # filter rules
        if "filter" in state["config"].keys():
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
                    if "associated-rule-id" in rule.keys():
                        continue

                    if "descr" not in rule.keys():
                        rule["descr"] = ""

                    # not possible to disable these rules
                    if rule["descr"] == "Anti-Lockout Rule":
                        continue

                    tracker = dict_get(rule, "created.time")
                    if tracker is None:
                        continue

                    # we use tracker as the unique id
                    if len(tracker) < 1:
                        continue

                    entity = OPNsenseFilterSwitch(
                        config_entry,
                        coordinator,
                        SwitchEntityDescription(
                            key="filter.{}".format(tracker),
                            name="Filter Rule {} ({})".format(tracker, rule["descr"]),
                            icon=icon,
                            # entity_category=entity_category,
                            device_class=device_class,
                            entity_registry_enabled_default=enabled_default,
                        ),
                    )
                    entities.append(entity)

        # nat port forward rules
        if "nat" in state["config"].keys():
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
                    if tracker is None:
                        continue

                    # we use tracker as the unique id
                    if len(tracker) < 1:
                        continue

                    if "descr" not in rule.keys():
                        rule["descr"] = ""

                    entity = OPNsenseNatSwitch(
                        config_entry,
                        coordinator,
                        SwitchEntityDescription(
                            key="nat_port_forward.{}".format(tracker),
                            name="NAT Port Forward Rule {} ({})".format(
                                tracker, rule["descr"]
                            ),
                            icon=icon,
                            # entity_category=entity_category,
                            device_class=device_class,
                            entity_registry_enabled_default=enabled_default,
                        ),
                    )
                    entities.append(entity)

        # nat outbound rules
        if "nat" in state["config"].keys():
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
                    if tracker is None:
                        continue

                    # we use tracker as the unique id
                    if len(tracker) < 1:
                        continue

                    if "descr" not in rule.keys():
                        rule["descr"] = ""

                    if "Auto created rule" in rule["descr"]:
                        continue

                    entity = OPNsenseNatSwitch(
                        config_entry,
                        coordinator,
                        SwitchEntityDescription(
                            key="nat_outbound.{}".format(tracker),
                            name="NAT Outbound Rule {} ({})".format(
                                tracker, rule["descr"]
                            ),
                            icon=icon,
                            # entity_category=entity_category,
                            device_class=device_class,
                            entity_registry_enabled_default=enabled_default,
                        ),
                    )
                    entities.append(entity)

        # services
        for service in state["services"]:
            for property in ["status"]:
                icon = "mdi:application-cog-outline"
                # likely only want very specific services to manipulate from actions
                enabled_default = False
                # entity_category = ENTITY_CATEGORY_CONFIG
                device_class = SwitchDeviceClass.SWITCH

                entity = OPNsenseServiceSwitch(
                    config_entry,
                    coordinator,
                    SwitchEntityDescription(
                        key="service.{}.{}".format(service["name"], property),
                        name="Service {} {}".format(service["name"], property),
                        icon=icon,
                        # entity_category=entity_category,
                        device_class=device_class,
                        entity_registry_enabled_default=enabled_default,
                    ),
                )
                entities.append(entity)
        return entities

    cem = CoordinatorEntityManager(
        hass,
        hass.data[DOMAIN][config_entry.entry_id][COORDINATOR],
        config_entry,
        process_entities_callback,
        async_add_entities,
    )
    cem.process_entities()


class OPNsenseSwitch(OPNsenseEntity, SwitchEntity):
    def __init__(
        self,
        config_entry,
        coordinator: DataUpdateCoordinator,
        entity_description: SwitchEntityDescription,
    ) -> None:
        """Initialize the entity."""
        self.config_entry = config_entry
        self.entity_description = entity_description
        self.coordinator = coordinator
        self._attr_name = f"{self.opnsense_device_name} {entity_description.name}"
        self._attr_unique_id = slugify(
            f"{self.opnsense_device_unique_id}_{entity_description.key}"
        )

    @property
    def is_on(self):
        return False

    @property
    def extra_state_attributes(self):
        return None


class OPNsenseFilterSwitch(OPNsenseSwitch):
    def _opnsense_get_tracker(self):
        parts = self.entity_description.key.split(".")
        parts.pop(0)
        return ".".join(parts)

    def _opnsense_get_rule(self):
        state = self.coordinator.data
        found = None
        tracker = self._opnsense_get_tracker()
        for rule in state["config"]["filter"]["rule"]:
            if dict_get(rule, "created.time") == tracker:
                found = rule
                break
        return found

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

    async def async_turn_on(self, **kwargs):
        """Turn the entity on."""
        rule = self._opnsense_get_rule()
        if rule is None:
            return
        tracker = self._opnsense_get_tracker()
        client = self._get_opnsense_client()
        await self.hass.async_add_executor_job(
            client.enable_filter_rule_by_created_time, tracker
        )
        await self.coordinator.async_refresh()

    async def async_turn_off(self, **kwargs):
        """Turn the entity off."""
        rule = self._opnsense_get_rule()
        if rule is None:
            return
        tracker = self._opnsense_get_tracker()
        client = self._get_opnsense_client()
        await self.hass.async_add_executor_job(
            client.disable_filter_rule_by_created_time, tracker
        )
        await self.coordinator.async_refresh()


class OPNsenseNatSwitch(OPNsenseSwitch):
    def _opnsense_get_rule_type(self):
        return self.entity_description.key.split(".")[0]

    def _opnsense_get_tracker(self):
        parts = self.entity_description.key.split(".")
        parts.pop(0)
        return ".".join(parts)

    def _opnsense_get_rule(self):
        state = self.coordinator.data
        found = None
        tracker = self._opnsense_get_tracker()
        rule_type = self._opnsense_get_rule_type()
        rules = []
        if rule_type == "nat_port_forward":
            rules = state["config"]["nat"]["rule"]
        if rule_type == "nat_outbound":
            rules = state["config"]["nat"]["outbound"]["rule"]

        for rule in rules:
            if dict_get(rule, "created.time") == tracker:
                found = rule
                break
        return found

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

    async def async_turn_on(self, **kwargs):
        """Turn the entity on."""
        rule = self._opnsense_get_rule()
        if rule is None:
            return
        tracker = self._opnsense_get_tracker()
        client = self._get_opnsense_client()
        rule_type = self._opnsense_get_rule_type()
        if rule_type == "nat_port_forward":
            method = client.enable_nat_port_forward_rule_by_created_time
        if rule_type == "nat_outbound":
            method = client.enable_nat_outbound_rule_by_created_time

        await self.hass.async_add_executor_job(method, tracker)
        await self.coordinator.async_refresh()

    async def async_turn_off(self, **kwargs):
        """Turn the entity off."""
        rule = self._opnsense_get_rule()
        if rule is None:
            return
        tracker = self._opnsense_get_tracker()
        client = self._get_opnsense_client()
        rule_type = self._opnsense_get_rule_type()
        if rule_type == "nat_port_forward":
            method = client.disable_nat_port_forward_rule_by_created_time
        if rule_type == "nat_outbound":
            method = client.disable_nat_outbound_rule_by_created_time

        await self.hass.async_add_executor_job(method, tracker)
        await self.coordinator.async_refresh()


class OPNsenseServiceSwitch(OPNsenseSwitch):
    def _opnsense_get_property_name(self):
        return self.entity_description.key.split(".")[2]

    def _opnsense_get_service_name(self):
        return self.entity_description.key.split(".")[1]

    def _opnsense_get_service(self):
        state = self.coordinator.data
        found = None
        service_name = self._opnsense_get_service_name()
        for service in state["services"]:
            if service["name"] == service_name:
                found = service
                break
        return found

    @property
    def available(self) -> bool:
        service = self._opnsense_get_service()
        property = self._opnsense_get_property_name()
        if service is None or property not in service.keys():
            return False

        return super().available

    @property
    def is_on(self):
        service = self._opnsense_get_service()
        property = self._opnsense_get_property_name()
        try:
            value = service[property]
            return value
        except KeyError:
            return STATE_UNKNOWN

    async def async_turn_on(self, **kwargs):
        """Turn the entity on."""
        service = self._opnsense_get_service()
        client = self._get_opnsense_client()
        result = await self.hass.async_add_executor_job(
            client.start_service, service["name"]
        )
        if result:
            await self.coordinator.async_refresh()

    async def async_turn_off(self, **kwargs):
        """Turn the entity off."""
        service = self._opnsense_get_service()
        client = self._get_opnsense_client()
        result = await self.hass.async_add_executor_job(
            client.stop_service, service["name"]
        )
        if result:
            await self.coordinator.async_refresh()
