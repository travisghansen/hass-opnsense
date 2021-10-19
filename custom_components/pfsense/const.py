"""The pfSense component."""
from __future__ import annotations

from typing import Final

from homeassistant.components.sensor import (
    DEVICE_CLASS_TEMPERATURE,
    DEVICE_CLASS_TIMESTAMP,
    STATE_CLASS_MEASUREMENT,
    SensorEntityDescription,
)

from homeassistant.const import (
    ENTITY_CATEGORY_DIAGNOSTIC,
    FREQUENCY_HERTZ,
    PERCENTAGE,
    TEMP_CELSIUS,
)

DEFAULT_USERNAME = "admin"
DOMAIN = "pfsense"

UNDO_UPDATE_LISTENER = "undo_update_listener"

PLATFORMS = ["sensor", "switch", "device_tracker"]

PFSENSE_CLIENT = "pfsense_client"

COORDINATOR = "coordinator"
DEVICE_TRACKER_COORDINATOR = "device_tracker_coordinator"
DEFAULT_SCAN_INTERVAL = 30
CONF_TLS_INSECURE = "tls_insecure"
DEFAULT_TLS_INSECURE = False

CONF_DEVICE_TRACKER_ENABLED = "device_tracker_enabled"
DEFAULT_DEVICE_TRACKER_ENABLED = False

CONF_DEVICE_TRACKER_SCAN_INTERVAL = "device_tracker_scan_interval"
DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL = 60

SENSOR_TYPES: Final[dict[str, SensorEntityDescription]] = {
    # pfstate
    "telemetry.pfstate.used": SensorEntityDescription(
        key="telemetry.pfstate.used",
        name="State Table Used",
        icon="mdi:information-outline",
        state_class=STATE_CLASS_MEASUREMENT,
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.pfstate.total": SensorEntityDescription(
        key="telemetry.pfstate.total",
        name="State Table Total",
        icon="mdi:information-outline",
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.pfstate.used_percent": SensorEntityDescription(
        key="telemetry.pfstate.used_percent",
        name="State Table Used Percentage",
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:gauge",
        state_class=STATE_CLASS_MEASUREMENT,
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),

    # mbuf
    "telemetry.mbuf.used": SensorEntityDescription(
        key="telemetry.mbuf.used",
        name="Memory Buffers Used",
        icon="mdi:information-outline",
        state_class=STATE_CLASS_MEASUREMENT,
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.mbuf.total": SensorEntityDescription(
        key="telemetry.mbuf.total",
        name="Memory Buffers Total",
        icon="mdi:information-outline",
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.mbuf.used_percent": SensorEntityDescription(
        key="telemetry.mbuf.used_percent",
        name="Memory Buffers Used Percentage",
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:gauge",
        state_class=STATE_CLASS_MEASUREMENT,
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),

    # memory with state_class due to being less static
    "telemetry.memory.usermem": SensorEntityDescription(
        key="telemetry.memory.usermem",
        name="Memory Usermem",
        icon="mdi:information-outline",
        state_class=STATE_CLASS_MEASUREMENT,
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.memory.swap_reserved": SensorEntityDescription(
        key="telemetry.memory.swap_reserved",
        name="Memory Swap Reserved",
        icon="mdi:information-outline",
        state_class=STATE_CLASS_MEASUREMENT,
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),

    # memory without state_class due to being generally static
    "telemetry.memory.physmem": SensorEntityDescription(
        key="telemetry.memory.physmem",
        name="Memory Physmem",
        icon="mdi:information-outline",
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.memory.realmem": SensorEntityDescription(
        key="telemetry.memory.realmem",
        name="Memory Realmem",
        icon="mdi:information-outline",
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.memory.swap_total": SensorEntityDescription(
        key="telemetry.memory.swap_total",
        name="Memory Swap Total",
        icon="mdi:information-outline",
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),

    # memory percentages
    "telemetry.memory.swap_used_percent": SensorEntityDescription(
        key="telemetry.memory.swap_used_percent",
        name="Memory Swap Used Percentage",
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:gauge",
        state_class=STATE_CLASS_MEASUREMENT,
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.memory.used_percent": SensorEntityDescription(
        key="telemetry.memory.used_percent",
        name="Memory Used Percentage",
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:gauge",
        state_class=STATE_CLASS_MEASUREMENT,
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),

    # cpu
    "telemetry.cpu.frequency.current": SensorEntityDescription(
        key="telemetry.cpu.frequency.current",
        name="CPU Frequency Current",
        native_unit_of_measurement=FREQUENCY_HERTZ,
        icon="mdi:information-outline",
        state_class=STATE_CLASS_MEASUREMENT,
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.cpu.frequency.max": SensorEntityDescription(
        key="telemetry.cpu.frequency.max",
        name="CPU Frequency Max",
        native_unit_of_measurement=FREQUENCY_HERTZ,
        icon="mdi:information-outline",
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.cpu.count": SensorEntityDescription(
        key="telemetry.cpu.count",
        name="CPU Count",
        icon="mdi:information-outline",
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.cpu.load_average.one_minute": SensorEntityDescription(
        key="telemetry.cpu.load_average.one_minute",
        name="CPU Load Average One Minute",
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:information-outline",
        state_class=STATE_CLASS_MEASUREMENT,
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.cpu.load_average.five_minute": SensorEntityDescription(
        key="telemetry.cpu.load_average.five_minute",
        name="CPU Load Average Five Minute",
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:information-outline",
        state_class=STATE_CLASS_MEASUREMENT,
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.cpu.load_average.fifteen_minute": SensorEntityDescription(
        key="telemetry.cpu.load_average.fifteen_minute",
        name="CPU Load Average Fifteen Minute",
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:information-outline",
        state_class=STATE_CLASS_MEASUREMENT,
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),

    # system
    "telemetry.system.temp": SensorEntityDescription(
        key="telemetry.system.temp",
        name="System Temperature",
        native_unit_of_measurement=TEMP_CELSIUS,
        device_class=DEVICE_CLASS_TEMPERATURE,
        icon="mdi:thermometer",
        state_class=STATE_CLASS_MEASUREMENT,
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.system.boottime": SensorEntityDescription(
        key="telemetry.system.boottime",
        name="System Boottime",
        device_class=DEVICE_CLASS_TIMESTAMP,
        icon="mdi:clock-outline",
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),

}
