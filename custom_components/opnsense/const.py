"""The OPNsense component."""

from typing import Final

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import PERCENTAGE, UnitOfInformation, UnitOfTime

VERSION = "v0.3.10"
DOMAIN = "opnsense"
OPNSENSE_LTD_FIRMWARE = "24.7"  # Some functions may not work but the integration in general should work. Show repair warning.
OPNSENSE_MIN_FIRMWARE = "24.1"  # Don't allow install, will not work.

UNDO_UPDATE_LISTENER = "undo_update_listener"

PLATFORMS: list = ["sensor", "switch", "device_tracker", "binary_sensor", "update"]
LOADED_PLATFORMS = "loaded_platforms"

OPNSENSE_CLIENT = "opnsense_client"
COORDINATOR = "coordinator"
DEVICE_TRACKER_COORDINATOR = "device_tracker_coordinator"
SHOULD_RELOAD = "should_reload"
TRACKED_MACS = "tracked_macs"
DEFAULT_SCAN_INTERVAL = 30
CONF_TLS_INSECURE = "tls_insecure"
DEFAULT_TLS_INSECURE = False
DEFAULT_VERIFY_SSL = True

CONF_DEVICE_TRACKER_ENABLED = "device_tracker_enabled"
DEFAULT_DEVICE_TRACKER_ENABLED = False

CONF_DEVICE_TRACKER_SCAN_INTERVAL = "device_tracker_scan_interval"
DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL = 150

CONF_DEVICE_TRACKER_CONSIDER_HOME = "device_tracker_consider_home"
DEFAULT_DEVICE_TRACKER_CONSIDER_HOME = 0

CONF_DEVICE_UNIQUE_ID = "device_unique_id"
CONF_FIRMWARE_VERSION = "v0.3.10"

CONF_DEVICES = "devices"
CONF_MANUAL_DEVICES = "manual_devices"

COUNT = "count"

# pulled from upnp component
BYTES_RECEIVED = "bytes_received"
BYTES_SENT = "bytes_sent"
PACKETS_RECEIVED = "packets_received"
PACKETS_SENT = "packets_sent"
DATA_PACKETS = "packets"
DATA_RATE_PACKETS_PER_SECOND = f"{DATA_PACKETS}/{UnitOfTime.SECONDS}"

ICON_MEMORY = "mdi:memory"

ATTR_UNBOUND_BLOCKLIST = "unbound_blocklist"
ATTR_NAT_PORT_FORWARD = "nat_port_forward"
ATTR_NAT_OUTBOUND = "nat_outbound"

STATIC_SENSORS: Final[dict[str, SensorEntityDescription]] = {
    # pfstate
    "telemetry.pfstate.used": SensorEntityDescription(
        key="telemetry.pfstate.used",
        name="pf State Table Used",
        native_unit_of_measurement=COUNT,
        device_class=None,
        icon="mdi:table-network",
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.pfstate.total": SensorEntityDescription(
        key="telemetry.pfstate.total",
        name="pf State Table Total",
        native_unit_of_measurement=COUNT,
        device_class=None,
        icon="mdi:table-network",
        state_class=None,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.pfstate.used_percent": SensorEntityDescription(
        key="telemetry.pfstate.used_percent",
        name="pf State Table Used Percentage",
        native_unit_of_measurement=PERCENTAGE,
        device_class=None,
        icon="mdi:table-network",
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    # mbuf
    "telemetry.mbuf.used": SensorEntityDescription(
        key="telemetry.mbuf.used",
        name="Memory Buffers Used",
        native_unit_of_measurement=UnitOfInformation.BYTES,
        device_class=SensorDeviceClass.DATA_SIZE,
        icon=ICON_MEMORY,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        suggested_unit_of_measurement=UnitOfInformation.KILOBYTES,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.mbuf.total": SensorEntityDescription(
        key="telemetry.mbuf.total",
        name="Memory Buffers Total",
        native_unit_of_measurement=UnitOfInformation.BYTES,
        device_class=SensorDeviceClass.DATA_SIZE,
        icon=ICON_MEMORY,
        state_class=None,
        suggested_display_precision=1,
        suggested_unit_of_measurement=UnitOfInformation.KILOBYTES,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.mbuf.used_percent": SensorEntityDescription(
        key="telemetry.mbuf.used_percent",
        name="Memory Buffers Used Percentage",
        native_unit_of_measurement=PERCENTAGE,
        device_class=None,
        icon=ICON_MEMORY,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    # memory with state_class due to being less static
    "telemetry.memory.swap_reserved": SensorEntityDescription(
        key="telemetry.memory.swap_reserved",
        name="Memory Swap Reserved",
        native_unit_of_measurement=UnitOfInformation.BYTES,
        device_class=SensorDeviceClass.DATA_SIZE,
        icon=ICON_MEMORY,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        suggested_unit_of_measurement=UnitOfInformation.MEGABYTES,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    # memory without state_class due to being generally static
    "telemetry.memory.physmem": SensorEntityDescription(
        key="telemetry.memory.physmem",
        name="Memory Physmem",
        native_unit_of_measurement=UnitOfInformation.BYTES,
        device_class=SensorDeviceClass.DATA_SIZE,
        icon=ICON_MEMORY,
        state_class=None,
        suggested_display_precision=1,
        suggested_unit_of_measurement=UnitOfInformation.GIGABYTES,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.memory.used": SensorEntityDescription(
        key="telemetry.memory.used",
        name="Memory Used",
        native_unit_of_measurement=UnitOfInformation.BYTES,
        device_class=SensorDeviceClass.DATA_SIZE,
        icon=ICON_MEMORY,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        suggested_unit_of_measurement=UnitOfInformation.GIGABYTES,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.memory.swap_total": SensorEntityDescription(
        key="telemetry.memory.swap_total",
        name="Memory Swap Total",
        native_unit_of_measurement=UnitOfInformation.BYTES,
        device_class=SensorDeviceClass.DATA_SIZE,
        icon=ICON_MEMORY,
        state_class=None,
        suggested_display_precision=1,
        suggested_unit_of_measurement=UnitOfInformation.MEGABYTES,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    # memory percentages
    "telemetry.memory.swap_used_percent": SensorEntityDescription(
        key="telemetry.memory.swap_used_percent",
        name="Memory Swap Used Percentage",
        native_unit_of_measurement=PERCENTAGE,
        device_class=None,
        icon=ICON_MEMORY,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.memory.used_percent": SensorEntityDescription(
        key="telemetry.memory.used_percent",
        name="Memory Used Percentage",
        native_unit_of_measurement=PERCENTAGE,
        device_class=None,
        icon=ICON_MEMORY,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=True,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.cpu.count": SensorEntityDescription(
        key="telemetry.cpu.count",
        name="CPU Count",
        native_unit_of_measurement=COUNT,
        device_class=None,
        icon="mdi:speedometer-medium",
        state_class=None,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.cpu.usage_total": SensorEntityDescription(
        key="telemetry.cpu.usage_total",
        name="CPU Usage",
        native_unit_of_measurement=PERCENTAGE,
        device_class=None,
        icon="mdi:speedometer-medium",
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=True,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.system.load_average.one_minute": SensorEntityDescription(
        key="telemetry.system.load_average.one_minute",
        name="System Load Average One Minute",
        native_unit_of_measurement=None,
        device_class=None,
        icon="mdi:speedometer-slow",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=2,
        entity_registry_enabled_default=True,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.system.load_average.five_minute": SensorEntityDescription(
        key="telemetry.system.load_average.five_minute",
        name="System Load Average Five Minute",
        native_unit_of_measurement=None,
        device_class=None,
        icon="mdi:speedometer-slow",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=2,
        entity_registry_enabled_default=True,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.system.load_average.fifteen_minute": SensorEntityDescription(
        key="telemetry.system.load_average.fifteen_minute",
        name="System Load Average Fifteen Minute",
        native_unit_of_measurement=None,
        device_class=None,
        icon="mdi:speedometer-slow",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=2,
        entity_registry_enabled_default=True,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "telemetry.system.boottime": SensorEntityDescription(
        key="telemetry.system.boottime",
        name="System Boottime",
        device_class=SensorDeviceClass.TIMESTAMP,
        icon="mdi:clock-outline",
        state_class=None,
        entity_registry_enabled_default=True,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    "certificates": SensorEntityDescription(
        key="certificates",
        name="Certificates",
        device_class=None,
        icon="mdi:certificate-outline",
        state_class=None,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
}

SERVICE_CLOSE_NOTICE = "close_notice"
SERVICE_START_SERVICE = "start_service"
SERVICE_STOP_SERVICE = "stop_service"
SERVICE_RESTART_SERVICE = "restart_service"
SERVICE_SYSTEM_HALT = "system_halt"
SERVICE_SYSTEM_REBOOT = "system_reboot"
SERVICE_SEND_WOL = "send_wol"
SERVICE_RELOAD_INTERFACE = "reload_interface"
SERVICE_GENERATE_VOUCHERS = "generate_vouchers"
SERVICE_KILL_STATES = "kill_states"
SERVICE_TOGGLE_ALIAS = "toggle_alias"
