"""Diagnostics support for the OPNsense integration."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, time
from enum import Enum
import ipaddress
import re
from typing import Any

from homeassistant.components.diagnostics import REDACTED, async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from . import OPNsenseData

_SECRET_FIELDS: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "cookie",
        "key",
        "password",
        "passwd",
        "private_key",
        "privatekey",
        "refresh_token",
        "secret",
        "token",
        "username",
    }
)
_NON_SECRET_KEY_FIELDS: frozenset[str] = frozenset({"public_key"})
_MAC_FIELDS: frozenset[str] = frozenset(
    {"apmac", "bssid", "gateway_mac", "hwaddr", "mac", "mac_address", "macaddr"}
)
_IP_FIELDS: frozenset[str] = frozenset(
    {
        "address",
        "dns_server",
        "dns_servers",
        "endpoint",
        "external",
        "gateway",
        "ip",
        "ip_address",
        "ipv4",
        "ipv6",
        "local_address",
        "real_address",
        "remote_address",
        "source",
        "target",
        "destination",
        "subnet",
        "tunnel_address",
        "tunnel_addresses",
        "virtual_address",
    }
)
_URL_FIELDS: frozenset[str] = frozenset({"host", "url"})
_ID_FIELDS: frozenset[str] = frozenset(
    {
        "caref",
        "device_unique_id",
        "entry_id",
        "fingerprint",
        "id",
        "ids",
        "issuer",
        "public_key",
        "pubkey",
        "serial",
        "serial_number",
        "subject",
        "unique_id",
        "uuid",
        "wwn",
    }
)
_PERSONAL_FIELDS: frozenset[str] = frozenset(
    {
        "client",
        "common_name",
        "content",
        "categories",
        "category",
        "description",
        "descr",
        "device",
        "domain",
        "email",
        "essid",
        "fqdn",
        "hostname",
        "ident",
        "interface",
        "label",
        "latitude",
        "lease_interface",
        "lease_interfaces",
        "location",
        "longitude",
        "lat",
        "lon",
        "message",
        "name",
        "notice",
        "output",
        "peer",
        "response",
        "server",
        "ssid",
        "status_message",
        "text",
        "title",
        "user",
    }
)
_SENSITIVE_FIELDS: frozenset[str] = frozenset(
    _MAC_FIELDS | _IP_FIELDS | _URL_FIELDS | _ID_FIELDS | _PERSONAL_FIELDS
)
_IDENTIFIER_KEY_CONTAINERS: frozenset[str] = frozenset(
    {
        "certificates",
        "clients",
        "d_nat",
        "dnsbl",
        "gateways",
        "interfaces",
        "leases",
        "npt",
        "one_to_one",
        "rules",
        "servers",
        "smart_info",
        "source_nat",
        "temps",
    }
)
_SAFE_OPERATIONAL_FIELDS: frozenset[str] = frozenset(
    {
        "date",
        "datetime",
        "firmware_version",
        "host_firmware_version",
        "last_exception",
        "mode",
        "period",
        "protocol",
        "role",
        "state",
        "status",
        "time",
        "type",
        "unit",
        "units",
        "valid_from",
        "valid_to",
    }
)
_SAFE_STRUCTURAL_FIELDS: frozenset[str] = frozenset(
    {
        "active",
        "arp_table",
        "bytes",
        "carp",
        "certificates",
        "clients",
        "config_entry",
        "coordinators",
        "count",
        "data",
        "device_tracker",
        "device_serial",
        "devices",
        "disabled_by",
        "discovery_keys",
        "enum",
        "firmware_version",
        "host_firmware_version",
        "inbytes_kilobytes_per_second",
        "interfaces",
        "json_scalars",
        "last_exception",
        "last_update_success",
        "leases",
        "live_traffic",
        "main",
        "minor_version",
        "notices",
        "nut_ups_status",
        "opaque",
        "options",
        "packets",
        "pfstate",
        "pref_disable_new_entities",
        "pref_disable_polling",
        "scan_interval",
        "source",
        "subentries",
        "system_info",
        "telemetry",
        "temperature",
        "temps",
        "used",
        "version",
        "wireguard",
    }
)
_SAFE_CODE_VALUES: frozenset[str] = frozenset(
    {
        "OL",
        "active",
        "available",
        "carp",
        "client",
        "connected",
        "disabled",
        "disconnected",
        "down",
        "enabled",
        "error",
        "failed",
        "http",
        "https",
        "offline",
        "ok",
        "online",
        "pending",
        "primary",
        "running",
        "secondary",
        "server",
        "stopped",
        "success",
        "tcp",
        "udp",
        "unknown",
        "unavailable",
        "up",
        "warning",
    }
)
_SAFE_UNIT_VALUES: frozenset[str] = frozenset(
    {"%", "A", "B", "B/s", "C", "F", "Hz", "K", "V", "W", "bit/s", "bytes", "ms", "s"}
)
_VERSION_PATTERN = re.compile(r"\d+(?:\.\d+)+(?:[-+._a-z0-9]*)?", re.IGNORECASE)
_EXCEPTION_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")

_MAC_PATTERN = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")
_IPV4_PATTERN = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
_IPV6_CANDIDATE_PATTERN = re.compile(
    r"(?<![0-9a-f:])(?:[0-9a-f.]*:[0-9a-f:.]+)"
    r"(?:%[0-9a-z_.-]+)?(?:/\d{1,3})?(?![0-9a-f:])",
    re.IGNORECASE,
)
_UUID_PATTERN = re.compile(
    r"(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![0-9a-f])"
)
_URL_PATTERN = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s\"'<>]+")
_EMAIL_PATTERN = re.compile(r"(?i)\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}\b")


def _normalize_field(field_name: object) -> str:
    """Normalize a payload field name for sensitivity matching."""
    if not isinstance(field_name, str):
        return ""
    return (
        field_name.removeprefix("%")
        .strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
        .replace(".", "_")
    )


def _is_secret_field(field_name: str) -> bool:
    """Return whether a normalized field contains a secret value."""
    if field_name in _NON_SECRET_KEY_FIELDS:
        return False
    return field_name in _SECRET_FIELDS or any(
        field_name.endswith(f"_{candidate}") for candidate in _SECRET_FIELDS
    )


def _is_sensitive_field(field_name: str) -> bool:
    """Return whether a normalized field contains a private identifier."""
    return field_name in _SENSITIVE_FIELDS or any(
        field_name.endswith(f"_{sensitive}") for sensitive in _SENSITIVE_FIELDS
    )


def _is_safe_operational_field(field_name: str) -> bool:
    """Return whether a field may contain safe operational metadata."""
    return field_name in _SAFE_OPERATIONAL_FIELDS or any(
        field_name.endswith(f"_{safe}") for safe in _SAFE_OPERATIONAL_FIELDS
    )


def _is_safe_structural_field(field_name: str) -> bool:
    """Return whether a mapping key belongs to the diagnostics payload structure."""
    return (
        field_name in _SAFE_STRUCTURAL_FIELDS
        or _is_secret_field(field_name)
        or field_name in _SENSITIVE_FIELDS
        or field_name == "ids"
        or field_name.endswith(("_id", "_ids"))
        or _is_safe_operational_field(field_name)
    )


def _is_safe_operational_value(field_name: str, value: str) -> bool:
    """Return whether a string value is valid safe metadata for its field."""
    if not _is_safe_operational_field(field_name):
        return False
    if field_name == "last_exception":
        return _EXCEPTION_PATTERN.fullmatch(value) is not None
    if "version" in field_name:
        return _VERSION_PATTERN.fullmatch(value) is not None
    if field_name in {"date", "valid_from", "valid_to"} or field_name.endswith("_date"):
        try:
            date.fromisoformat(value)
        except ValueError:
            return False
        return True
    if field_name in {"datetime", "time"} or field_name.endswith(("_datetime", "_time")):
        try:
            datetime.fromisoformat(value) if "date" in field_name else time.fromisoformat(value)
        except ValueError:
            return False
        return True
    if field_name in {"unit", "units"} or field_name.endswith(("_unit", "_units")):
        return value in _SAFE_UNIT_VALUES
    return value in _SAFE_CODE_VALUES


def _coordinator_diagnostics(coordinator: Any | None) -> dict[str, Any] | None:
    """Build diagnostics from an existing coordinator without refreshing it."""
    if coordinator is None:
        return None

    last_exception = getattr(coordinator, "last_exception", None)
    return {
        "last_update_success": bool(getattr(coordinator, "last_update_success", False)),
        "last_exception": type(last_exception).__name__ if last_exception is not None else None,
        "data": getattr(coordinator, "data", None),
    }


@dataclass
class _Pseudonymizer:
    """Replace sensitive values with consistent placeholders for one document."""

    aliases: dict[tuple[type, str | int | float], str] = field(default_factory=dict)
    key_aliases: dict[tuple[object, object], str] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)

    def register(self, kind: str, value: object) -> None:
        """Register a sensitive value for consistent replacement."""
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            return
        if value in ("", REDACTED):
            return
        alias_key = (type(value), value)
        if alias_key not in self.aliases:
            self.counters[kind] = self.counters.get(kind, 0) + 1
            self.aliases[alias_key] = f"**REDACTED_{kind.upper()}_{self.counters[kind]}**"

    def alias_for(self, value: object) -> str | None:
        """Return the registered alias for a supported scalar value."""
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            return None
        return self.aliases.get((type(value), value))

    def register_key(self, value: object) -> None:
        """Register a dynamic mapping key without rendering its value."""
        if isinstance(value, (str, int, float)) and not isinstance(value, bool) and value != "":
            self.register("key", value)
            return
        token = self._key_token(value)
        if token not in self.key_aliases:
            self.counters["key"] = self.counters.get("key", 0) + 1
            self.key_aliases[token] = f"**REDACTED_KEY_{self.counters['key']}**"

    def key_alias_for(self, value: object) -> str:
        """Return the distinct alias registered for a dynamic mapping key."""
        return self.alias_for(value) or self.key_aliases[self._key_token(value)]

    @staticmethod
    def _key_token(value: object) -> tuple[object, object]:
        """Build a non-rendering, type-aware token for a dynamic mapping key."""
        if value is None or isinstance(value, (str, int, float, bool)):
            return (type(value), value)
        return (type(value), id(value))

    def collect(self, value: Any, parent_field: str = "", *, force_sensitive: bool = False) -> None:
        """Collect sensitive values recursively before replacing mapping keys."""
        if isinstance(value, Enum):
            self.collect(value.value, parent_field, force_sensitive=force_sensitive)
            return
        if isinstance(value, Mapping):
            redact_mapping_keys = force_sensitive or parent_field in _IDENTIFIER_KEY_CONTAINERS
            for key, item in value.items():
                normalized_key = _normalize_field(key)
                redact_key = redact_mapping_keys or not _is_safe_structural_field(normalized_key)
                if redact_key:
                    self.register_key(key)
                if force_sensitive:
                    self.collect(item, normalized_key, force_sensitive=True)
                elif not _is_secret_field(normalized_key):
                    if _is_sensitive_field(normalized_key):
                        self.register(self._kind_for_field(normalized_key, item), item)
                    self.collect(
                        item,
                        normalized_key,
                        force_sensitive=not redact_key
                        and _is_sensitive_field(normalized_key)
                        and isinstance(item, (Mapping, list, tuple, set)),
                    )
                if isinstance(key, str):
                    self._collect_detected_values(key)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                self.collect(item, parent_field, force_sensitive=force_sensitive)
            return
        if force_sensitive:
            if isinstance(value, str):
                self._collect_detected_values(value)
            self.register("value", value)
            return
        if isinstance(value, str):
            self._collect_detected_values(value)
            if not _is_safe_operational_value(parent_field, value):
                self.register("value", value)

    def sanitize(self, value: Any, parent_field: str = "", *, force_sensitive: bool = False) -> Any:
        """Return a recursively pseudonymized, JSON-compatible copy."""
        if isinstance(value, Mapping):
            sanitized: dict[Any, Any] = {}
            redact_mapping_keys = force_sensitive or parent_field in _IDENTIFIER_KEY_CONTAINERS
            for key, item in value.items():
                normalized_key = _normalize_field(key)
                redact_key = redact_mapping_keys or not _is_safe_structural_field(normalized_key)
                sanitized_key = (
                    self.key_alias_for(key)
                    if redact_key
                    else self._replace_embedded(key)
                    if isinstance(key, str)
                    else key
                )
                if force_sensitive:
                    sanitized[sanitized_key] = self.sanitize(
                        item, normalized_key, force_sensitive=True
                    )
                elif _is_secret_field(normalized_key):
                    sanitized[sanitized_key] = REDACTED
                elif _is_sensitive_field(normalized_key) and not isinstance(
                    item, (Mapping, list, tuple, set)
                ):
                    sanitized[sanitized_key] = self.alias_for(item) or REDACTED
                else:
                    sanitized[sanitized_key] = self.sanitize(
                        item,
                        normalized_key,
                        force_sensitive=not redact_key
                        and _is_sensitive_field(normalized_key)
                        and isinstance(item, (Mapping, list, tuple, set)),
                    )
            return sanitized
        if isinstance(value, (list, tuple)):
            return [
                self.sanitize(item, parent_field, force_sensitive=force_sensitive) for item in value
            ]
        if isinstance(value, set):
            return [
                self.sanitize(item, parent_field, force_sensitive=force_sensitive) for item in value
            ]
        if force_sensitive:
            alias = self.alias_for(value)
            if alias is not None:
                return alias
        return self._replace_scalar(value, parent_field)

    def _collect_detected_values(self, value: str) -> None:
        """Collect formatted identifiers embedded in an arbitrary string."""
        for pattern, kind in (
            (_URL_PATTERN, "url"),
            (_EMAIL_PATTERN, "email"),
            (_MAC_PATTERN, "mac"),
            (_UUID_PATTERN, "id"),
        ):
            for match in pattern.finditer(value):
                self.register(kind, match.group(0))

        for match in _IPV4_PATTERN.finditer(value):
            candidate = match.group(0)
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            self.register("ip", candidate)

        for match in _IPV6_CANDIDATE_PATTERN.finditer(value):
            candidate = match.group(0)
            try:
                ipaddress.ip_interface(candidate)
            except ValueError:
                continue
            self.register("ip", candidate)

        try:
            ipaddress.ip_interface(value)
        except ValueError:
            return
        self.register("ip", value)

    def _kind_for_field(self, field_name: str, value: object) -> str:
        """Return a useful placeholder type for a sensitive field."""
        if isinstance(value, str):
            if _MAC_PATTERN.fullmatch(value):
                return "mac"
            try:
                ipaddress.ip_interface(value)
            except ValueError:
                pass
            else:
                return "ip"
        if field_name in _URL_FIELDS or field_name.endswith(
            tuple(f"_{item}" for item in _URL_FIELDS)
        ):
            return "url"
        if field_name in _ID_FIELDS or field_name.endswith(
            tuple(f"_{item}" for item in _ID_FIELDS)
        ):
            return "id"
        if field_name in {"email", "user"}:
            return "user"
        return "value"

    def _replace_embedded(self, value: str) -> str:
        """Replace detected formatted identifiers without scanning unrelated aliases."""
        result = value
        for pattern in (_URL_PATTERN, _EMAIL_PATTERN, _MAC_PATTERN, _UUID_PATTERN):
            result = pattern.sub(
                lambda match: self.alias_for(match.group(0)) or match.group(0), result
            )

        def _replace_ip(match: re.Match[str]) -> str:
            """Replace a candidate only when it is a valid IP address or interface."""
            candidate = match.group(0)
            try:
                ipaddress.ip_interface(candidate)
            except ValueError:
                return candidate
            return self.alias_for(candidate) or candidate

        result = _IPV4_PATTERN.sub(_replace_ip, result)
        return _IPV6_CANDIDATE_PATTERN.sub(_replace_ip, result)

    def _replace_scalar(self, value: Any, parent_field: str = "") -> Any:
        """Replace registered values in a scalar while preserving its type otherwise."""
        if isinstance(value, Enum):
            return self.sanitize(value.value, parent_field)
        if isinstance(value, str):
            if not _is_safe_operational_value(parent_field, value):
                alias = self.alias_for(value)
                if alias is not None:
                    return alias
            return self._replace_embedded(value)
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, (datetime, date, time)):
            return value.isoformat()
        return REDACTED


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry[OPNsenseData]
) -> dict[str, Any]:
    """Return privacy-safe diagnostics for an OPNsense config entry."""
    runtime_data = entry.runtime_data
    diagnostics: dict[str, Any] = {
        "config_entry": entry.as_dict(),
        "coordinators": {
            "main": _coordinator_diagnostics(runtime_data.coordinator),
            "device_tracker": _coordinator_diagnostics(runtime_data.device_tracker_coordinator),
            "live_traffic": _coordinator_diagnostics(runtime_data.live_traffic_coordinator),
        },
    }
    credential_redacted = async_redact_data(diagnostics, _SECRET_FIELDS)
    pseudonymizer = _Pseudonymizer()
    pseudonymizer.collect(credential_redacted)
    return pseudonymizer.sanitize(credential_redacted)
