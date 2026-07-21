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

    aliases: dict[str, str] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)
    embedded_aliases: set[str] = field(default_factory=set)

    def register(self, kind: str, value: object, *, embedded: bool = False) -> None:
        """Register a sensitive value for consistent replacement."""
        if not isinstance(value, str):
            return
        if not value or value == REDACTED:
            return
        if value not in self.aliases:
            self.counters[kind] = self.counters.get(kind, 0) + 1
            self.aliases[value] = f"**REDACTED_{kind.upper()}_{self.counters[kind]}**"
        if embedded:
            self.embedded_aliases.add(value)

    def collect(self, value: Any, parent_field: str = "", *, force_sensitive: bool = False) -> None:
        """Collect sensitive values recursively before replacing mapping keys."""
        if isinstance(value, Mapping):
            redact_mapping_keys = force_sensitive or parent_field in _IDENTIFIER_KEY_CONTAINERS
            for key, item in value.items():
                normalized_key = _normalize_field(key)
                if redact_mapping_keys:
                    self.register("key", key)
                if force_sensitive:
                    self.collect(item, normalized_key, force_sensitive=True)
                elif not _is_secret_field(normalized_key):
                    if _is_sensitive_field(normalized_key):
                        self.register(self._kind_for_field(normalized_key, item), item)
                    self.collect(
                        item,
                        normalized_key,
                        force_sensitive=not redact_mapping_keys
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
        if isinstance(value, str):
            if force_sensitive:
                self._collect_detected_values(value)
                self.register("value", value)
            else:
                self._collect_detected_values(value)

    def sanitize(self, value: Any, parent_field: str = "", *, force_sensitive: bool = False) -> Any:
        """Return a recursively pseudonymized, JSON-compatible copy."""
        if isinstance(value, Mapping):
            sanitized: dict[Any, Any] = {}
            redact_mapping_keys = force_sensitive or parent_field in _IDENTIFIER_KEY_CONTAINERS
            for key, item in value.items():
                normalized_key = _normalize_field(key)
                sanitized_key = self._replace_scalar(key)
                if force_sensitive:
                    sanitized[sanitized_key] = self.sanitize(
                        item, normalized_key, force_sensitive=True
                    )
                elif _is_secret_field(normalized_key):
                    sanitized[sanitized_key] = REDACTED
                elif _is_sensitive_field(normalized_key) and not isinstance(
                    item, (Mapping, list, tuple, set)
                ):
                    sanitized[sanitized_key] = (
                        self.aliases.get(item, REDACTED) if isinstance(item, str) else REDACTED
                    )
                else:
                    sanitized[sanitized_key] = self.sanitize(
                        item,
                        normalized_key,
                        force_sensitive=not redact_mapping_keys
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
        if force_sensitive and isinstance(value, str):
            return self.aliases.get(value, REDACTED)
        return self._replace_scalar(value)

    def _collect_detected_values(self, value: str) -> None:
        """Collect formatted identifiers embedded in an arbitrary string."""
        for pattern, kind in (
            (_URL_PATTERN, "url"),
            (_EMAIL_PATTERN, "email"),
            (_MAC_PATTERN, "mac"),
            (_UUID_PATTERN, "id"),
        ):
            for match in pattern.finditer(value):
                self.register(kind, match.group(0), embedded=True)

        for match in _IPV4_PATTERN.finditer(value):
            candidate = match.group(0)
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            self.register("ip", candidate, embedded=True)

        for match in _IPV6_CANDIDATE_PATTERN.finditer(value):
            candidate = match.group(0)
            try:
                ipaddress.ip_interface(candidate)
            except ValueError:
                continue
            self.register("ip", candidate, embedded=True)

        try:
            ipaddress.ip_interface(value)
        except ValueError:
            return
        self.register("ip", value, embedded=True)

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

    def _replace_scalar(self, value: Any) -> Any:
        """Replace registered values in a scalar while preserving its type otherwise."""
        if isinstance(value, Enum):
            return self.sanitize(value.value)
        if isinstance(value, str):
            if value in self.aliases:
                return self.aliases[value]
            result = value
            for sensitive, replacement in sorted(
                ((sensitive, self.aliases[sensitive]) for sensitive in self.embedded_aliases),
                key=lambda item: len(item[0]),
                reverse=True,
            ):
                result = result.replace(sensitive, replacement)
            return result
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
