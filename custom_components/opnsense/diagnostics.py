"""Diagnostics support for the OPNsense integration."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, time
from enum import Enum
import ipaddress
import math
import re
from typing import Any

from homeassistant.components.diagnostics import REDACTED
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
        "source_net",
        "target",
        "destination",
        "destination_net",
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
        "fingerprint",
        "public_key",
        "pubkey",
        "serial",
        "serial_number",
        "wwn",
    }
)
_URL_FIELD_SUFFIXES: tuple[str, ...] = tuple(f"_{item}" for item in _URL_FIELDS)
_ID_FIELD_SUFFIXES: tuple[str, ...] = tuple(f"_{item}" for item in _ID_FIELDS)
_IP_FIELD_SUFFIXES: tuple[str, ...] = tuple(f"_{item}" for item in _IP_FIELDS)
_PRIVATE_FIELDS: frozenset[str] = frozenset(
    {
        "common_name",
        "email",
        "ident",
        "latitude",
        "location",
        "longitude",
        "lat",
        "lon",
        "response",
        "user",
    }
)
_SENSITIVE_FIELDS: frozenset[str] = frozenset(
    _IP_FIELDS | _URL_FIELDS | _ID_FIELDS | _PRIVATE_FIELDS
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
_CAREF_PATTERN = re.compile(r"(?i)^[0-9a-f]{13}$")
_URL_PATTERN = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s\"'<>]+")
_EMAIL_PATTERN = re.compile(r"(?i)\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
_INTERNAL_IPV4_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_LOOPBACK_IPV4 = ipaddress.IPv4Address("127.0.0.1")
_ULA_IPV6_NETWORK = ipaddress.IPv6Network("fc00::/7")
_LOOPBACK_IPV6 = ipaddress.IPv6Address("::1")
_IPV6_SENTENCE_PUNCTUATION = ".,;!?"
_SPEEDTEST_LAST_METRICS: frozenset[str] = frozenset({"download", "upload", "latency"})
_MIN_EMBEDDED_SECRET_LENGTH = 4


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


def _is_alias_metadata_field(field_name: str) -> bool:
    """Return whether a normalized field contains OPNsense alias display metadata."""
    return field_name.startswith("alias_meta_")


def _is_speedtest_server_field(path: tuple[str, ...], field_name: str) -> bool:
    """Return whether a field is a latest speed-test metric's server description."""
    return (
        field_name == "server"
        and len(path) >= 3
        and path[-3] == "speedtest"
        and path[-2] == "last"
        and path[-1] in _SPEEDTEST_LAST_METRICS
    )


def _is_safe_ipv4(value: str) -> bool:
    """Return whether a value is an allowed local IPv4 address or interface."""
    try:
        address = ipaddress.ip_interface(value).ip
    except ValueError:
        return False
    return isinstance(address, ipaddress.IPv4Address) and (
        address == _LOOPBACK_IPV4 or any(address in network for network in _INTERNAL_IPV4_NETWORKS)
    )


def _is_safe_ipv6(value: str) -> bool:
    """Return whether a value is an allowed local IPv6 address or interface."""
    try:
        address = ipaddress.ip_interface(value).ip
    except ValueError:
        return False
    return isinstance(address, ipaddress.IPv6Address) and (
        address.is_link_local or address == _LOOPBACK_IPV6 or address in _ULA_IPV6_NETWORK
    )


def _is_safe_network_identifier(value: object) -> bool:
    """Return whether a mapping identifier is safe and useful in diagnostics."""
    return isinstance(value, str) and (
        _MAC_PATTERN.fullmatch(value) is not None or _is_safe_ipv4(value) or _is_safe_ipv6(value)
    )


def _validated_ipv6_candidate(candidate: str) -> tuple[str, str] | None:
    """Return a valid IPv6 candidate and any trailing sentence punctuation."""
    try:
        interface = ipaddress.ip_interface(candidate)
    except ValueError:
        core = candidate.rstrip(_IPV6_SENTENCE_PUNCTUATION)
        if core == candidate:
            return None
        try:
            interface = ipaddress.ip_interface(core)
        except ValueError:
            return None
        suffix = candidate[len(core) :]
    else:
        core = candidate
        suffix = ""
    if not isinstance(interface, ipaddress.IPv6Interface):
        return None
    return core, suffix


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

    aliases: dict[tuple[type, str | int | float | date | datetime | time], str] = field(
        default_factory=dict
    )
    key_aliases: dict[tuple[object, object], str] = field(default_factory=dict)
    embedded_identifier_aliases: dict[str, str] = field(default_factory=dict)
    embedded_secret_aliases: dict[str, str] = field(default_factory=dict)
    speedtest_server_aliases: dict[str, str] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)

    def register(self, kind: str, value: object) -> None:
        """Register a sensitive value for consistent replacement."""
        if isinstance(value, bool) or not isinstance(
            value, (str, int, float, date, datetime, time)
        ):
            return
        if isinstance(value, float) and not math.isfinite(value):
            return
        if value in ("", REDACTED):
            return
        alias_key = (type(value), value)
        if alias_key not in self.aliases:
            self.counters[kind] = self.counters.get(kind, 0) + 1
            self.aliases[alias_key] = f"**REDACTED_{kind.upper()}_{self.counters[kind]}**"
        if kind not in {"key", "secret"} and isinstance(value, str):
            self.embedded_identifier_aliases[value] = self.aliases[alias_key]

    def alias_for(self, value: object) -> str | None:
        """Return the registered alias for a supported scalar value."""
        if isinstance(value, bool) or not isinstance(
            value, (str, int, float, date, datetime, time)
        ):
            return None
        if isinstance(value, float) and not math.isfinite(value):
            return None
        return self.aliases.get((type(value), value))

    def register_speedtest_server(self, value: str) -> None:
        """Register a speed-test server description without affecting other fields."""
        if value in self.speedtest_server_aliases:
            return
        self.counters["speedtest_server"] = self.counters.get("speedtest_server", 0) + 1
        self.speedtest_server_aliases[value] = (
            f"**REDACTED_SPEEDTEST_SERVER_{self.counters['speedtest_server']}**"
        )

    def register_key(self, value: object) -> None:
        """Register a dynamic mapping key without rendering its value."""
        if isinstance(value, str):
            self._collect_detected_values(value)
        if (
            isinstance(value, (str, int, float, date, datetime, time))
            and not isinstance(value, bool)
            and value != ""
            and not (isinstance(value, float) and not math.isfinite(value))
        ):
            self.register("key", value)
            return
        token = self._key_token(value)
        if token not in self.key_aliases:
            self.counters["key"] = self.counters.get("key", 0) + 1
            self.key_aliases[token] = f"**REDACTED_KEY_{self.counters['key']}**"

    def collect_secret_literals(self, value: Any) -> None:
        """Collect exact credentials anywhere in raw diagnostics for free-text replacement."""
        if isinstance(value, Mapping):
            for key, item in value.items():
                if _is_secret_field(_normalize_field(key)):
                    self._register_secret_literals(item)
                else:
                    self.collect_secret_literals(item)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                self.collect_secret_literals(item)

    def _register_secret_literals(self, value: Any) -> None:
        """Register string literals contained by a secret field."""
        if isinstance(value, str):
            if value not in ("", REDACTED):
                self.register("secret", value)
                if len(value) >= _MIN_EMBEDDED_SECRET_LENGTH:
                    self.embedded_secret_aliases[value] = self.aliases[(str, value)]
            return
        if isinstance(value, Mapping):
            for item in value.values():
                self._register_secret_literals(item)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                self._register_secret_literals(item)

    def key_alias_for(self, value: object) -> str:
        """Return the distinct alias registered for a dynamic mapping key."""
        return self.alias_for(value) or self.key_aliases[self._key_token(value)]

    @staticmethod
    def _key_token(value: object) -> tuple[object, object]:
        """Build a non-rendering, type-aware token for a dynamic mapping key."""
        if isinstance(value, float) and not math.isfinite(value):
            if math.isnan(value):
                return (float, "nan")
            return (float, "positive_infinity" if value > 0 else "negative_infinity")
        if value is None or isinstance(value, (str, int, float, bool)):
            return (type(value), value)
        return (type(value), id(value))

    def collect(
        self,
        value: Any,
        *,
        force_sensitive: bool = False,
        path: tuple[str, ...] = (),
    ) -> None:
        """Collect sensitive values recursively before replacing mapping keys."""
        if isinstance(value, Enum):
            self.collect(
                value.value,
                force_sensitive=force_sensitive,
            )
            return
        if isinstance(value, Mapping):
            for key, item in value.items():
                normalized_key = _normalize_field(key)
                if _is_alias_metadata_field(normalized_key):
                    continue
                redact_key = self._should_redact_key(key, force_sensitive=force_sensitive)
                if redact_key:
                    self.register_key(key)
                elif isinstance(key, str):
                    self._collect_detected_values(key)
                if force_sensitive:
                    self.collect(item, force_sensitive=True, path=(*path, normalized_key))
                elif not _is_secret_field(normalized_key):
                    if normalized_key == "issuer":
                        kind = self._kind_for_field(normalized_key, item)
                        if kind is not None:
                            self.register(kind, item)
                    elif (
                        _is_speedtest_server_field(path, normalized_key)
                        and isinstance(item, str)
                        and item not in ("", REDACTED)
                    ):
                        self.register_speedtest_server(item)
                    elif _is_sensitive_field(normalized_key):
                        kind = self._kind_for_field(normalized_key, item)
                        if kind is not None:
                            self.register(kind, item)
                    self.collect(
                        item,
                        force_sensitive=not redact_key
                        and _is_sensitive_field(normalized_key)
                        and isinstance(item, (Mapping, list, tuple, set)),
                        path=(*path, normalized_key),
                    )
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                self.collect(
                    item,
                    force_sensitive=force_sensitive,
                    path=path,
                )
            return
        if force_sensitive:
            if isinstance(value, str):
                self._collect_detected_values(value)
            self.register("value", value)
            return
        if isinstance(value, str):
            self._collect_detected_values(value)

    def sanitize(
        self,
        value: Any,
        *,
        force_sensitive: bool = False,
        path: tuple[str, ...] = (),
    ) -> Any:
        """Return a recursively pseudonymized, JSON-compatible copy."""
        if isinstance(value, Enum):
            return self.sanitize(
                value.value,
                force_sensitive=force_sensitive,
                path=path,
            )
        if isinstance(value, Mapping):
            sanitized: dict[Any, Any] = {}
            for key, item in value.items():
                normalized_key = _normalize_field(key)
                if _is_alias_metadata_field(normalized_key):
                    sanitized[key] = item
                    continue
                redact_key = self._should_redact_key(key, force_sensitive=force_sensitive)
                sanitized_key = (
                    self.key_alias_for(key)
                    if redact_key
                    else self._replace_embedded(key)
                    if isinstance(key, str)
                    else key
                )
                if force_sensitive:
                    sanitized[sanitized_key] = self.sanitize(
                        item, force_sensitive=True, path=(*path, normalized_key)
                    )
                elif _is_secret_field(normalized_key):
                    sanitized[sanitized_key] = REDACTED
                elif normalized_key == "issuer":
                    sanitized[sanitized_key] = self.alias_for(item) or self._replace_scalar(item)
                elif _is_speedtest_server_field(path, normalized_key):
                    alias = (
                        self.speedtest_server_aliases.get(item) if isinstance(item, str) else None
                    )
                    sanitized[sanitized_key] = alias or self._replace_scalar(item)
                elif _is_sensitive_field(normalized_key) and not isinstance(
                    item, (Mapping, list, tuple, set)
                ):
                    sanitized[sanitized_key] = self.alias_for(item) or self._replace_scalar(item)
                else:
                    sanitized[sanitized_key] = self.sanitize(
                        item,
                        force_sensitive=not redact_key
                        and _is_sensitive_field(normalized_key)
                        and isinstance(item, (Mapping, list, tuple, set)),
                        path=(*path, normalized_key),
                    )
            return sanitized
        if isinstance(value, (list, tuple, set)):
            return [
                self.sanitize(
                    item,
                    force_sensitive=force_sensitive,
                    path=path,
                )
                for item in value
            ]
        if force_sensitive:
            alias = self.alias_for(value)
            if alias is not None:
                return alias
        return self._replace_scalar(value)

    @staticmethod
    def _should_redact_key(value: object, *, force_sensitive: bool) -> bool:
        """Return whether a mapping key needs replacement for privacy or JSON safety."""
        unsupported = not isinstance(value, (str, int, float, bool, type(None)))
        nonfinite = isinstance(value, float) and not math.isfinite(value)
        return (
            unsupported or nonfinite or (force_sensitive and not _is_safe_network_identifier(value))
        )

    def _collect_detected_values(self, value: str) -> None:
        """Collect formatted identifiers embedded in an arbitrary string."""
        for pattern, kind in (
            (_URL_PATTERN, "url"),
            (_EMAIL_PATTERN, "email"),
        ):
            for match in pattern.finditer(value):
                self.register(kind, match.group(0))

        for match in _IPV4_PATTERN.finditer(value):
            candidate = match.group(0)
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if not _is_safe_ipv4(candidate):
                self.register("ipv4", candidate)

        for match in _IPV6_CANDIDATE_PATTERN.finditer(value):
            candidate = match.group(0)
            validated = _validated_ipv6_candidate(candidate)
            if validated is None:
                continue
            core, _suffix = validated
            if not _is_safe_ipv6(core):
                self.register("ipv6", core)

        try:
            interface = ipaddress.ip_interface(value)
        except ValueError:
            return
        if isinstance(interface, ipaddress.IPv4Interface):
            if not _is_safe_ipv4(value):
                self.register("ipv4", value)
        elif not _is_safe_ipv6(value):
            self.register("ipv6", value)

    def _kind_for_field(self, field_name: str, value: object) -> str | None:
        """Return a useful placeholder type for a sensitive field."""
        if isinstance(value, str):
            if _MAC_PATTERN.fullmatch(value):
                return None
            if _UUID_PATTERN.fullmatch(value):
                return None
            try:
                interface = ipaddress.ip_interface(value)
            except ValueError:
                pass
            else:
                if isinstance(interface, ipaddress.IPv4Interface) and _is_safe_ipv4(value):
                    return None
                if isinstance(interface, ipaddress.IPv6Interface) and _is_safe_ipv6(value):
                    return None
                return "ipv4" if isinstance(interface, ipaddress.IPv4Interface) else "ipv6"
        if field_name == "issuer":
            return "id" if isinstance(value, str) and _CAREF_PATTERN.fullmatch(value) else None
        if field_name in _IP_FIELDS or field_name.endswith(_IP_FIELD_SUFFIXES):
            return None
        if field_name in _URL_FIELDS or field_name.endswith(_URL_FIELD_SUFFIXES):
            return "url"
        if field_name in _ID_FIELDS or field_name.endswith(_ID_FIELD_SUFFIXES):
            return "id"
        if field_name in {"email", "user"}:
            return "user"
        return "value"

    def _replace_embedded(self, value: str) -> str:
        """Replace detected formatted identifiers without scanning unrelated aliases."""
        result = value
        for pattern in (_URL_PATTERN, _EMAIL_PATTERN):
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

        def _replace_ipv6(match: re.Match[str]) -> str:
            """Replace a valid IPv6 core while preserving sentence punctuation."""
            candidate = match.group(0)
            validated = _validated_ipv6_candidate(candidate)
            if validated is None:
                return candidate
            core, suffix = validated
            return f"{self.alias_for(core) or core}{suffix}"

        result = _IPV6_CANDIDATE_PATTERN.sub(_replace_ipv6, result)
        for literal, alias in sorted(
            self.embedded_identifier_aliases.items(),
            key=lambda item: len(item[0]),
            reverse=True,
        ):
            result = re.sub(rf"(?<!\w){re.escape(literal)}(?!\w)", alias, result)
        for secret, alias in sorted(
            self.embedded_secret_aliases.items(), key=lambda item: len(item[0]), reverse=True
        ):
            result = re.sub(rf"(?<!\w){re.escape(secret)}(?!\w)", alias, result)
        return result

    def _replace_scalar(self, value: Any) -> Any:
        """Replace registered values in a scalar while preserving its type otherwise."""
        if isinstance(value, str):
            alias = self.alias_for(value)
            if alias is not None:
                return alias
            return self._replace_embedded(value)
        if value is None or isinstance(value, (bool, int)):
            return value
        if isinstance(value, float):
            return value if math.isfinite(value) else None
        if isinstance(value, (datetime, date, time)):
            return value.isoformat()
        return REDACTED


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry[OPNsenseData]
) -> dict[str, Any]:
    """Return privacy-safe diagnostics for an OPNsense config entry."""
    runtime_data = getattr(entry, "runtime_data", None)
    diagnostics: dict[str, Any] = {
        "config_entry": entry.as_dict(),
        "coordinators": {
            "main": _coordinator_diagnostics(getattr(runtime_data, "coordinator", None)),
            "device_tracker": _coordinator_diagnostics(
                getattr(runtime_data, "device_tracker_coordinator", None)
            ),
            "live_traffic": _coordinator_diagnostics(
                getattr(runtime_data, "live_traffic_coordinator", None)
            ),
        },
    }
    pseudonymizer = _Pseudonymizer()
    pseudonymizer.collect_secret_literals(diagnostics)
    pseudonymizer.collect(diagnostics)
    return pseudonymizer.sanitize(diagnostics)
