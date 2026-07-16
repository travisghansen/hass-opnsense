"""Restart-safe registry reconciliation for device-ID repairs."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.entity import Entity
from homeassistant.util import slugify

from .const import DOMAIN
from .helpers import detach_shared_router_parent

REPAIR_MARKER_KEY: str = "device_id_repair"
_REPAIR_MARKER_VERSION = 1

type EntityIdentity = tuple[str, str, str]
type PlatformDomain = Platform | str


class RepairReconciliationError(HomeAssistantError):
    """Raised when registry reconciliation cannot continue safely."""


@dataclass(frozen=True)
class RepairMarker:
    """Validated persisted repair marker."""

    version: int
    old_device_id: str
    new_device_id: str


def build_repair_marker(old_device_id: str, new_device_id: str) -> dict[str, object]:
    """Build the current persisted device-ID repair marker."""
    return {
        "version": _REPAIR_MARKER_VERSION,
        "old_device_id": old_device_id,
        "new_device_id": new_device_id,
    }


def has_repair_marker(entry: ConfigEntry) -> bool:
    """Return whether the entry contains a persisted repair marker."""
    return REPAIR_MARKER_KEY in entry.data


def parse_repair_marker(entry: ConfigEntry) -> RepairMarker | None:
    """Parse and validate the entry's persisted repair marker."""
    value = entry.data.get(REPAIR_MARKER_KEY)
    if not isinstance(value, Mapping):
        return None
    version = value.get("version")
    old_device_id = value.get("old_device_id")
    new_device_id = value.get("new_device_id")
    if (
        version != _REPAIR_MARKER_VERSION
        or not isinstance(old_device_id, str)
        or not old_device_id.strip()
        or not isinstance(new_device_id, str)
        or not new_device_id.strip()
        or old_device_id == new_device_id
    ):
        return None
    return RepairMarker(version, old_device_id, new_device_id)


def _registry_identity(entry: er.RegistryEntry) -> EntityIdentity:
    """Return an entity's full registry collision identity."""
    return entry.domain, entry.platform, entry.unique_id


def _platform_domain_value(platform_domain: PlatformDomain) -> str:
    """Return the string entity domain for a platform value."""
    return platform_domain.value if isinstance(platform_domain, Platform) else platform_domain


@dataclass
class RepairReconciliation:
    """Coordinate in-place identity migration with platform discovery."""

    hass: HomeAssistant
    config_entry: ConfigEntry
    marker: RepairMarker
    desired_identities: set[EntityIdentity] = field(default_factory=set)
    completed_platform_domains: set[str] = field(default_factory=set)
    active: bool = True
    _candidate_entity_ids: set[str] = field(default_factory=set)

    def prepare(self) -> None:
        """Preflight every target collision, then migrate identifiers in place."""
        entity_registry = er.async_get(self.hass)
        device_registry = dr.async_get(self.hass)
        candidates = er.async_entries_for_config_entry(entity_registry, self.config_entry.entry_id)
        self._candidate_entity_ids = {candidate.entity_id for candidate in candidates}
        old_prefix = f"{slugify(self.marker.old_device_id)}_"
        new_prefix = f"{slugify(self.marker.new_device_id)}_"

        migrations: list[tuple[er.RegistryEntry, str]] = []
        for candidate in candidates:
            if not candidate.unique_id.startswith(old_prefix):
                continue
            target_unique_id = f"{new_prefix}{candidate.unique_id[len(old_prefix) :]}"
            target_entity_id = entity_registry.async_get_entity_id(
                candidate.domain, candidate.platform, target_unique_id
            )
            target = entity_registry.async_get(target_entity_id) if target_entity_id else None
            if target is not None and target.entity_id != candidate.entity_id:
                raise RepairReconciliationError(
                    f"entity target collision: {candidate.domain}, "
                    f"{candidate.platform}, {target_unique_id}"
                )
            migrations.append((candidate, target_unique_id))

        old_main = device_registry.async_get_device(
            identifiers={(DOMAIN, self.marker.old_device_id)}
        )
        new_main = device_registry.async_get_device(
            identifiers={(DOMAIN, self.marker.new_device_id)}
        )
        if new_main is not None:
            if old_main is not None and new_main.id != old_main.id:
                raise RepairReconciliationError("primary device identifier target collision")
            if old_main is None and self.config_entry.entry_id not in new_main.config_entries:
                raise RepairReconciliationError("primary device identifier target collision")

        try:
            if old_main is not None and new_main is None:
                new_identifiers = {
                    (DOMAIN, self.marker.new_device_id) if domain == DOMAIN else (domain, value)
                    for domain, value in old_main.identifiers
                }
                new_main = device_registry.async_update_device(
                    old_main.id, new_identifiers=new_identifiers
                )
            for candidate, target_unique_id in migrations:
                entity_registry.async_update_entity(
                    candidate.entity_id, new_unique_id=target_unique_id
                )
        except (
            dr.DeviceIdentifierCollisionError,
            HomeAssistantError,
            KeyError,
            ValueError,
        ) as err:
            raise RepairReconciliationError("registry identifier migration failed") from err

    def record_desired_entities(
        self, platform_domain: PlatformDomain, entities: Iterable[Entity] | None
    ) -> None:
        """Record a platform's complete intended entity list, including disabled rows.

        If ``entities`` is ``None``, the platform discovery payload was missing
        or malformed and should not be treated as complete.
        """
        if entities is None:
            return
        domain = _platform_domain_value(platform_domain)
        self.completed_platform_domains.add(domain)
        for entity in entities:
            if entity.unique_id is not None:
                self.desired_identities.add((domain, DOMAIN, entity.unique_id))

    def require_platforms_complete(self, platform_domains: Iterable[PlatformDomain]) -> None:
        """Fail unless every forwarded platform reported its final entity list."""
        required_domains = {
            _platform_domain_value(platform_domain) for platform_domain in platform_domains
        }
        missing_domains = required_domains - self.completed_platform_domains
        if missing_domains:
            missing = ", ".join(sorted(missing_domains))
            raise RepairReconciliationError(f"platform discovery incomplete: {missing}")

    def finalize(self) -> None:
        """Remove stale candidates and detach only unreferenced obsolete devices."""
        entity_registry = er.async_get(self.hass)
        device_registry = dr.async_get(self.hass)
        try:
            for entity_id in self._candidate_entity_ids:
                candidate = entity_registry.async_get(entity_id)
                if candidate is None or _registry_identity(candidate) in self.desired_identities:
                    continue
                entity_registry.async_remove(entity_id)

            surviving_entities = er.async_entries_for_config_entry(
                entity_registry, self.config_entry.entry_id
            )
            preserved_device_ids = {
                entity.device_id for entity in surviving_entities if entity.device_id is not None
            }
            main_device = device_registry.async_get_device(
                identifiers={(DOMAIN, self.marker.new_device_id)}
            )
            if main_device is not None:
                preserved_device_ids.add(main_device.id)
            for device in dr.async_entries_for_config_entry(
                device_registry, self.config_entry.entry_id
            ):
                if device.id not in preserved_device_ids:
                    router_device_id = main_device.id if main_device is not None else None
                    detach_shared_router_parent(
                        shared_config_entry_id=self.config_entry.entry_id,
                        shared_device_entry=device,
                        router_device_id=router_device_id,
                        config_entries=self.hass.config_entries,
                        device_registry=device_registry,
                    )
        except (HomeAssistantError, KeyError, ValueError) as err:
            raise RepairReconciliationError("registry finalization failed") from err

    def mark_complete(self) -> None:
        """Disable reconciliation-only behavior after persisted marker clearance."""
        self.active = False


def record_desired_entities(
    config_entry: ConfigEntry,
    platform_domain: PlatformDomain,
    entities: Iterable[Entity] | None,
) -> None:
    """Record a final platform entity list when reconciliation is active."""
    reconciliation = getattr(config_entry.runtime_data, "repair_reconciliation", None)
    if isinstance(reconciliation, RepairReconciliation) and reconciliation.active:
        reconciliation.record_desired_entities(platform_domain, entities)


def is_reconciliation_active(config_entry: ConfigEntry) -> bool:
    """Return whether this setup is performing device-ID reconciliation."""
    reconciliation = getattr(config_entry.runtime_data, "repair_reconciliation", None)
    return isinstance(reconciliation, RepairReconciliation) and reconciliation.active
