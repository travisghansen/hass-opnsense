"""Unit tests for custom_components.opnsense.entity."""

from collections.abc import Callable, Iterator, Mapping
from unittest.mock import MagicMock

from homeassistant.util import slugify
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense.const import CONF_DEVICE_UNIQUE_ID, DOMAIN
from custom_components.opnsense.coordinator import OPNsenseDataUpdateCoordinator
from custom_components.opnsense.entity import OPNsenseBaseEntity, OPNsenseEntity


def test_payload_display_name_uses_scalar_fallback() -> None:
    """Display names use scalar payload values when no string field is available."""
    assert OPNsenseEntity.payload_display_name({"name": 42}, "fallback", "name") == "42"


class _BadStrValue:
    """Value object that raises when converted to a string."""

    def __str__(self) -> str:
        raise ValueError("string conversion failure")


class _BadStripValue(str):
    """String value that raises when stripped."""

    __slots__ = ()

    def strip(self, chars: str | None = None) -> str:
        """Raise when display-name normalization strips whitespace.

        Args:
            chars: Optional characters to strip, matching ``str.strip``.
        """
        raise ValueError("strip failure")


class _FaultyPayload(Mapping[str, object]):
    """Payload whose get() raises for a target field."""

    def __init__(self, values: dict[str, object]) -> None:
        self._values = values

    def get(self, key: str, default: object | None = None) -> object | None:
        if key == "broken_get":
            raise ValueError("payload get failed")
        return self._values.get(key, default)

    def __getitem__(self, key: str) -> object:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


def test_payload_display_name_skips_get_and_str_failures() -> None:
    """Display-name lookup should skip bad fields and return the fallback."""
    payload = _FaultyPayload(
        {
            "broken_get": "ignored",
            "broken_strip": _BadStripValue("ignored"),
            "broken_str": _BadStrValue(),
        }
    )

    assert (
        OPNsenseEntity.payload_display_name(
            payload,
            "fallback",
            "broken_get",
            "broken_strip",
            "broken_str",
            "missing",
        )
        == "fallback"
    )


def test_init_sets_unique_and_name_suffixes(
    make_config_entry: Callable[..., MockConfigEntry], dummy_coordinator: MagicMock
) -> None:
    """Verify unique_id and suffix-only name handling for base entities."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev-123", "url": "http://x"}, title="MyBox")
    coord = dummy_coordinator
    ent = OPNsenseBaseEntity(
        config_entry=entry, coordinator=coord, unique_id_suffix="suf", name_suffix="Name"
    )

    assert hasattr(ent, "unique_id")
    # deterministically compute expected slug from device_unique_id and assert
    device_unique = entry.data.get(CONF_DEVICE_UNIQUE_ID)
    expected_prefix = slugify(device_unique)
    # entity unique id is slugified(device_unique_id) + '_' + suffix
    assert ent.unique_id is not None
    assert ent.unique_id.startswith(f"{expected_prefix}_")
    assert ent.unique_id.endswith("_suf")
    assert ent.unique_id == "dev_123_suf"
    assert ent.has_entity_name is True
    assert hasattr(ent, "name")
    assert ent.name == "Name"


def test_available_property_toggle(
    make_config_entry: Callable[..., MockConfigEntry], dummy_coordinator: MagicMock
) -> None:
    """Entity available property reflects internal availability flag."""
    entry = make_config_entry()
    coord = dummy_coordinator
    ent = OPNsenseBaseEntity(config_entry=entry, coordinator=coord, unique_id_suffix="test")
    assert ent.available is False
    ent._available = True
    assert ent.available is True


def test_device_info_name_prefers_title_and_fallback_to_state(
    make_config_entry: Callable[..., MockConfigEntry], dummy_coordinator: MagicMock
) -> None:
    """Device info name prefers config entry title and falls back to state name."""
    # when title present
    entry = make_config_entry(
        {CONF_DEVICE_UNIQUE_ID: "dev-123", "url": "http://x"}, title="BoxTitle"
    )
    coord = dummy_coordinator
    ent = OPNsenseEntity(config_entry=entry, coordinator=coord, unique_id_suffix="test")
    info = ent.device_info
    assert info is not None
    assert info["name"] == "BoxTitle"

    # when title empty -> falls back to coordinator.data system_info.name
    entry2 = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev-123", "url": "http://x"}, title="")
    coord2 = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord2.data = {"system_info": {"name": "FromState"}}
    ent2 = OPNsenseEntity(config_entry=entry2, coordinator=coord2, unique_id_suffix="test")
    info2 = ent2.device_info
    assert info2 is not None
    assert info2["name"] == "FromState"


def test_get_opnsense_state_value_nested_lookup(
    make_config_entry: Callable[..., MockConfigEntry], dummy_coordinator: MagicMock
) -> None:
    """Nested state lookup returns deep values or None when missing."""
    entry = make_config_entry()
    coord = dummy_coordinator
    coord.data = {"a": {"b": {"c": 5}}}
    ent = OPNsenseBaseEntity(config_entry=entry, coordinator=coord, unique_id_suffix="test")
    assert ent._get_opnsense_state_value("a.b.c") == 5
    assert ent._get_opnsense_state_value("non.existent.path") is None


def test_entity_helpers_fail_closed_for_non_mapping_coordinator_data(
    make_config_entry: Callable[..., MockConfigEntry], dummy_coordinator: MagicMock
) -> None:
    """Entity helper lookups should return ``None`` when coordinator data is malformed."""
    entry = make_config_entry()
    coord = dummy_coordinator
    coord.data = []
    ent = OPNsenseBaseEntity(config_entry=entry, coordinator=coord, unique_id_suffix="test")

    assert ent._mapping_at("anything") is None
    assert ent._list_at("anything") is None


def test_mark_unavailable_can_clear_attributes(
    make_config_entry: Callable[..., MockConfigEntry], dummy_coordinator: MagicMock
) -> None:
    """Marking unavailable can clear stale attributes when requested."""
    entry = make_config_entry()
    coord = dummy_coordinator
    ent = OPNsenseBaseEntity(config_entry=entry, coordinator=coord, unique_id_suffix="test")
    ent._available = True
    ent._attr_extra_state_attributes = {"stale": "value"}
    object.__setattr__(ent, "async_write_ha_state", lambda: None)

    ent._mark_unavailable(clear_attributes=True)

    assert ent.available is False
    assert ent.extra_state_attributes == {}


@pytest.mark.asyncio
async def test_async_added_to_hass_sets_client_and_calls_update(
    make_config_entry: Callable[..., MockConfigEntry], dummy_coordinator: MagicMock
) -> None:
    """async_added_to_hass attaches client and triggers update handler."""
    entry = make_config_entry()
    coord = dummy_coordinator
    # provide a runtime client
    client = object()
    # make_config_entry provides runtime_data; attach a client on it
    entry.runtime_data.opnsense_client = client

    ent = OPNsenseBaseEntity(config_entry=entry, coordinator=coord, unique_id_suffix="test")

    # stub the entity update handler to observe it being called
    called = {"count": 0}

    def fake_handle() -> None:
        """Record that the entity update callback was invoked."""
        called["count"] += 1

    object.__setattr__(ent, "_handle_coordinator_update", fake_handle)

    # provide a minimal hass stub so lifecycle behaves more like real HA
    ent.hass = MagicMock()
    # should not raise because runtime_data contains OPNSENSE_CLIENT
    await ent.async_added_to_hass()
    assert ent._client is client
    assert called["count"] == 1


@pytest.mark.asyncio
async def test_async_added_to_hass_missing_client_raises(
    make_config_entry: Callable[..., MockConfigEntry], dummy_coordinator: MagicMock
) -> None:
    """async_added_to_hass logs and returns when runtime client is missing."""
    entry = make_config_entry()
    coord = dummy_coordinator
    # runtime_data has opnsense_client attribute but it's None -> logs and returns
    entry.runtime_data.opnsense_client = None

    ent = OPNsenseBaseEntity(config_entry=entry, coordinator=coord, unique_id_suffix="test")

    # avoid writing HA state (which requires hass) by stubbing the handler
    object.__setattr__(ent, "_handle_coordinator_update", lambda: None)
    ent.hass = MagicMock()
    await ent.async_added_to_hass()
    assert ent._client is None


def test_device_info_variants(
    make_config_entry: Callable[..., MockConfigEntry], dummy_coordinator: MagicMock
) -> None:
    """Device info reflects identifiers and firmware when present."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev-123"})
    coord = dummy_coordinator
    # when coordinator.data is None
    coord.data = None
    ent = OPNsenseEntity(config_entry=entry, coordinator=coord, unique_id_suffix="test")
    info = ent.device_info
    assert info is not None
    assert info["identifiers"] == {(DOMAIN, "dev-123")}
    assert info["sw_version"] is None

    # when firmware present
    coord2 = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord2.data = {"host_firmware_version": "1.2.3"}
    ent2 = OPNsenseEntity(config_entry=entry, coordinator=coord2, unique_id_suffix="test")
    info2 = ent2.device_info
    assert info2 is not None
    assert info2["sw_version"] == "1.2.3"
