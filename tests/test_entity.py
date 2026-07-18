"""Unit tests for custom_components.opnsense.entity."""

from collections.abc import Callable, Iterator, Mapping
from unittest.mock import MagicMock

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense.const import (
    CONF_DEVICE_UNIQUE_ID,
    CONF_ENTRY_TYPE,
    DOMAIN,
    ENTRY_TYPE_CARP,
)
from custom_components.opnsense.coordinator import OPNsenseDataUpdateCoordinator
from custom_components.opnsense.entity import OPNsenseBaseEntity, OPNsenseEntity
from custom_components.opnsense.helpers import config_entry_identity


def test_payload_display_name_uses_scalar_fallback() -> None:
    """Display names use scalar payload values when no string field is available."""
    assert OPNsenseEntity.payload_display_name({"name": 42}, "fallback", "name") == "42"


class _BadStrValue:
    """Value object that raises when converted to a string."""

    def __str__(self) -> str:
        """Raise when the display-name helper converts this value to text."""
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
        """Store payload values used by mapping protocol tests.

        Args:
            values: Values returned by the mapping methods.
        """
        self._values = values

    def get(self, key: str, default: object | None = None) -> object | None:
        """Return a value or raise for the deliberately broken key.

        Args:
            key: Mapping key to read.
            default: Value returned when the key is absent.

        Returns:
            object | None: Stored value or the supplied default.

        Raises:
            ValueError: If ``key`` is the simulated broken field.
        """
        if key == "broken_get":
            raise ValueError("payload get failed")
        return self._values.get(key, default)

    def __getitem__(self, key: str) -> object:
        """Return the stored value for a required mapping key.

        Args:
            key: Mapping key to read.

        Returns:
            object: Stored mapping value.
        """
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        """Iterate over stored mapping keys.

        Returns:
            Iterator[str]: Iterator over the payload keys.
        """
        return iter(self._values)

    def __len__(self) -> int:
        """Return the number of stored mapping values.

        Returns:
            int: Number of payload values.
        """
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

    assert ent.unique_id is not None
    assert ent.unique_id == "dev_123_suf"
    assert ent.has_entity_name is True
    assert ent.name == "Name"

    carp_entry = make_config_entry(
        entry_id="carp-entry",
        data={CONF_ENTRY_TYPE: ENTRY_TYPE_CARP},
        title="CARP VIP",
    )
    carp_ent = OPNsenseBaseEntity(
        config_entry=carp_entry, coordinator=dummy_coordinator, unique_id_suffix="test"
    )
    assert config_entry_identity(carp_entry) == "carp-entry"
    assert carp_ent._device_unique_id == "carp-entry"
    assert carp_ent.unique_id == "carp_entry_test"


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
