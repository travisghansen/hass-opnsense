"""Shared testing utilities for hass-opnsense test modules."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final

from aiopnsense import OPNsenseClient
from homeassistant.const import CONF_VERIFY_SSL
import pytest

from custom_components.opnsense.const import DEFAULT_VERIFY_SSL
from custom_components.opnsense.device_tracker_evidence import DeviceTrackerEvidenceSnapshot


def stub_async_write_ha_state(entity: Any) -> None:
    """Replace Home Assistant state writes with a no-op for unit-level entity tests.

    Args:
        entity (Any): Entity instance under test.
    """
    object.__setattr__(entity, "async_write_ha_state", lambda: None)


def patch_opnsense_client(monkeypatch: pytest.MonkeyPatch, module: Any, client_ctor: Any) -> None:
    """Patch OPNsense client construction with a deterministic constructor.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest monkeypatch fixture.
        module (Any): Target module exposing client construction helpers.
        client_ctor (Any): Callable/class used to construct fake clients for tests.
    """

    def _create_opnsense_client(
        *,
        hass: Any,
        url: str,
        username: str,
        password: str,
        verify_ssl: bool | None,
        throw_errors: bool = False,
        name: str | None = None,
    ) -> Any:
        """Create a fake OPNsense client using the provided constructor.

        Args:
            hass (Any): Home Assistant instance passed by production code.
            url (str): OPNsense base URL from caller input.
            username (str): Username from caller input.
            password (str): Password from caller input.
            verify_ssl (bool | None): Optional TLS verification value passed by shared helper
                callers.
            throw_errors (bool): Error propagation behavior passed by shared helper callers.
            name (str | None): Optional client display name passed by caller.

        Returns:
            Any: Fake client instance returned by `client_ctor`.
        """
        del hass
        return client_ctor(
            url=url,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            throw_errors=throw_errors,
            name=name,
        )

    def _create_opnsense_client_from_config_entry(
        *,
        hass: Any,
        config_entry: Any,
        throw_errors: bool = False,
    ) -> Any:
        """Create a fake OPNsense client from a config entry.

        Args:
            hass (Any): Home Assistant instance passed by production code.
            config_entry (Any): Config entry with connection settings.
            throw_errors (bool): Error propagation behavior passed by shared helper callers.

        Returns:
            Any: Fake client instance returned by `client_ctor`.
        """
        return _create_opnsense_client(
            hass=hass,
            url=config_entry.data["url"],
            username=config_entry.data["username"],
            password=config_entry.data["password"],
            verify_ssl=config_entry.data.get(
                CONF_VERIFY_SSL,
                DEFAULT_VERIFY_SSL,
            ),
            throw_errors=throw_errors,
            name=config_entry.title,
        )

    if hasattr(module, "create_opnsense_client_from_config_entry"):
        monkeypatch.setattr(
            module,
            "create_opnsense_client_from_config_entry",
            _create_opnsense_client_from_config_entry,
        )
    if hasattr(module, "create_opnsense_client"):
        monkeypatch.setattr(module, "create_opnsense_client", _create_opnsense_client)


class _SameAsMac:
    """Sentinel meaning a neighbor entry's ``valid_mac`` equals its supplied ``mac``."""

    __slots__ = ()


SAME_AS_MAC: Final = _SameAsMac()


def arp_ndp_entry(
    mac: str | None,
    *,
    valid_mac: str | _SameAsMac | None = SAME_AS_MAC,
    ipv4_address: str | None = None,
    ipv6_address: str | None = None,
    hostname: str | None = None,
    manufacturer: str | None = None,
    expired: bool = False,
    interface: object = None,
    expires: object = None,
    arp_type: object = None,
) -> OPNsenseClient.ArpNdpEntry:
    """Build a client neighbor entry from already-normalized values.

    Every field is passed through unchanged; the test states the canonical values the client
    library would return. ``valid_mac`` defaults to ``mac``, so pass ``valid_mac=None`` for an
    entry whose MAC the library rejects.

    Args:
        mac (str | None): Permissively normalized MAC, or None when absent.
        valid_mac (str | _SameAsMac | None): Canonical six-octet MAC, None when invalid, or the
            default sentinel meaning ``mac``.
        ipv4_address (str | None): Canonical IPv4 address, or None.
        ipv6_address (str | None): Canonical IPv6 address, or None.
        hostname (str | None): Hostname with surrounding question marks removed, or None.
        manufacturer (str | None): Nonempty manufacturer, or None.
        expired (bool): Whether the neighbor entry has expired.
        interface (object): Copied interface metadata.
        expires (object): Copied raw expiration metadata.
        arp_type (object): Copied raw neighbor entry type.

    Returns:
        OPNsenseClient.ArpNdpEntry: Entry with the supplied fields.
    """
    return OPNsenseClient.ArpNdpEntry(
        mac=mac,
        valid_mac=mac if isinstance(valid_mac, _SameAsMac) else valid_mac,
        ipv4_address=ipv4_address,
        ipv6_address=ipv6_address,
        hostname=hostname,
        manufacturer=manufacturer,
        expired=expired,
        interface=interface,
        expires=expires,
        arp_type=arp_type,
    )


def arp_ndp_table(
    entries: Sequence[OPNsenseClient.ArpNdpEntry] = (),
    *,
    unparsed_row_count: int = 0,
    raw_rows: Sequence[object] = (),
) -> OPNsenseClient.ArpNdpTable:
    """Build a client neighbor table from explicit entries.

    Args:
        entries (Sequence[OPNsenseClient.ArpNdpEntry]): Normalized entries in table order.
        unparsed_row_count (int): Number of source rows that were not mappings.
        raw_rows (Sequence[object]): Raw rows kept for diagnostics only.

    Returns:
        OPNsenseClient.ArpNdpTable: Table built from the supplied values.
    """
    return OPNsenseClient.ArpNdpTable(
        entries=tuple(entries),
        unparsed_row_count=unparsed_row_count,
        raw_rows=tuple(raw_rows),
    )


def evidence_snapshot(
    *,
    arp: OPNsenseClient.ArpNdpTable | None = None,
    ndp: OPNsenseClient.ArpNdpTable | None = None,
    arp_current: bool = True,
    ndp_current: bool = True,
    observations: object = None,
) -> DeviceTrackerEvidenceSnapshot:
    """Build a tracker snapshot from already-normalized tables.

    Args:
        arp (OPNsenseClient.ArpNdpTable | None): Effective ARP table, or None when absent.
        ndp (OPNsenseClient.ArpNdpTable | None): Effective NDP table, or None when absent.
        arp_current (bool): Whether ``arp`` was fetched by the current refresh.
        ndp_current (bool): Whether ``ndp`` was fetched by the current refresh.
        observations (object): Raw host-observation response from the current refresh.

    Returns:
        DeviceTrackerEvidenceSnapshot: Snapshot built by the production constructor.
    """
    return DeviceTrackerEvidenceSnapshot.from_tables(
        arp=arp,
        ndp=ndp,
        arp_current=arp_current,
        ndp_current=ndp_current,
        observations=observations,
    )
