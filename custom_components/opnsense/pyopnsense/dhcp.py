"""DHCP and ARP methods for OPNsenseClient."""

from collections.abc import MutableMapping
from datetime import datetime, tzinfo
from typing import Any

import awesomeversion

from ._typing import PyOPNsenseClientProtocol
from .helpers import _LOGGER, _log_errors, get_ip_key, timestamp_to_datetime, try_to_int


class DHCPMixin(PyOPNsenseClientProtocol):
    """DHCP methods for OPNsenseClient."""

    @_log_errors
    async def get_arp_table(self, resolve_hostnames: bool = False) -> list:
        """Return the active ARP table.

        Parameters
        ----------
        resolve_hostnames : bool
            Whether reverse-DNS names should be resolved for ARP entries. Defaults to False.

        Returns
        -------
        list
        Parsed arp table payload returned by OPNsense APIs.


        """
        # [{'hostname': '?', 'ip-address': '<ip>', 'mac-address': '<mac>', 'interface': 'em0', 'expires': 1199, 'type': 'ethernet'}, ...]
        request_body: dict[str, Any] = {"resolve": "yes" if resolve_hostnames else "no"}
        arp_table_info = await self._safe_dict_post(
            "/api/diagnostics/interface/search_arp", payload=request_body
        )
        # _LOGGER.debug(f"[get_arp_table] arp_table_info: {arp_table_info}")
        arp_table: list = arp_table_info.get("rows", [])
        # _LOGGER.debug(f"[get_arp_table] arp_table: {arp_table}")
        return arp_table

    @_log_errors
    async def get_dhcp_leases(self, opnsense_tz: tzinfo | None = None) -> dict[str, Any]:
        """Return list of DHCP leases.

        Parameters
        ----------
        opnsense_tz : tzinfo | None
            Optional pre-fetched timezone for this refresh cycle.

        Returns
        -------
        dict[str, Any]
        Parsed dhcp leases payload returned by OPNsense APIs.


        """
        if opnsense_tz is None:
            opnsense_tz = await self._get_opnsense_timezone()
        leases_raw: list = await self._get_kea_dhcpv4_leases(opnsense_tz=opnsense_tz)
        leases_raw += await self._get_isc_dhcpv4_leases(opnsense_tz=opnsense_tz)
        leases_raw += await self._get_isc_dhcpv6_leases(opnsense_tz=opnsense_tz)
        leases_raw += await self._get_dnsmasq_leases(opnsense_tz=opnsense_tz)
        # TODO: Add Kea dhcpv6 leases if API ever gets added

        # _LOGGER.debug(f"[get_dhcp_leases] leases_raw: {leases_raw}")
        leases: dict[str, Any] = {}
        lease_interfaces: dict[str, Any] = await self._get_kea_interfaces()
        for lease in leases_raw:
            if (
                not isinstance(lease, MutableMapping)
                or not isinstance(lease.get("if_name", None), str)
                or len(lease.get("if_name", "")) == 0
            ):
                continue
            if_name = lease.pop("if_name", None)
            if_descr = lease.pop("if_descr", None)
            if if_name not in leases:
                lease_interfaces[if_name] = if_descr
                leases[if_name] = []
            leases[if_name].append(lease)

        sorted_lease_interfaces: dict[str, Any] = {
            key: lease_interfaces[key] for key in sorted(lease_interfaces)
        }
        sorted_leases: dict[str, Any] = {}
        for if_name in sorted(leases):
            if_subnet = leases[if_name]
            sorted_leases[if_name] = sorted(if_subnet, key=get_ip_key)

        dhcp_leases: dict[str, Any] = {
            "lease_interfaces": sorted_lease_interfaces,
            "leases": sorted_leases,
        }
        # _LOGGER.debug(f"[get_dhcp_leases] dhcp_leases: {dhcp_leases}")

        return dhcp_leases

    async def _get_kea_interfaces(self) -> dict[str, Any]:
        """Return interfaces setup for Kea.

        Returns
        -------
        dict[str, Any]
        Parsed kea interfaces payload returned by OPNsense APIs.


        """
        response = await self._safe_dict_get("/api/kea/dhcpv4/get")
        lease_interfaces: dict[str, Any] = {}
        general: dict[str, Any] = response.get("dhcpv4", {}).get("general", {})
        if general.get("enabled", "0") != "1":
            return {}
        for if_name, iface in general.get("interfaces", {}).items():
            if not isinstance(iface, MutableMapping):
                continue
            if iface.get("selected", 0) == 1 and iface.get("value", None):
                lease_interfaces[if_name] = iface.get("value")
        # _LOGGER.debug(f"[get_kea_interfaces] lease_interfaces: {lease_interfaces}")
        return lease_interfaces

    async def _get_kea_dhcpv4_leases(self, opnsense_tz: tzinfo | None = None) -> list:
        """Return IPv4 DHCP Leases by Kea.

        Parameters
        ----------
        opnsense_tz : tzinfo | None
            Optional pre-fetched timezone for this refresh cycle. Kea lease timestamps
            are parsed from epoch values and do not currently use this value.

        Returns
        -------
        list
        Parsed kea dhcpv4 leases payload returned by OPNsense APIs.


        """
        response = await self._safe_dict_get("/api/kea/leases4/search")
        if not isinstance(response.get("rows", None), list):
            return []
        if self._use_snake_case:
            res_resp = await self._safe_dict_get("/api/kea/dhcpv4/search_reservation")
        else:
            res_resp = await self._safe_dict_get("/api/kea/dhcpv4/searchReservation")
        if not isinstance(res_resp.get("rows", None), list):
            res_info = []
        else:
            res_info = res_resp.get("rows", [])
        reservations = {}
        for res in res_info:
            if not isinstance(res, MutableMapping):
                continue
            if res.get("hw_address", None):
                reservations.update({res.get("hw_address"): res.get("ip_address", "")})
        # _LOGGER.debug(f"[get_kea_dhcpv4_leases] reservations: {reservations}")
        leases_info: list = response.get("rows", [])
        # _LOGGER.debug(f"[get_kea_dhcpv4_leases] leases_info: {leases_info}")
        leases: list = []
        for lease_info in leases_info:
            if (
                lease_info is None
                or not isinstance(lease_info, MutableMapping)
                or lease_info.get("state", "0") != "0"
                or not lease_info.get("hwaddr", None)
            ):
                continue
            lease: dict[str, Any] = {}
            lease["address"] = lease_info.get("address", None)
            lease["hostname"] = (
                lease_info.get("hostname", None).strip(".")
                if isinstance(lease_info.get("hostname", None), str)
                and len(lease_info.get("hostname", "")) > 0
                else None
            )
            lease["if_descr"] = lease_info.get("if_descr", None)
            lease["if_name"] = lease_info.get("if_name", None)
            if (
                lease_info.get("hwaddr", None)
                and lease_info.get("hwaddr") in reservations
                and reservations[lease_info.get("hwaddr")] == lease_info.get("address", None)
            ):
                lease["type"] = "static"
            else:
                lease["type"] = "dynamic"
            lease["mac"] = lease_info.get("hwaddr", None)
            if try_to_int(lease_info.get("expire", None)):
                lease["expires"] = timestamp_to_datetime(
                    try_to_int(lease_info.get("expire", None)) or 0
                )
                if lease["expires"] < datetime.now().astimezone():
                    continue
            else:
                lease["expires"] = lease_info.get("expire", None)
            leases.append(lease)
        # _LOGGER.debug(f"[get_kea_dhcpv4_leases] leases: {leases}")
        return leases

    def _keep_latest_leases(self, reservations: list[dict]) -> list[dict]:
        """Deduplicate leases and keep the entry with the latest expiration.

        Parameters
        ----------
        reservations : list[dict]
            Reservations used by `_keep_latest_leases`.

        Returns
        -------
        list[dict]
        De-duplicated reservations retaining the latest expiration per unique lease.


        """
        seen: dict[tuple, dict] = {}

        for entry in reservations:
            if not isinstance(entry, MutableMapping):
                continue
            expire = try_to_int(entry.get("expire"), -1)
            if expire is None:
                continue
            # Create a key from all fields except 'expire'
            key = tuple(sorted((k, v) for k, v in entry.items() if k != "expire"))

            # Keep the entry with the latest expiration time
            seen_expire = try_to_int(seen.get(key, {}).get("expire"), -1)
            if seen_expire is None:
                seen_expire = -1
            if key not in seen or expire > seen_expire:
                seen[key] = dict(entry)

        return list(seen.values())

    async def _get_dnsmasq_leases(self, opnsense_tz: tzinfo | None = None) -> list:
        """Return Dnsmasq IPv4 and IPv6 DHCP Leases.

        Parameters
        ----------
        opnsense_tz : tzinfo | None
            Optional pre-fetched timezone for this refresh cycle. Dnsmasq lease timestamps
            are parsed from epoch values and do not currently use this value.

        Returns
        -------
        list
        Parsed dnsmasq leases payload returned by OPNsense APIs.


        """
        firmware = await self.get_host_firmware_version()

        try:
            if awesomeversion.AwesomeVersion(firmware) < awesomeversion.AwesomeVersion("25.1"):
                _LOGGER.debug("Skipping get_dnsmasq_leases for OPNsense < 25.1")
                return []
            if awesomeversion.AwesomeVersion(firmware) < awesomeversion.AwesomeVersion("25.1.7"):
                _LOGGER.debug("Skipping get_dnsmasq_leases for OPNsense < 25.1.7")
                return []
        except (awesomeversion.exceptions.AwesomeVersionCompareException, TypeError, ValueError):
            pass

        response = await self._safe_dict_get("/api/dnsmasq/leases/search")
        leases_info: list = response.get("rows", [])
        if not isinstance(leases_info, list):
            return []
        # _LOGGER.debug("[get_dnsmasq_leases] leases_info: %s", leases_info)
        cleaned_leases = self._keep_latest_leases(leases_info)
        # _LOGGER.debug("[get_dnsmasq_leases] cleaned_leases: %s", cleaned_leases)

        leases: list = []
        for lease_info in cleaned_leases:
            # _LOGGER.debug("[get_dnsmasq_leases] lease_info: %s", lease_info)
            if not isinstance(lease_info, MutableMapping):
                continue
            lease: dict[str, Any] = {}
            lease["address"] = lease_info.get("address", None)
            lease["hostname"] = (
                lease_info.get("hostname", None)
                if isinstance(lease_info.get("hostname", None), str)
                and lease_info.get("hostname", None) != "*"
                and len(lease_info.get("hostname", "")) > 0
                else None
            )
            lease["if_descr"] = lease_info.get("if_descr", None)
            lease["if_name"] = lease_info.get("if", None)
            if lease_info.get("is_reserved", "0") == "1":
                lease["type"] = "static"
            else:
                lease["type"] = "dynamic"
            lease["mac"] = (
                lease_info.get("hwaddr", None)
                if isinstance(lease_info.get("hwaddr", None), str)
                and len(lease_info.get("hwaddr", "")) > 0
                else None
            )

            if try_to_int(lease_info.get("expire", None)):
                lease["expires"] = timestamp_to_datetime(
                    try_to_int(lease_info.get("expire", None)) or 0
                )
                if lease["expires"] < datetime.now().astimezone():
                    continue
            else:
                lease["expires"] = lease_info.get("expire", None)
            leases.append(lease)
        # _LOGGER.debug("[get_dnsmasq_leases] leases: %s", leases)
        return leases

    async def _get_isc_dhcpv4_leases(self, opnsense_tz: tzinfo | None = None) -> list:
        """Return IPv4 DHCP Leases by ISC.

        Parameters
        ----------
        opnsense_tz : tzinfo | None
            Optional pre-fetched timezone for this refresh cycle.

        Returns
        -------
        list
        Parsed isc dhcpv4 leases payload returned by OPNsense APIs.


        """
        if not await self.is_endpoint_available("/api/dhcpv4/service/status"):
            _LOGGER.debug("ISC DHCP not installed")
            return []
        if self._use_snake_case:
            response = await self._safe_dict_get("/api/dhcpv4/leases/search_lease")
        else:
            response = await self._safe_dict_get("/api/dhcpv4/leases/searchLease")
        leases_info: list = response.get("rows", [])
        if not isinstance(leases_info, list):
            return []
        if opnsense_tz is None:
            opnsense_tz = await self._get_opnsense_timezone()
        # _LOGGER.debug(f"[get_isc_dhcpv4_leases] leases_info: {leases_info}")
        leases: list = []
        for lease_info in leases_info:
            # _LOGGER.debug(f"[get_isc_dhcpv4_leases] lease_info: {lease_info}")
            if (
                not isinstance(lease_info, MutableMapping)
                or lease_info.get("state", "") != "active"
                or not lease_info.get("mac", None)
            ):
                continue
            lease: dict[str, Any] = {}
            lease["address"] = lease_info.get("address", None)
            lease["hostname"] = (
                lease_info.get("hostname", None)
                if isinstance(lease_info.get("hostname", None), str)
                and len(lease_info.get("hostname", "")) > 0
                else None
            )
            lease["if_descr"] = lease_info.get("if_descr", None)
            lease["if_name"] = lease_info.get("if", None)
            lease["type"] = lease_info.get("type", None)
            lease["mac"] = lease_info.get("mac", None)
            if lease_info.get("ends", None):
                try:
                    dt: datetime = datetime.strptime(
                        lease_info.get("ends", None), "%Y/%m/%d %H:%M:%S"
                    )
                except (TypeError, ValueError):
                    continue
                lease["expires"] = dt.replace(tzinfo=opnsense_tz)
                if lease["expires"] < datetime.now().astimezone():
                    continue
            else:
                lease["expires"] = lease_info.get("ends", None)
            leases.append(lease)
        # _LOGGER.debug(f"[get_isc_dhcpv4_leases] leases: {leases}")
        return leases

    async def _get_isc_dhcpv6_leases(self, opnsense_tz: tzinfo | None = None) -> list:
        """Return IPv6 DHCP Leases by ISC.

        Parameters
        ----------
        opnsense_tz : tzinfo | None
            Optional pre-fetched timezone for this refresh cycle.

        Returns
        -------
        list
        Parsed isc dhcpv6 leases payload returned by OPNsense APIs.


        """
        if not await self.is_endpoint_available("/api/dhcpv6/service/status"):
            _LOGGER.debug("ISC DHCP not installed")
            return []
        if self._use_snake_case:
            response = await self._safe_dict_get("/api/dhcpv6/leases/search_lease")
        else:
            response = await self._safe_dict_get("/api/dhcpv6/leases/searchLease")
        leases_info: list = response.get("rows", [])
        if not isinstance(leases_info, list):
            return []
        if opnsense_tz is None:
            opnsense_tz = await self._get_opnsense_timezone()
        # _LOGGER.debug(f"[get_isc_dhcpv6_leases] leases_info: {leases_info}")
        leases: list = []
        for lease_info in leases_info:
            # _LOGGER.debug(f"[get_isc_dhcpv6_leases] lease_info: {lease_info}")
            if (
                not isinstance(lease_info, MutableMapping)
                or lease_info.get("state", "") != "active"
                or not lease_info.get("mac", None)
            ):
                continue
            lease: dict[str, Any] = {}
            lease["address"] = lease_info.get("address", None)
            lease["hostname"] = (
                lease_info.get("hostname", None)
                if isinstance(lease_info.get("hostname", None), str)
                and len(lease_info.get("hostname", "")) > 0
                else None
            )
            lease["if_descr"] = lease_info.get("if_descr", None)
            lease["if_name"] = lease_info.get("if", None)
            lease["type"] = lease_info.get("type", None)
            lease["mac"] = lease_info.get("mac", None)
            if lease_info.get("ends", None):
                try:
                    dt: datetime = datetime.strptime(
                        lease_info.get("ends", None), "%Y/%m/%d %H:%M:%S"
                    )
                except (TypeError, ValueError):
                    continue
                lease["expires"] = dt.replace(tzinfo=opnsense_tz)
                if lease["expires"] < datetime.now().astimezone():
                    continue
            else:
                lease["expires"] = lease_info.get("ends", None)
            leases.append(lease)
        # _LOGGER.debug(f"[get_isc_dhcpv6_leases] leases: {leases}")
        return leases
