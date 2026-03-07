"""Captive portal voucher methods for OPNsenseClient."""

from collections.abc import MutableMapping
from typing import Any
from urllib.parse import quote

from ._typing import PyOPNsenseClientProtocol
from .exceptions import VoucherServerError
from .helpers import _LOGGER, human_friendly_duration, timestamp_to_datetime, try_to_int


class VouchersMixin(PyOPNsenseClientProtocol):
    """Captive portal voucher methods for OPNsenseClient."""

    async def generate_vouchers(self, data: MutableMapping[str, Any]) -> list:
        """Generate vouchers from the Voucher Server.

        Parameters
        ----------
        data : MutableMapping[str, Any]
            Input mapping used to build the request payload.

        Returns
        -------
        list
        List of generated voucher entries returned by the voucher service.


        """
        if data.get("voucher_server", None):
            server = data.get("voucher_server")
        else:
            if self._use_snake_case:
                servers = await self._safe_list_get("/api/captiveportal/voucher/list_providers")
            else:
                servers = await self._safe_list_get("/api/captiveportal/voucher/listProviders")
            if len(servers) == 0:
                raise VoucherServerError("No voucher servers exist")
            if len(servers) != 1:
                raise VoucherServerError(
                    "More than one voucher server. Must specify voucher server name"
                )
            server = servers[0]
        server_slug = quote(str(server), safe="")
        payload: dict[str, Any] = dict(data).copy()
        payload.pop("voucher_server", None)
        if self._use_snake_case:
            voucher_url: str = f"/api/captiveportal/voucher/generate_vouchers/{server_slug}/"
        else:
            voucher_url = f"/api/captiveportal/voucher/generateVouchers/{server_slug}/"
        _LOGGER.debug("[generate_vouchers] url: %s, payload: %s", voucher_url, payload)
        vouchers = await self._safe_list_post(
            voucher_url,
            payload=payload,
        )
        ordered_keys: list = [
            "username",
            "password",
            "vouchergroup",
            "starttime",
            "expirytime",
            "expiry_timestamp",
            "validity_str",
            "validity",
        ]
        for voucher in vouchers:
            validity = try_to_int(voucher.get("validity"))
            if validity is not None:
                voucher["validity_str"] = human_friendly_duration(validity)

            expiry_timestamp = try_to_int(voucher.get("expirytime"))
            if expiry_timestamp is not None:
                voucher["expiry_timestamp"] = expiry_timestamp
                voucher["expirytime"] = timestamp_to_datetime(expiry_timestamp)

            rearranged_voucher: dict[str, Any] = {
                key: voucher[key] for key in ordered_keys if key in voucher
            }
            voucher.clear()
            voucher.update(rearranged_voucher)

        _LOGGER.debug("[generate_vouchers] vouchers: %s", vouchers)
        return vouchers
