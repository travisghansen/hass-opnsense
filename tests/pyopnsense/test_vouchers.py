"""Tests for `pyopnsense.vouchers`."""

from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from custom_components.opnsense import pyopnsense


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "safe_get_ret,safe_post_ret,data,expect_exc,expect_username,expect_extras",
    [
        ([], None, {}, pyopnsense.VoucherServerError, None, None),
        (["s1", "s2"], None, {}, pyopnsense.VoucherServerError, None, None),
        (
            None,
            [
                {
                    "username": "u",
                    "password": "p",
                    "vouchergroup": "g",
                    "starttime": "t",
                    "expirytime": 253402300799,
                    "validity": 65,
                }
            ],
            {"voucher_server": "srv"},
            None,
            "u",
            ["expiry_timestamp", "validity_str"],
        ),
    ],
)
async def test_generate_vouchers_server_selection_errors_and_success(
    safe_get_ret, safe_post_ret, data, expect_exc, expect_username, expect_extras
):
    """generate_vouchers: no servers / multiple servers -> error, provided server -> success.

    Consolidated test covering error cases and success with optional extra fields.
    """
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # follow original tests' snake_case setting where applicable
        client._use_snake_case = False
        if safe_get_ret is not None:
            client._safe_list_get = AsyncMock(return_value=safe_get_ret)
            with pytest.raises(expect_exc):
                await client.generate_vouchers(data)
            return

        # safe_post case: expect success and optional extra fields
        client._safe_list_post = AsyncMock(return_value=safe_post_ret)
        got = await client.generate_vouchers(data)
        assert isinstance(got, list) and got[0].get("username") == expect_username
        for key in expect_extras or []:
            assert key in got[0]
    finally:
        await client.async_close()
