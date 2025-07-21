from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from custom_components.opnsense import pyopnsense

# Utility function tests


def test_wireguard_is_connected_true():
    now = datetime.now().astimezone()
    assert pyopnsense.wireguard_is_connected(now - timedelta(minutes=2)) is True


def test_wireguard_is_connected_false():
    now = datetime.now().astimezone()
    assert pyopnsense.wireguard_is_connected(now - timedelta(minutes=5)) is False
    assert pyopnsense.wireguard_is_connected(None) is False


def test_human_friendly_duration():
    assert pyopnsense.human_friendly_duration(65) == "1 minute, 5 seconds"
    assert pyopnsense.human_friendly_duration(0) == "0 seconds"
    assert "month" in pyopnsense.human_friendly_duration(2419200)


def test_get_ip_key():
    assert pyopnsense.get_ip_key({"address": "192.168.1.1"})[0] == 0
    assert pyopnsense.get_ip_key({"address": "::1"})[0] == 1
    assert pyopnsense.get_ip_key({"address": "notanip"})[0] == 2
    assert pyopnsense.get_ip_key({})[0] == 3


def test_dict_get():
    data = {"a": {"b": {"c": 1}}, "x": [0, 1, 2]}
    assert pyopnsense.dict_get(data, "a.b.c") == 1
    assert pyopnsense.dict_get(data, "x.1") == 1
    assert pyopnsense.dict_get(data, "x.10", default=42) == 42


def test_timestamp_to_datetime():
    ts = int(datetime.now().timestamp())
    dt = pyopnsense.timestamp_to_datetime(ts)
    assert isinstance(dt, datetime)
    assert pyopnsense.timestamp_to_datetime(None) is None


def test_voucher_server_error():
    with pytest.raises(pyopnsense.VoucherServerError):
        raise pyopnsense.VoucherServerError


@pytest.mark.asyncio
async def test_client_name_property():
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost",
        username="user",
        password="pass",
        session=session,
    )
    assert client.name == "OPNsense"


@pytest.mark.asyncio
async def test_reset_and_get_query_counts():
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost",
        username="user",
        password="pass",
        session=session,
    )
    await client.reset_query_counts()
    rest, xml = await client.get_query_counts()
    assert rest == 0
    assert xml == 0


def test_try_to_int_and_float():
    assert pyopnsense.OPNsenseClient._try_to_int("5") == 5
    assert pyopnsense.OPNsenseClient._try_to_int(None, 7) == 7
    assert pyopnsense.OPNsenseClient._try_to_float("5.5") == 5.5
    assert pyopnsense.OPNsenseClient._try_to_float(None, 3.3) == 3.3


@pytest.mark.asyncio
async def test_safe_dict_get_and_list_get():
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost",
        username="user",
        password="pass",
        session=session,
    )
    # Patch _get to return dict or list
    with patch.object(client, "_get", new=AsyncMock(return_value={"foo": "bar"})):
        result = await client._safe_dict_get("/fake")
        assert result == {"foo": "bar"}
    with patch.object(client, "_get", new=AsyncMock(return_value=[1, 2, 3])):
        result = await client._safe_list_get("/fake")
        assert result == [1, 2, 3]
    with patch.object(client, "_get", new=AsyncMock(return_value=None)):
        result = await client._safe_dict_get("/fake")
        assert result == {}
        result = await client._safe_list_get("/fake")
        assert result == []


@pytest.mark.asyncio
async def test_safe_dict_post_and_list_post():
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost",
        username="user",
        password="pass",
        session=session,
    )
    with patch.object(client, "_post", new=AsyncMock(return_value={"foo": "bar"})):
        result = await client._safe_dict_post("/fake")
        assert result == {"foo": "bar"}
    with patch.object(client, "_post", new=AsyncMock(return_value=[1, 2, 3])):
        result = await client._safe_list_post("/fake")
        assert result == [1, 2, 3]
    with patch.object(client, "_post", new=AsyncMock(return_value=None)):
        result = await client._safe_dict_post("/fake")
        assert result == {}
        result = await client._safe_list_post("/fake")
        assert result == []


@pytest.mark.asyncio
async def test_get_ip_key_sorting():
    items = [
        {"address": "192.168.1.2"},
        {"address": "::1"},
        {"address": "notanip"},
        {},
    ]
    sorted_items = sorted(items, key=pyopnsense.get_ip_key)
    assert sorted_items[0]["address"] == "192.168.1.2"
    assert sorted_items[1]["address"] == "::1"
    assert sorted_items[2]["address"] == "notanip"
    assert sorted_items[3] == {}


@pytest.mark.asyncio
async def test_opnsenseclient_async_close():
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost",
        username="user",
        password="pass",
        session=session,
    )
    # Patch background tasks to be not done
    client._queue_monitor = MagicMock()
    client._queue_monitor.done.return_value = False
    client._workers = [MagicMock(), MagicMock()]
    for w in client._workers:
        w.done.return_value = False
    client._request_queue = MagicMock()
    client._request_queue.empty.side_effect = [False, True]
    await client.async_close()
    for w in client._workers:
        w.cancel.assert_called()
    client._queue_monitor.cancel.assert_called()


# More integration and async tests can be added for OPNsenseClient methods by mocking network calls.
# For >80% coverage, add tests for error handling, decorators, and edge cases as needed.
