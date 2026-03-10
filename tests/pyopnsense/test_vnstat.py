"""Tests for `pyopnsense.vnstat`."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest


@pytest.mark.asyncio
async def test_parse_vnstat_payload_hourly_with_split_day_rows(make_client) -> None:
    """Hourly vnStat payloads should combine date rows with time rows."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        payload = {
            "response": """
 igc0 / hourly

         hour        rx      |     tx      |    total    |   avg. rate
     03/07/26
         18:00      1.00 GiB |  512.00 MiB |    1.50 GiB |    2.00 Mbit/s
         19:00      2.00 GiB |  256.00 MiB |    2.25 GiB |    3.00 Mbit/s
"""
        }
        parsed = client._parse_vnstat_payload(payload, expected_period="hourly")
        rows = parsed["interfaces"]["igc0"]
        assert len(rows) == 2
        assert rows[0]["label"] == "03/07/26 18:00"
        assert rows[0]["day"] == "03/07/26"
        assert rows[0]["hour"] == "18:00"
        assert rows[1]["label"] == "03/07/26 19:00"
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_parse_vnstat_month_label_apostrophe_format(make_client) -> None:
    """Monthly vnStat labels like ``Apr '25`` should parse as year/month."""
    client = make_client(session=MagicMock(spec=aiohttp.ClientSession))
    try:
        assert client._parse_month_label("Apr '25") == (2025, 4)
        assert client._parse_month_label("March '26") == (2026, 3)
        assert client._parse_month_label("2026-03") == (2026, 3)
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_vnstat_summary_from_hourly_daily_monthly(make_client) -> None:
    """get_vnstat should produce per-interface summary fields used by sensors."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        # Keep payload dates aligned with mocked OPNsense system time to avoid
        # day-boundary/timezone flakiness in CI.
        now = datetime(2000, 1, 15, 12, 0, 0)
        prev_hour = now - timedelta(hours=1)
        this_month = now.date().replace(day=1)
        prev_month = this_month - timedelta(days=1)
        rollover_date_header = (
            f"     {now.strftime('%m/%d/%y')}\n" if now.date() != prev_hour.date() else ""
        )

        hourly_payload = {
            "response": f"""
 igc0 / hourly

         hour        rx      |     tx      |    total    |   avg. rate
     {prev_hour.strftime("%m/%d/%y")}
         {prev_hour.strftime("%H:%M")}      1.00 GiB |    1.00 GiB |    2.00 GiB |    4.00 Mbit/s
{rollover_date_header}         {now.strftime("%H:%M")}      2.00 GiB |    1.00 GiB |    3.00 GiB |    6.00 Mbit/s
 igc1 / hourly

         hour        rx      |     tx      |    total    |   avg. rate
     {prev_hour.strftime("%m/%d/%y")}
         {prev_hour.strftime("%H:%M")}      512.00 MiB |  512.00 MiB |    1.00 GiB |    2.00 Mbit/s
{rollover_date_header}         {now.strftime("%H:%M")}      1.00 GiB |  512.00 MiB |    1.50 GiB |    3.00 Mbit/s
"""
        }
        daily_payload = {
            "response": f"""
 igc0 / daily

          day        rx      |     tx      |    total    |   avg. rate
      {(now.date() - timedelta(days=1)).strftime("%m/%d/%y")}      1.00 GiB |    1.00 GiB |    2.00 GiB |    1.00 Mbit/s
      {now.strftime("%m/%d/%y")}      2.00 GiB |    2.00 GiB |    4.00 GiB |    2.00 Mbit/s
 igc1 / daily

          day        rx      |     tx      |    total    |   avg. rate
      {(now.date() - timedelta(days=1)).strftime("%m/%d/%y")}    512.00 MiB |  512.00 MiB |    1.00 GiB |    0.50 Mbit/s
      {now.strftime("%m/%d/%y")}      1.00 GiB |  512.00 MiB |    1.50 GiB |    0.75 Mbit/s
"""
        }
        monthly_payload = {
            "response": f"""
 igc0 / monthly

        month        rx      |     tx      |    total    |   avg. rate
       {prev_month.strftime("%b '%y")}      3.00 GiB |    3.00 GiB |    6.00 GiB |    1.00 Mbit/s
       {this_month.strftime("%b '%y")}      4.00 GiB |    4.00 GiB |    8.00 GiB |    2.00 Mbit/s
 igc1 / monthly

        month        rx      |     tx      |    total    |   avg. rate
       {prev_month.strftime("%b '%y")}      1.00 GiB |    1.00 GiB |    2.00 GiB |    1.00 Mbit/s
       {this_month.strftime("%b '%y")}      1.50 GiB |    1.50 GiB |    3.00 GiB |    2.00 Mbit/s
"""
        }

        client._safe_dict_get = AsyncMock(
            side_effect=[hourly_payload, daily_payload, monthly_payload]
        )
        client._safe_dict_post = AsyncMock(return_value={"datetime": "2000-01-15 12:00:00 EST"})
        vnstat = await client.get_vnstat()

        gib = 1024**3
        assert vnstat["interface_count"] == 2
        igc0_metrics = vnstat["interfaces"]["igc0"]["metrics"]
        assert igc0_metrics["vnstat_today"]["total_bytes"] == 4 * gib
        assert igc0_metrics["vnstat_today"]["rx_bytes"] == 2 * gib
        assert igc0_metrics["vnstat_today"]["tx_bytes"] == 2 * gib
        assert igc0_metrics["vnstat_this_month"]["total_bytes"] == 8 * gib
        assert igc0_metrics["vnstat_yesterday_total"]["total_bytes"] == 2 * gib
        assert igc0_metrics["vnstat_last_month_total"]["total_bytes"] == 6 * gib
        assert igc0_metrics["vnstat_last_hour_total"]["total_bytes"] == 3 * gib

        igc1_metrics = vnstat["interfaces"]["igc1"]["metrics"]
        assert igc1_metrics["vnstat_today"]["total_bytes"] == int(1.5 * gib)
        assert igc1_metrics["vnstat_today"]["rx_bytes"] == 1 * gib
        assert igc1_metrics["vnstat_today"]["tx_bytes"] == int(0.5 * gib)
        assert igc1_metrics["vnstat_this_month"]["total_bytes"] == 3 * gib
        assert igc1_metrics["vnstat_yesterday_total"]["total_bytes"] == 1 * gib
        assert igc1_metrics["vnstat_last_month_total"]["total_bytes"] == 2 * gib
        assert igc1_metrics["vnstat_last_hour_total"]["total_bytes"] == int(1.5 * gib)
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_vnstat_uses_systemtime_endpoint_path(make_client) -> None:
    """get_vnstat should query snake_case and camelCase system-time endpoints correctly."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._safe_dict_get = AsyncMock(return_value={"response": ""})
        client._safe_dict_post = AsyncMock(return_value={"datetime": "invalid"})

        client._use_snake_case = True
        await client.get_vnstat()
        client._safe_dict_post.assert_awaited_with("/api/diagnostics/system/system_time")

        client._safe_dict_post.reset_mock()
        client._use_snake_case = False
        await client.get_vnstat()
        client._safe_dict_post.assert_awaited_with("/api/diagnostics/system/systemTime")
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_opnsense_timezone_parse_and_fallback(make_client) -> None:
    """_get_opnsense_timezone should parse valid timezone strings and fallback on errors."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._use_snake_case = True
        client._safe_dict_post = AsyncMock(return_value={"datetime": "2026-03-07 12:00:00 EST"})
        parsed_tz = await client._get_opnsense_timezone()
        assert parsed_tz is not None
        parsed_dt = datetime(2026, 3, 7, 12, 0, 0, tzinfo=parsed_tz)
        assert parsed_tz.utcoffset(parsed_dt) == timedelta(hours=-5)

        client._safe_dict_post = AsyncMock(return_value={"datetime": "not-a-datetime"})
        fallback_tz = await client._get_opnsense_timezone()
        assert fallback_tz is not None
        local_tz = datetime.now().astimezone().tzinfo
        assert local_tz is not None
        now_local = datetime.now().astimezone()
        assert fallback_tz == local_tz or fallback_tz.utcoffset(now_local) == local_tz.utcoffset(
            now_local
        )
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_parse_vnstat_payload_and_helpers_edge_cases(make_client) -> None:
    """VnStat payload/helper methods should handle malformed and fallback scenarios."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        parsed_empty = client._parse_vnstat_payload({"response": 123}, expected_period="hourly")
        assert parsed_empty["interfaces"] == {}

        parsed_mismatch = client._parse_vnstat_payload(
            {"response": "igc0 / daily\n03/07/26    1.00 GiB | 1.00 GiB | 2.00 GiB | 1.00 Mbit/s"},
            expected_period="hourly",
        )
        assert parsed_mismatch["period"] == "daily"

        assert client._parse_vnstat_row("estimated      2.41 TiB | 676.07 GiB | 3.07 TiB |") is None
        assert client._parse_vnstat_row("nonsense row") is None
        assert client._to_bytes("3.14", "BAD") is None
        assert client._to_bits_per_second("3.14", "BAD") is None

        assert client._collect_vnstat_interfaces(
            {"interfaces": {"igc0": []}}, {"interfaces": {1: []}}
        ) == ["igc0"]
        assert client._interface_rows({"interfaces": {"igc0": [{"label": "x"}]}}, "igc0") == [
            {"label": "x"}
        ]
        assert client._interface_rows({"interfaces": []}, "igc0") == []

        tz = UTC
        today = datetime.now(tz=tz).date()
        yesterday = today - timedelta(days=1)
        assert (
            client._pick_daily_row(
                [
                    {"label": yesterday.strftime("%m/%d/%y")},
                    {"label": today.strftime("%m/%d/%y")},
                ],
                0,
                tz,
            )
            is not None
        )
        assert client._pick_daily_row([{"label": "bad"}], 0, tz) == {"label": "bad"}
        assert client._pick_daily_row([{"label": "bad0"}, {"label": "bad1"}], 1, tz) == {
            "label": "bad0"
        }

        this_month = datetime.now(tz=tz).strftime("%b '%y")
        assert client._pick_monthly_row([{"label": this_month}], 0, tz) == {"label": this_month}
        assert client._pick_monthly_row([{"label": "bad0"}, {"label": "bad1"}], 1, tz) == {
            "label": "bad0"
        }

        now_hour = datetime.now(tz=tz).replace(minute=0, second=0, microsecond=0)
        prev_hour = now_hour - timedelta(hours=1)
        rows = [
            {"label": prev_hour.strftime("%m/%d/%y %H:%M"), "total_bytes": 1},
            {"label": now_hour.strftime("%m/%d/%y %H:%M"), "total_bytes": 2},
        ]
        selected = client._pick_last_hour_row(rows, tz)
        assert selected == rows[0]
        assert client._parse_hourly_label(now_hour.strftime("%m/%d/%y %H:%M"), tz) is not None
        assert client._parse_hourly_label("bad", tz) is None
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_vnstat_metric_values_none_and_valid(make_client) -> None:
    """_metric_values should return valid mapping only when all fields are ints."""
    client = make_client(session=MagicMock(spec=aiohttp.ClientSession))
    try:
        assert client._metric_values(None) is None
        assert client._metric_values({"total_bytes": 1, "rx_bytes": 2, "tx_bytes": 3}) == {
            "total_bytes": 1,
            "rx_bytes": 2,
            "tx_bytes": 3,
        }
        assert client._metric_values({"total_bytes": 1, "rx_bytes": None, "tx_bytes": 3}) is None
    finally:
        await client.async_close()
