"""Live interface traffic coordinator for OPNsense stream updates."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
import logging
import math
from typing import TYPE_CHECKING, Any

from aiopnsense.exceptions import OPNsenseError
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import CONF_SYNC_LIVE_TRAFFIC, DEFAULT_SYNC_OPTION_VALUE
from .coordinator import OPNsenseDataUpdateCoordinator

if TYPE_CHECKING:
    from aiopnsense import OPNsenseClient

_LOGGER: logging.Logger = logging.getLogger(__name__)

_STREAM_RATE_FIELD_MAP: dict[str, str] = {
    "rx_bytes_per_second": "inbytes_kilobytes_per_second",
    "tx_bytes_per_second": "outbytes_kilobytes_per_second",
    "rx_packets_per_second": "inpkts_packets_per_second",
    "tx_packets_per_second": "outpkts_packets_per_second",
}
_LIVE_TRAFFIC_INTERFACE_FIELDS: tuple[str, ...] = (
    "name",
    "status",
    "enabled",
    "interface",
    "device",
    "ipv4",
    "ipv6",
    "media",
    "vlan_tag",
    "mac",
)
_RETRY_DELAYS_SECONDS: tuple[int, ...] = (5, 10, 20, 30)
_AGGREGATE_LOG_SAMPLE_COUNT: int = 60


class OPNsenseLiveTrafficCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Consume interface traffic stream updates and expose live rates."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        client: OPNsenseClient,
        poll_interval: int = 1,
    ) -> None:
        """Initialize the live-traffic coordinator.

        Args:
            hass: Home Assistant instance.
            config_entry: Config entry that owns this coordinator.
            coordinator: Main coordinator whose interface metadata should be merged.
            client: OPNsense API client exposing ``stream_interface_traffic``.
            poll_interval: Poll interval in seconds for the stream call.
        """
        super().__init__(
            hass=hass,
            logger=_LOGGER,
            name=f"{config_entry.title} live interface traffic",
            update_interval=None,
            # Avoid implicit unload registration from DataUpdateCoordinator:
            # setup and teardown are managed explicitly by integration code.
            config_entry=None,
        )
        self._config_entry: ConfigEntry = config_entry
        self._coordinator: OPNsenseDataUpdateCoordinator = coordinator
        self._client: OPNsenseClient = client
        self._poll_interval: int = poll_interval
        self._task: asyncio.Task[None] | None = None
        self._shutdown_requested: bool = False
        self._failure_count: int = 0
        self._samples_since_log: int = 0
        self._interface_updates_since_log: int = 0
        self.data = {"interfaces": {}}

    async def async_start(self) -> None:
        """Start the stream loop as an entry-owned background task.

        The task is created only once; repeated calls are no-ops while it is active.
        """
        if self._task is not None and not self._task.done():
            return
        self._shutdown_requested = False
        self._task = self._config_entry.async_create_background_task(
            self.hass,
            self._run(),
            f"OPNsense live traffic {self.name}",
        )

    async def async_shutdown(self) -> None:
        """Stop the background stream loop and wait for the task to finish.

        This function cancels the running task and awaits it, forwarding cancellation
        into the running loop to ensure ``_run`` exits cleanly.
        """
        self._shutdown_requested = True
        try:
            task = self._task
            if task is not None and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    _LOGGER.debug("Live traffic task cancelled during shutdown")
        finally:
            self._task = None
            await super().async_shutdown()

    async def _run(self) -> None:
        """Run the stream loop and apply retry/backoff behavior on failures."""
        while not self._shutdown_requested:
            has_sample = await self._consume_stream()
            if self._shutdown_requested:
                break
            if has_sample:
                # Reset consecutive failures once we have usable live traffic.
                self._failure_count = 0

            if not self._read_live_traffic_flag():
                await asyncio.sleep(self._poll_interval)
                continue

            self._failure_count = min(self._failure_count + 1, len(_RETRY_DELAYS_SECONDS))
            delay = self._get_retry_delay()
            _LOGGER.warning("Retrying live traffic stream in %s seconds", delay)
            await asyncio.sleep(delay)

    def _get_retry_delay(self) -> int:
        """Return the current retry delay in seconds.

        Returns:
            int: Retry delay derived from ``_RETRY_DELAYS_SECONDS`` using the current
                consecutive failure count.
        """
        if self._failure_count <= 0:
            return _RETRY_DELAYS_SECONDS[0]
        delay_index = min(
            self._failure_count - 1,
            len(_RETRY_DELAYS_SECONDS) - 1,
        )
        return _RETRY_DELAYS_SECONDS[delay_index]

    async def _consume_stream(self) -> bool:
        """Consume a single stream cycle and apply any usable rate samples.

        Returns ``True`` only when at least one payload row was successfully converted
        into interface rates and published to listeners.

        Returns:
            bool: ``True`` when one or more usable samples were consumed, else
                ``False``.

        Raises:
            asyncio.CancelledError: Propagates when the stream is cancelled.
        """
        has_valid_sample = False
        try:
            async for payload in self._client.stream_interface_traffic(
                poll_interval=self._poll_interval
            ):
                if self._consume_payload(payload):
                    has_valid_sample = True
        except asyncio.CancelledError:
            raise
        except OPNsenseError as err:
            self.async_set_update_error(err)
            _LOGGER.warning("Live traffic stream failed with OPNsenseError: %s", err)
            return False
        except (TimeoutError, RuntimeError, TypeError, ValueError, AttributeError) as err:
            self.async_set_update_error(err)
            _LOGGER.warning("Live traffic stream failed: %s", err)
            return False

        if not has_valid_sample:
            self.async_set_update_error(
                RuntimeError("Live traffic stream ended without valid interface payload")
            )
            return False

        # The stream ended after providing valid samples; mark unavailable so
        # reconnect backoff is applied while preserving the last sample payload.
        self.async_set_update_error(
            RuntimeError("Live traffic stream ended and must be reconnected")
        )
        return True

    def _consume_payload(self, payload: Mapping[str, Any]) -> bool:
        """Merge a stream payload with coordinator interface metadata.

        Args:
            payload: Mapping payload from the stream with an ``interfaces`` section.

        Returns:
            bool: ``True`` when metadata and at least one usable interface row was
                merged and published.
        """
        if not isinstance(payload, Mapping):
            _LOGGER.debug("Ignoring non-mapping live traffic payload: %s", type(payload))
            return False

        interface_rows = payload.get("interfaces")
        if not isinstance(interface_rows, Mapping):
            _LOGGER.debug("Ignoring live traffic payload missing interfaces map")
            return False

        main_state = self._coordinator.data
        if not isinstance(main_state, Mapping):
            _LOGGER.debug("Skipping live traffic update because main state is unavailable")
            return False
        main_interfaces = main_state.get("interfaces")
        if not isinstance(main_interfaces, Mapping):
            _LOGGER.debug("Skipping live traffic update because metadata is unavailable")
            return False

        merged_interfaces: dict[str, Any] = {}
        for interface_name, rates in interface_rows.items():
            merged_interface = self._build_live_traffic_interface_data(
                interface_name,
                rates,
                main_interfaces,
            )
            if merged_interface is None:
                continue
            merged_interfaces[interface_name] = merged_interface

        if not merged_interfaces:
            return False

        merged_data: dict[str, Any] = {"interfaces": merged_interfaces}
        host_firmware_version = main_state.get("host_firmware_version")
        if host_firmware_version is not None:
            merged_data["host_firmware_version"] = host_firmware_version
        self._async_publish_data(merged_data)
        return True

    def _build_live_traffic_interface_data(
        self,
        interface_name: Any,
        rates: Any,
        main_interfaces: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """Build merged live traffic interface payload data.

        Args:
            interface_name: Interface identifier from the stream payload.
            rates: Stream-provided rates for that interface.
            main_interfaces: Metadata map keyed by interface name from coordinator data.

        Returns:
            dict[str, Any] | None: Merged metadata and mapped rates, or ``None`` when
                the row is incomplete or invalid.
        """
        if not isinstance(interface_name, str):
            return None
        if not isinstance(rates, Mapping):
            return None

        interface_rates: dict[str, Any] = {}
        for stream_key, state_key in _STREAM_RATE_FIELD_MAP.items():
            if stream_key not in rates:
                continue
            mapped_rate = self._map_stream_rate(stream_key, rates[stream_key])
            if mapped_rate is not None:
                interface_rates[state_key] = mapped_rate
        if not interface_rates:
            return None

        metadata = main_interfaces.get(interface_name)
        if not isinstance(metadata, Mapping):
            return None

        merged_interface = {
            field: metadata[field] for field in _LIVE_TRAFFIC_INTERFACE_FIELDS if field in metadata
        }
        merged_interface.update(interface_rates)
        return merged_interface

    @callback
    def _async_publish_data(self, data: dict[str, Any]) -> None:
        """Publish push data and periodically summarize live traffic activity.

        This coordinator has no scheduled refresh, so it can notify listeners
        directly without the per-sample debug message emitted by
        ``DataUpdateCoordinator.async_set_updated_data``.

        Args:
            data: Merged interface metadata and live traffic rates.
        """
        self.data = data
        self.last_update_success = True
        self._samples_since_log += 1
        interfaces = data.get("interfaces")
        if isinstance(interfaces, Mapping):
            self._interface_updates_since_log += len(interfaces)

        if self._samples_since_log >= _AGGREGATE_LOG_SAMPLE_COUNT:
            _LOGGER.debug(
                "Processed %d live interface traffic samples covering %d interface updates",
                self._samples_since_log,
                self._interface_updates_since_log,
            )
            self._samples_since_log = 0
            self._interface_updates_since_log = 0

        self.async_update_listeners()

    def _read_live_traffic_flag(self) -> bool:
        """Return whether live traffic should be synchronized for this entry.

        Returns:
            bool: ``True`` when live traffic is enabled for this config entry.
        """
        data: Mapping[str, Any] = self._config_entry.data
        return data.get(CONF_SYNC_LIVE_TRAFFIC, DEFAULT_SYNC_OPTION_VALUE)

    @staticmethod
    def _map_stream_rate(stream_key: str, raw_rate: Any) -> float | None:
        """Normalize a stream rate key into Home Assistant payload units.

        Args:
            stream_key: Stream field name from ``_STREAM_RATE_FIELD_MAP``.
            raw_rate: Incoming raw value to coerce and normalize.

        Returns:
            float | None: Rounded kilobytes-per-second or packets-per-second value, or
                ``None`` when invalid.
        """
        try:
            rate = float(raw_rate)
        except TypeError, ValueError:
            return None
        if not math.isfinite(rate) or rate < 0:
            return None
        if stream_key in {"rx_bytes_per_second", "tx_bytes_per_second"}:
            rate /= 1000.0
        return round(rate, 2)
