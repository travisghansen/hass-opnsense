"""Repair flows for the OPNsense integration."""

from copy import deepcopy
import logging
from typing import TypeGuard

from aiopnsense.exceptions import OPNsenseError
from homeassistant.components.repairs import ConfirmRepairFlow, RepairsFlow, RepairsFlowResult
from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import issue_registry as ir
import voluptuous as vol

from .const import CONF_DEVICE_UNIQUE_ID, DOMAIN, TRACKED_MACS
from .helpers import create_opnsense_client_from_config_entry
from .repair_reconciliation import REPAIR_MARKER_KEY, build_repair_marker, parse_repair_marker

_DEVICE_ID_MISMATCH_ISSUE_SUFFIX = "_device_id_mismatched"
_LOGGER = logging.getLogger(__name__)


def build_device_id_mismatch_issue_id(entry_id: str) -> str:
    """Build the stable mismatch issue ID for a config entry."""
    return f"{entry_id}{_DEVICE_ID_MISMATCH_ISSUE_SUFFIX}"


def is_valid_device_id(device_id: object) -> TypeGuard[str]:
    """Return whether a device ID is a usable string identifier."""
    return isinstance(device_id, str) and bool(device_id.strip())


def _entry_matches_snapshot(
    entry: ConfigEntry | None,
    entry_id: str,
    data_snapshot: dict[str, object],
    options_snapshot: dict[str, object],
    unique_id_snapshot: str | None,
    *,
    allow_tracked_macs_mutation: bool = False,
) -> bool:
    """Return whether a re-fetched entry still matches the repair snapshot.

    Args:
        entry: Current config entry, if it still exists.
        entry_id: Entry ID captured when the repair started.
        data_snapshot: Original config-entry data mapping.
        options_snapshot: Original config-entry options mapping.
        unique_id_snapshot: Original config-entry unique ID.
        allow_tracked_macs_mutation: Whether tracked-MACS-only changes are ignored.

    Returns:
        bool: ``True`` when the entry identity and persisted values are unchanged.
    """
    normalized_snapshot = data_snapshot
    normalized_entry_data = dict(entry.data) if entry is not None else None
    if allow_tracked_macs_mutation:
        normalized_snapshot = _without_tracked_macs_for_recovery(normalized_snapshot)
        if normalized_entry_data is not None:
            normalized_entry_data = _without_tracked_macs_for_recovery(normalized_entry_data)

    return bool(
        entry is not None
        and entry.entry_id == entry_id
        and normalized_entry_data == normalized_snapshot
        and dict(entry.options) == options_snapshot
        and entry.unique_id == unique_id_snapshot
    )


def _without_tracked_macs_for_recovery(payload: dict[str, object]) -> dict[str, object]:
    """Return a snapshot copy that ignores setup-time tracked MAC mutations."""
    normalized_payload: dict[str, object] = dict(payload)
    normalized_payload.pop(TRACKED_MACS, None)
    return normalized_payload


def _get_entry_matching_snapshot(
    hass: HomeAssistant,
    entry_id: str,
    data_snapshot: dict[str, object],
    options_snapshot: dict[str, object],
    unique_id_snapshot: str | None,
) -> ConfigEntry | None:
    """Return the current entry only when it still matches the repair snapshot.

    Args:
        hass: Home Assistant instance that owns the config entry.
        entry_id: Entry ID captured when the repair started.
        data_snapshot: Original config-entry data mapping.
        options_snapshot: Original config-entry options mapping.
        unique_id_snapshot: Original config-entry unique ID.

    Returns:
        ConfigEntry | None: Matching current entry, if it is still owned.
    """
    current_entry = hass.config_entries.async_get_entry(entry_id)
    if not _entry_matches_snapshot(
        current_entry,
        entry_id,
        data_snapshot,
        options_snapshot,
        unique_id_snapshot,
    ):
        return None
    return current_entry


async def _async_validate_and_probe_device_id(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
) -> str | None:
    """Validate an OPNsense client and probe the current device identifier.

    Args:
        hass: Home Assistant instance that owns the config entry.
        config_entry: OPNsense config entry used to build the client.

    Returns:
        str | None: Device identifier returned by OPNsense.

    Raises:
        OPNsenseError: If validation or the Device ID probe fails.
    """
    client = create_opnsense_client_from_config_entry(
        hass=hass,
        config_entry=config_entry,
        throw_errors=True,
    )
    try:
        await client.validate()
        return await client.get_device_unique_id()
    finally:
        await client.async_close()


async def _async_prepare_entry_for_repair(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
) -> tuple[bool, bool]:
    """Check whether an entry can be safely unloaded before repair mutation.

    Args:
        hass: Home Assistant instance that owns the config entry.
        config_entry: OPNsense config entry being repaired.

    Returns:
        tuple[bool, bool]: Whether the entry is ready and whether it was loaded.
    """
    entry_was_loaded = config_entry.state is ConfigEntryState.LOADED
    if not config_entry.state.recoverable:
        return False, entry_was_loaded
    if entry_was_loaded:
        try:
            unload_ok = await hass.config_entries.async_unload(config_entry.entry_id)
        except HomeAssistantError, KeyError:
            _LOGGER.exception(
                "Device ID repair could not unload %s; aborting repair",
                config_entry.title,
            )
            return False, entry_was_loaded
        if not unload_ok:
            _LOGGER.debug("Device ID repair could not unload %s", config_entry.title)
            return False, entry_was_loaded
    return True, entry_was_loaded


def _device_id_repair_abort_reason(
    observed_device_id: object,
    expected_device_id: str,
    current_device_id: object,
) -> str | None:
    """Return the abort reason for an invalid replacement device ID.

    Args:
        observed_device_id: Device identifier returned by the firewall.
        expected_device_id: Replacement identifier stored in the repair issue.
        current_device_id: Identifier currently stored on the config entry.

    Returns:
        str | None: Repair abort reason, or ``None`` when the replacement is valid.
    """
    if not is_valid_device_id(observed_device_id):
        return "cannot_connect"
    if observed_device_id != expected_device_id or observed_device_id == current_device_id:
        return "entry_changed"
    return None


def async_create_device_id_mismatch_issue(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    observed_device_id: object,
) -> bool:
    """Create a fixable hardware-replacement issue for a normal device entry.

    Args:
        hass: Home Assistant instance that owns the issue registry.
        config_entry: Device config entry with the stale identifier.
        observed_device_id: Replacement device identifier observed at runtime.

    Returns:
        bool: `True` when the issue was created; otherwise `False` for invalid IDs.
    """
    old_device_id = config_entry.data[CONF_DEVICE_UNIQUE_ID]
    if not is_valid_device_id(old_device_id) or not is_valid_device_id(observed_device_id):
        return False
    ir.async_create_issue(
        hass=hass,
        domain=DOMAIN,
        issue_id=build_device_id_mismatch_issue_id(config_entry.entry_id),
        is_fixable=True,
        is_persistent=False,
        severity=ir.IssueSeverity.ERROR,
        translation_key="device_id_mismatched",
        translation_placeholders={
            "entry_title": config_entry.title,
            "old_device_id": old_device_id,
            "new_device_id": observed_device_id,
        },
        data={
            "entry_id": config_entry.entry_id,
            "old_device_id": old_device_id,
            "new_device_id": observed_device_id,
        },
    )
    return True


class DeviceIDMismatchRepairFlow(RepairsFlow):
    """Rebuild one OPNsense config entry after confirmed hardware replacement."""

    def __init__(self, entry_id: str, old_device_id: str, new_device_id: str) -> None:
        """Initialize a repair flow from issue data.

        Args:
            entry_id: Config-entry ID associated with the repair issue.
            old_device_id: Device identifier stored before the repair.
            new_device_id: Replacement identifier expected by the issue.
        """
        self._entry_id = entry_id
        self._old_device_id = old_device_id
        self._expected_device_id = new_device_id
        self._description_placeholders: dict[str, str] = {
            "entry_title": "",
            "old_device_id": old_device_id,
            "new_device_id": new_device_id,
        }

    async def async_step_init(self, user_input: dict[str, str] | None = None) -> RepairsFlowResult:
        """Load issue placeholders and display the confirmation step.

        Args:
            user_input: Ignored initialization payload.

        Returns:
            RepairsFlowResult: Confirmation form result.
        """
        del user_input
        issue_registry = ir.async_get(self.hass)
        issue = issue_registry.async_get_issue(self.handler, self.issue_id)
        if issue is not None and issue.translation_placeholders is not None:
            self._description_placeholders = dict(issue.translation_placeholders)
        return await self.async_step_confirm()

    async def _async_reload_with_recovery(
        self,
        entry: ConfigEntry,
        *,
        data_snapshot: dict[str, object],
        options_snapshot: dict[str, object],
        unique_id_snapshot: str | None,
    ) -> RepairsFlowResult:
        """Reload an updated entry and schedule guarded recovery on any reload failure.

        Args:
            entry: Updated OPNsense config entry to reload.
            data_snapshot: Persisted data expected before repair completion.
            options_snapshot: Persisted options expected before repair completion.
            unique_id_snapshot: Persisted unique ID expected before repair completion.

        Returns:
            RepairsFlowResult: Successful completion or a retryable repair failure.
        """
        try:
            if await self.hass.config_entries.async_reload(entry.entry_id):
                _LOGGER.info("Device ID repair reload completed for %s", entry.title)
                return self.async_create_entry(data={})
        except HomeAssistantError, KeyError:
            _LOGGER.exception(
                "Device ID repair did not finish for %s; cannot reload entry",
                entry.title,
            )
        self._schedule_recovery_reload(
            data_snapshot=data_snapshot,
            options_snapshot=options_snapshot,
            unique_id_snapshot=unique_id_snapshot,
            entry_id=entry.entry_id,
            entry_title=entry.title,
        )
        return self.async_abort(reason="repair_failed")

    def _schedule_recovery_reload(
        self,
        *,
        data_snapshot: dict[str, object],
        options_snapshot: dict[str, object],
        unique_id_snapshot: str | None,
        entry_id: str,
        entry_title: str,
    ) -> None:
        """Schedule a guarded recovery reload when the repair may have mutated state.

        Args:
            data_snapshot: Snapshot of the entry data used to detect changes.
            options_snapshot: Snapshot of entry options used to detect changes.
            unique_id_snapshot: Snapshot of the entry unique ID used to detect changes.
            entry_id: Config entry ID used to resolve the entry for reload.
            entry_title: Human-readable entry title for log context.
        """
        current_entry = self.hass.config_entries.async_get_entry(entry_id)
        if not _entry_matches_snapshot(
            current_entry,
            entry_id,
            data_snapshot,
            options_snapshot,
            unique_id_snapshot,
            allow_tracked_macs_mutation=True,
        ):
            return
        try:
            self.hass.config_entries.async_schedule_reload(entry_id)
        except HomeAssistantError, KeyError:
            _LOGGER.exception(
                "Device ID repair did not finish for %s; cannot schedule recovery "
                "reload after an interrupted repair mutation",
                entry_title,
            )

    def _schedule_changed_entry_reload(self, *, entry_id: str, entry_title: str) -> None:
        """Schedule recovery for an entry that changed while it was being unloaded.

        Args:
            entry_id: Config entry ID to schedule for reload.
            entry_title: Human-readable entry title for log context.
        """
        try:
            self.hass.config_entries.async_schedule_reload(entry_id)
        except HomeAssistantError, KeyError:
            _LOGGER.exception(
                "Device ID repair did not finish for %s; cannot schedule recovery "
                "reload after the config entry changed during unload",
                entry_title,
            )

    def _schedule_changed_entry_reload_if_needed(
        self,
        *,
        entry_was_loaded: bool,
        entry: ConfigEntry,
    ) -> None:
        """Schedule a recovery reload when a previously loaded entry changed."""
        if entry_was_loaded:
            self._schedule_changed_entry_reload(
                entry_id=entry.entry_id,
                entry_title=entry.title,
            )

    def _validate_entry_snapshot(
        self,
        *,
        current_entry: ConfigEntry | None,
        entry_was_loaded: bool,
        entry_data_snapshot: dict[str, object],
        entry_options_snapshot: dict[str, object],
        entry_unique_id_snapshot: str | None,
    ) -> ConfigEntry | None:
        """Return the entry when the runtime snapshot still matches."""
        if _entry_matches_snapshot(
            current_entry,
            self._entry_id,
            entry_data_snapshot,
            entry_options_snapshot,
            entry_unique_id_snapshot,
        ):
            return current_entry

        if current_entry is not None:
            self._schedule_changed_entry_reload_if_needed(
                entry_was_loaded=entry_was_loaded,
                entry=current_entry,
            )
        return None

    async def _async_validate_post_unload_reprobe(
        self,
        *,
        entry: ConfigEntry,
        entry_was_loaded: bool,
        entry_data_snapshot: dict[str, object],
        entry_options_snapshot: dict[str, object],
        entry_unique_id_snapshot: str | None,
    ) -> tuple[ConfigEntry, str] | str:
        """Strictly re-probe and validate an entry after it has been unloaded.

        Args:
            entry: Unloaded OPNsense config entry to re-probe.
            entry_was_loaded: Whether the entry was loaded before repair preparation.
            entry_data_snapshot: Original config-entry data mapping.
            entry_options_snapshot: Original config-entry options mapping.
            entry_unique_id_snapshot: Original config-entry unique ID.

        Returns:
            tuple[ConfigEntry, str] | str: Validated entry and device ID, or the
            repair abort reason.
        """
        try:
            reprobed_device_id = await _async_validate_and_probe_device_id(self.hass, entry)
        except OPNsenseError:
            self._schedule_changed_entry_reload_if_needed(
                entry_was_loaded=entry_was_loaded,
                entry=entry,
            )
            return "cannot_connect"

        if not is_valid_device_id(reprobed_device_id):
            self._schedule_changed_entry_reload_if_needed(
                entry_was_loaded=entry_was_loaded,
                entry=entry,
            )
            return "cannot_connect"

        current_entry = self._validate_entry_snapshot(
            current_entry=self.hass.config_entries.async_get_entry(self._entry_id),
            entry_was_loaded=entry_was_loaded,
            entry_data_snapshot=entry_data_snapshot,
            entry_options_snapshot=entry_options_snapshot,
            entry_unique_id_snapshot=entry_unique_id_snapshot,
        )
        if current_entry is None:
            return "entry_changed"
        entry = current_entry

        if abort_reason := _device_id_repair_abort_reason(
            reprobed_device_id,
            self._expected_device_id,
            entry.data.get(CONF_DEVICE_UNIQUE_ID),
        ):
            self._schedule_changed_entry_reload_if_needed(
                entry_was_loaded=entry_was_loaded,
                entry=entry,
            )
            return abort_reason

        duplicate = next(
            (
                candidate
                for candidate in self.hass.config_entries.async_entries(DOMAIN)
                if candidate.entry_id != entry.entry_id
                and candidate.unique_id == reprobed_device_id
            ),
            None,
        )
        if duplicate is not None:
            self._schedule_changed_entry_reload_if_needed(
                entry_was_loaded=entry_was_loaded,
                entry=entry,
            )
            return "already_configured"

        return entry, reprobed_device_id

    async def async_step_confirm(
        self, user_input: dict[str, str] | None = None
    ) -> RepairsFlowResult:
        """Confirm and perform the ordered registry rebuild.

        Args:
            user_input: Confirmation payload, or ``None`` to render the form.

        Returns:
            RepairsFlowResult: Confirmation form, abort result, or successful completion.
        """
        if user_input is None:
            return self.async_show_form(
                step_id="confirm",
                data_schema=vol.Schema({}),
                description_placeholders=self._description_placeholders,
            )

        entry = self.hass.config_entries.async_get_entry(self._entry_id)
        if entry is None:
            return self.async_abort(reason="entry_not_found")
        _LOGGER.info("Starting Device ID repair for %s", entry.title)
        entry_data_snapshot = deepcopy(dict(entry.data))
        entry_options_snapshot = deepcopy(dict(entry.options))
        entry_unique_id_snapshot = entry.unique_id
        stored_device_id = entry.data.get(CONF_DEVICE_UNIQUE_ID)
        expected_repair_marker = build_repair_marker(
            self._old_device_id,
            self._expected_device_id,
        )
        if stored_device_id == self._expected_device_id:
            if REPAIR_MARKER_KEY not in entry.data:
                return await self._async_reload_with_recovery(
                    entry,
                    data_snapshot=entry_data_snapshot,
                    options_snapshot=entry_options_snapshot,
                    unique_id_snapshot=entry_unique_id_snapshot,
                )
            repair_marker = parse_repair_marker(entry)
            if (
                repair_marker is None
                or repair_marker.old_device_id != self._old_device_id
                or repair_marker.new_device_id != self._expected_device_id
            ):
                return self.async_abort(reason="entry_changed")
            try:
                observed_device_id = await _async_validate_and_probe_device_id(self.hass, entry)
            except OPNsenseError:
                return self.async_abort(reason="cannot_connect")
            if not is_valid_device_id(observed_device_id):
                return self.async_abort(reason="cannot_connect")
            if observed_device_id != self._expected_device_id:
                return self.async_abort(reason="entry_changed")
            entry_ready, entry_was_loaded = await _async_prepare_entry_for_repair(self.hass, entry)
            if not entry_ready:
                return self.async_abort(reason="cannot_unload")
            current_entry = self._validate_entry_snapshot(
                current_entry=self.hass.config_entries.async_get_entry(self._entry_id),
                entry_was_loaded=entry_was_loaded,
                entry_data_snapshot=entry_data_snapshot,
                entry_options_snapshot=entry_options_snapshot,
                entry_unique_id_snapshot=entry_unique_id_snapshot,
            )
            if current_entry is None:
                return self.async_abort(reason="entry_changed")
            return await self._async_reload_with_recovery(
                current_entry,
                data_snapshot=entry_data_snapshot,
                options_snapshot=entry_options_snapshot,
                unique_id_snapshot=entry_unique_id_snapshot,
            )
        if stored_device_id != self._old_device_id:
            return self.async_abort(reason="entry_changed")

        try:
            observed_device_id = await _async_validate_and_probe_device_id(self.hass, entry)
        except OPNsenseError:
            return self.async_abort(reason="cannot_connect")

        current_entry = _get_entry_matching_snapshot(
            self.hass,
            self._entry_id,
            entry_data_snapshot,
            entry_options_snapshot,
            entry_unique_id_snapshot,
        )
        if current_entry is None:
            return self.async_abort(reason="entry_changed")
        entry = current_entry

        if abort_reason := _device_id_repair_abort_reason(
            observed_device_id,
            self._expected_device_id,
            entry.data.get(CONF_DEVICE_UNIQUE_ID),
        ):
            return self.async_abort(reason=abort_reason)

        duplicate = next(
            (
                candidate
                for candidate in self.hass.config_entries.async_entries(DOMAIN)
                if candidate.entry_id != entry.entry_id
                and candidate.unique_id == observed_device_id
            ),
            None,
        )
        if duplicate is not None:
            return self.async_abort(reason="already_configured")

        entry_ready, entry_was_loaded = await _async_prepare_entry_for_repair(self.hass, entry)
        if not entry_ready:
            return self.async_abort(reason="cannot_unload")

        current_entry = self._validate_entry_snapshot(
            current_entry=self.hass.config_entries.async_get_entry(self._entry_id),
            entry_was_loaded=entry_was_loaded,
            entry_data_snapshot=entry_data_snapshot,
            entry_options_snapshot=entry_options_snapshot,
            entry_unique_id_snapshot=entry_unique_id_snapshot,
        )
        if current_entry is None:
            return self.async_abort(reason="entry_changed")
        entry = current_entry

        reprobe_result = await self._async_validate_post_unload_reprobe(
            entry=entry,
            entry_was_loaded=entry_was_loaded,
            entry_data_snapshot=entry_data_snapshot,
            entry_options_snapshot=entry_options_snapshot,
            entry_unique_id_snapshot=entry_unique_id_snapshot,
        )
        if isinstance(reprobe_result, str):
            return self.async_abort(reason=reprobe_result)
        entry, reprobed_device_id = reprobe_result

        new_data = {
            **entry.data,
            CONF_DEVICE_UNIQUE_ID: reprobed_device_id,
            REPAIR_MARKER_KEY: expected_repair_marker,
        }

        try:
            updated = self.hass.config_entries.async_update_entry(
                entry,
                data=new_data,
                unique_id=observed_device_id,
            )
        except HomeAssistantError, KeyError:
            _LOGGER.exception(
                "Device ID repair did not finish for %s; cannot update config entry",
                entry.title,
            )
            if entry_was_loaded:
                self._schedule_recovery_reload(
                    data_snapshot=entry_data_snapshot,
                    options_snapshot=entry_options_snapshot,
                    unique_id_snapshot=entry_unique_id_snapshot,
                    entry_id=entry.entry_id,
                    entry_title=entry.title,
                )
            return self.async_abort(reason="repair_failed")

        if not updated:
            _LOGGER.error(
                "Device ID repair did not finish for %s; config-entry update made no changes",
                entry.title,
            )
            if entry_was_loaded:
                self._schedule_recovery_reload(
                    data_snapshot=entry_data_snapshot,
                    options_snapshot=entry_options_snapshot,
                    unique_id_snapshot=entry_unique_id_snapshot,
                    entry_id=entry.entry_id,
                    entry_title=entry.title,
                )
            return self.async_abort(reason="repair_failed")

        _LOGGER.info(
            "Device ID repair persisted replacement identity for %s; "
            "reloading for registry reconciliation",
            entry.title,
        )

        post_update_entry_data_snapshot: dict[str, object] = {
            **entry_data_snapshot,
            CONF_DEVICE_UNIQUE_ID: reprobed_device_id,
            REPAIR_MARKER_KEY: expected_repair_marker,
        }
        post_update_entry_unique_id_snapshot = reprobed_device_id

        return await self._async_reload_with_recovery(
            entry,
            data_snapshot=post_update_entry_data_snapshot,
            options_snapshot=entry_options_snapshot,
            unique_id_snapshot=post_update_entry_unique_id_snapshot,
        )


async def async_create_fix_flow(
    hass: HomeAssistant,
    issue_id: str,
    data: dict[str, str | int | float | None] | None,
) -> RepairsFlow:
    """Create a Device ID replacement flow for a well-formed issue.

    Args:
        hass: Home Assistant instance that owns the repair flow.
        issue_id: Issue identifier used to select the repair type.
        data: Issue data containing the entry and device identifiers.

    Returns:
        RepairsFlow: Device ID repair flow or a generic confirmation flow.
    """
    del hass
    if not issue_id.endswith(_DEVICE_ID_MISMATCH_ISSUE_SUFFIX) or data is None:
        return ConfirmRepairFlow()

    entry_id = data.get("entry_id")
    old_device_id = data.get("old_device_id")
    new_device_id = data.get("new_device_id")
    if not (
        isinstance(entry_id, str)
        and entry_id
        and is_valid_device_id(old_device_id)
        and is_valid_device_id(new_device_id)
        and issue_id == build_device_id_mismatch_issue_id(entry_id)
    ):
        return ConfirmRepairFlow()

    return DeviceIDMismatchRepairFlow(
        entry_id=entry_id,
        old_device_id=old_device_id,
        new_device_id=new_device_id,
    )
