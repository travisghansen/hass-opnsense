"""Repair flows for the OPNsense integration."""

from copy import deepcopy
import logging
from typing import TypeGuard

from aiopnsense.exceptions import OPNsenseError
from homeassistant.components.repairs import ConfirmRepairFlow, RepairsFlow, RepairsFlowResult
from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import device_registry as dr, entity_registry as er, issue_registry as ir
import voluptuous as vol

from .const import CONF_DEVICE_UNIQUE_ID, DOMAIN
from .helpers import create_opnsense_client_from_config_entry

_ISSUE_SUFFIX = "_device_id_mismatched"
_LOGGER = logging.getLogger(__name__)


def is_valid_device_id(device_id: object) -> TypeGuard[str]:
    """Return whether a device ID is a usable string identifier."""
    return isinstance(device_id, str) and bool(device_id.strip())


def _entry_matches_snapshot(
    entry: ConfigEntry | None,
    entry_id: str,
    data_snapshot: dict[str, object],
    options_snapshot: dict[str, object],
    unique_id_snapshot: str | None,
) -> bool:
    """Return whether a re-fetched entry still matches the repair snapshot.

    Args:
        entry: Current config entry, if it still exists.
        entry_id: Entry ID captured when the repair started.
        data_snapshot: Original config-entry data mapping.
        options_snapshot: Original config-entry options mapping.
        unique_id_snapshot: Original config-entry unique ID.

    Returns:
        bool: ``True`` when the entry identity and persisted values are unchanged.
    """
    return bool(
        entry is not None
        and entry.entry_id == entry_id
        and dict(entry.data) == data_snapshot
        and dict(entry.options) == options_snapshot
        and entry.unique_id == unique_id_snapshot
    )


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
        OPNsenseError: If validation or the device-ID probe fails.
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
    if entry_was_loaded and not await hass.config_entries.async_unload(config_entry.entry_id):
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
        issue_id=f"{config_entry.entry_id}{_ISSUE_SUFFIX}",
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
                return self.async_create_entry(data={})
        except HomeAssistantError, KeyError:
            _LOGGER.exception(
                "Device-ID repair did not finish for %s; cannot reload entry",
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
        ):
            return
        try:
            self.hass.config_entries.async_schedule_reload(entry_id)
        except HomeAssistantError, KeyError:
            _LOGGER.exception(
                "Device-ID repair did not finish for %s; cannot schedule recovery "
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
                "Device-ID repair did not finish for %s; cannot schedule recovery "
                "reload after the config entry changed during unload",
                entry_title,
            )

    def _cleanup_entry_registries(self, entry: ConfigEntry) -> bool:
        """Remove the entry's entities and device associations from the registries.

        Args:
            entry: Config entry whose old registry data should be removed.

        Returns:
            bool: ``True`` when all registry cleanup operations succeeded.
        """
        entity_registry = er.async_get(self.hass)
        device_registry = dr.async_get(self.hass)
        entities_to_cleanup = er.async_entries_for_config_entry(entity_registry, entry.entry_id)
        devices_to_cleanup = dr.async_entries_for_config_entry(device_registry, entry.entry_id)

        failed_cleanup = False
        for entity in entities_to_cleanup:
            try:
                entity_registry.async_remove(entity.entity_id)
            except HomeAssistantError, KeyError, ValueError:
                failed_cleanup = True
                _LOGGER.exception(
                    "Device-ID repair did not finish for %s; cannot remove entity %s",
                    entry.title,
                    entity.entity_id,
                )

        for device in devices_to_cleanup:
            try:
                device_registry.async_update_device(
                    device.id,
                    remove_config_entry_id=entry.entry_id,
                )
            except HomeAssistantError, KeyError, ValueError:
                failed_cleanup = True
                _LOGGER.exception(
                    "Device-ID repair did not finish for %s; cannot update device %s",
                    entry.title,
                    device.id,
                )
        return not failed_cleanup

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
        entry_data_snapshot = deepcopy(dict(entry.data))
        entry_options_snapshot = deepcopy(dict(entry.options))
        entry_unique_id_snapshot = entry.unique_id
        stored_device_id = entry.data.get(CONF_DEVICE_UNIQUE_ID)
        if stored_device_id == self._expected_device_id:
            entry_ready, entry_was_loaded = await _async_prepare_entry_for_repair(self.hass, entry)
            if not entry_ready:
                return self.async_abort(reason="cannot_unload")
            current_entry = self.hass.config_entries.async_get_entry(self._entry_id)
            if current_entry is None or not _entry_matches_snapshot(
                current_entry,
                self._entry_id,
                entry_data_snapshot,
                entry_options_snapshot,
                entry_unique_id_snapshot,
            ):
                if entry_was_loaded and current_entry is not None:
                    self._schedule_changed_entry_reload(
                        entry_id=entry.entry_id,
                        entry_title=entry.title,
                    )
                return self.async_abort(reason="entry_changed")
            if not self._cleanup_entry_registries(current_entry):
                self._schedule_recovery_reload(
                    data_snapshot=entry_data_snapshot,
                    options_snapshot=entry_options_snapshot,
                    unique_id_snapshot=entry_unique_id_snapshot,
                    entry_id=current_entry.entry_id,
                    entry_title=current_entry.title,
                )
                return self.async_abort(reason="repair_failed")
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

        current_entry = self.hass.config_entries.async_get_entry(self._entry_id)
        if current_entry is None or not _entry_matches_snapshot(
            current_entry,
            self._entry_id,
            entry_data_snapshot,
            entry_options_snapshot,
            entry_unique_id_snapshot,
        ):
            if entry_was_loaded and current_entry is not None:
                self._schedule_changed_entry_reload(
                    entry_id=entry.entry_id,
                    entry_title=entry.title,
                )
            return self.async_abort(reason="entry_changed")
        entry = current_entry

        new_data = {**entry.data, CONF_DEVICE_UNIQUE_ID: observed_device_id}

        try:
            updated = self.hass.config_entries.async_update_entry(
                entry,
                data=new_data,
                unique_id=observed_device_id,
            )
        except HomeAssistantError, KeyError:
            _LOGGER.exception(
                "Device-ID repair did not finish for %s; cannot update config entry",
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
                "Device-ID repair did not finish for %s; config-entry update made no changes",
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

        post_update_entry_data_snapshot: dict[str, object] = {
            **entry_data_snapshot,
            CONF_DEVICE_UNIQUE_ID: observed_device_id,
        }
        post_update_entry_unique_id_snapshot = observed_device_id

        if not self._cleanup_entry_registries(entry):
            self._schedule_recovery_reload(
                data_snapshot=post_update_entry_data_snapshot,
                options_snapshot=entry_options_snapshot,
                unique_id_snapshot=post_update_entry_unique_id_snapshot,
                entry_id=entry.entry_id,
                entry_title=entry.title,
            )
            return self.async_abort(reason="repair_failed")

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
    """Create a device-ID replacement flow for a well-formed issue.

    Args:
        hass: Home Assistant instance that owns the repair flow.
        issue_id: Issue identifier used to select the repair type.
        data: Issue data containing the entry and device identifiers.

    Returns:
        RepairsFlow: Device-ID repair flow or a generic confirmation flow.
    """
    del hass
    if not issue_id.endswith(_ISSUE_SUFFIX) or data is None:
        return ConfirmRepairFlow()

    entry_id = data.get("entry_id")
    old_device_id = data.get("old_device_id")
    new_device_id = data.get("new_device_id")
    if not (
        isinstance(entry_id, str)
        and entry_id
        and is_valid_device_id(old_device_id)
        and is_valid_device_id(new_device_id)
        and issue_id == f"{entry_id}{_ISSUE_SUFFIX}"
    ):
        return ConfirmRepairFlow()

    return DeviceIDMismatchRepairFlow(
        entry_id=entry_id,
        old_device_id=old_device_id,
        new_device_id=new_device_id,
    )
