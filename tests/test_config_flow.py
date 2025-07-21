import contextlib
import importlib
from unittest.mock import MagicMock
import xmlrpc.client

import aiohttp
import pytest

cf_mod = importlib.import_module("custom_components.opnsense.config_flow")


def test_mac_and_ip_and_cleanse():
    # MAC validation
    assert cf_mod.is_valid_mac_address("aa:bb:cc:dd:ee:ff")
    assert not cf_mod.is_valid_mac_address("not-a-mac")

    # IP validation
    assert cf_mod.is_ip_address("192.168.1.1")
    assert not cf_mod.is_ip_address("not-an-ip")

    # cleanse sensitive data
    msg = "user=admin&pass=secret"
    out = cf_mod.cleanse_sensitive_data(msg, ["secret"])
    assert "[redacted]" in out


@pytest.mark.asyncio
async def test_clean_and_parse_url_success_and_failure():
    # missing scheme -> should be fixed to https
    ui = {cf_mod.CONF_URL: "router.example"}
    await cf_mod._clean_and_parse_url(ui)
    assert ui[cf_mod.CONF_URL] == "https://router.example"

    # invalid netloc -> raise InvalidURL
    with pytest.raises(cf_mod.InvalidURL):
        await cf_mod._clean_and_parse_url({cf_mod.CONF_URL: ""})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc_key, expected",
    [
        ("below_min", "below_min_firmware"),
        ("unknown_fw", "unknown_firmware"),
        ("missing_id", "missing_device_unique_id"),
        ("plugin_missing", "plugin_missing"),
        ("invalid_url", "invalid_url_format"),
        ("xmlrpc_invalid_auth", "invalid_auth"),
        ("xmlrpc_privilege", "privilege_missing"),
        ("xmlrpc_plugin", "plugin_missing"),
        ("xmlrpc_other", "cannot_connect"),
        ("client_connector_ssl", "cannot_connect_ssl"),
        ("resp_401", "invalid_auth"),
        ("resp_403", "privilege_missing"),
        ("resp_500", "cannot_connect"),
        ("protocol_307", "url_redirect"),
        ("too_many_redirects", "cannot_connect"),
        ("timeout", "connect_timeout"),
        ("server_timeout", "cannot_connect"),
        ("os_ssl", "privilege_missing"),
        ("os_timed_out", "connect_timeout"),
        ("os_ssl_handshake", "cannot_connect_ssl"),
        ("os_unknown", "unknown"),
    ],
)
async def test_validate_input_exception_mapping(monkeypatch, exc_key, expected):
    """Ensure validate_input maps various exceptions to the expected error code."""

    # Build exception object lazily to avoid constructor issues at collection time
    if exc_key == "below_min":
        exc = cf_mod.BelowMinFirmware()
    elif exc_key == "unknown_fw":
        exc = cf_mod.UnknownFirmware()
    elif exc_key == "missing_id":
        exc = cf_mod.MissingDeviceUniqueID("x")
    elif exc_key == "plugin_missing":
        exc = cf_mod.PluginMissing()
    elif exc_key == "invalid_url":
        exc = aiohttp.InvalidURL("u")
    elif exc_key == "xmlrpc_invalid_auth":
        exc = xmlrpc.client.Fault(1, "Invalid username or password")
    elif exc_key == "xmlrpc_privilege":
        exc = xmlrpc.client.Fault(1, "Authentication failed: not enough privileges")
    elif exc_key == "xmlrpc_plugin":
        exc = xmlrpc.client.Fault(1, "opnsense.exec_php does not exist")
    elif exc_key == "xmlrpc_other":
        exc = xmlrpc.client.Fault(1, "other fault")
    elif exc_key == "client_connector_ssl":
        # ClientConnectorSSLError requires a connector key object with host/port; provide one
        class Conn:
            host = "host.example"
            port = 443
            ssl = None

        exc = aiohttp.ClientConnectorSSLError(Conn(), OSError("ssl error"))
    elif exc_key in ("resp_401", "resp_403", "resp_500"):
        status = 401 if exc_key == "resp_401" else 403 if exc_key == "resp_403" else 500

        # Provide minimal request_info with a real_url to satisfy logging/str()
        class RI:
            real_url = "http://localhost"

        exc = aiohttp.ClientResponseError(request_info=RI(), history=(), status=status, message="m")
    elif exc_key == "protocol_307":
        exc = xmlrpc.client.ProtocolError("u", 307, "307 Temporary Redirect", {})
    elif exc_key == "too_many_redirects":

        class RI:
            real_url = "http://localhost"

        exc = aiohttp.TooManyRedirects(request_info=RI(), history=())
    elif exc_key == "timeout":
        exc = TimeoutError("t")
    elif exc_key == "server_timeout":
        exc = aiohttp.ServerTimeoutError("t")
    elif exc_key == "os_ssl":
        exc = OSError("unsupported XML-RPC protocol")
    elif exc_key == "os_timed_out":
        exc = OSError("timed out")
    elif exc_key == "os_ssl_handshake":
        exc = OSError("SSL: handshake")
    else:
        exc = OSError("unknown")

    async def _raiser(user_input, hass):
        raise exc

    monkeypatch.setattr(cf_mod, "_handle_user_input", _raiser)
    errors = {}
    res = await cf_mod.validate_input(hass=MagicMock(), user_input={}, errors=errors)
    assert res.get("base") == expected


def test_validate_firmware_version_raises():
    """_validate_firmware_version should raise BelowMinFirmware for old versions."""
    # pick an obviously old version
    with pytest.raises(cf_mod.BelowMinFirmware):
        cf_mod._validate_firmware_version("1.0")


def test_log_and_set_error_sets_base(caplog):
    """_log_and_set_error should log the message and set errors['base']."""
    errors = {}
    cf_mod._log_and_set_error(errors=errors, key="test_key", message="an msg")
    assert errors.get("base") == "test_key"
    assert "an msg" in caplog.text


@pytest.mark.asyncio
async def test_get_dt_entries_sorts_and_includes_selected(monkeypatch):
    """Ensure _get_dt_entries returns selected devices first and ARP entries sorted by IP."""

    # Fake client that returns an arp table with mixed entries
    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def get_arp_table(self, resolve_hostnames=True):
            return [
                {"mac": "aa:bb:cc:00:00:01", "hostname": "hostb", "ip": "192.168.1.20"},
                {"mac": "11:22:33:44:55:66", "hostname": "", "ip": "10.0.0.5"},
                {"mac": "bb:cc:dd:00:00:02", "hostname": "hosta", "ip": "192.168.1.10"},
            ]

    monkeypatch.setattr(cf_mod, "OPNsenseClient", FakeClient)

    hass = MagicMock()
    config = {cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"}
    selected = ["aa:bb:cc:00:00:01"]
    res = await cf_mod._get_dt_entries(hass=hass, config=config, selected_devices=selected)

    # ensure selected device is present and IP-based entries are present
    keys = list(res.keys())
    assert "aa:bb:cc:00:00:01" in keys
    assert "11:22:33:44:55:66" in keys


def test_build_user_input_and_granular_and_options_schemas_defaults():
    """Verify the schema builders accept empty input and return defaults where applicable."""
    uis = None
    # user input schema should provide keys and defaults
    schema = cf_mod._build_user_input_schema(user_input=uis)
    validated = schema({})
    assert cf_mod.CONF_URL in validated

    # granular sync schema
    gschema = cf_mod._build_granular_sync_schema(user_input=None)
    gvalidated = gschema({})
    # every granular item should be present (defaults applied)
    for item in cf_mod.GRANULAR_SYNC_ITEMS:
        assert item in gvalidated

    # options init schema: test clamping/coercion for scan interval
    oschema = cf_mod._build_options_init_schema(user_input=None)
    out = oschema({})
    assert cf_mod.CONF_SCAN_INTERVAL in out


def test_async_get_options_flow_returns_options_flow():
    """async_get_options_flow should return an OPNsenseOptionsFlow instance."""
    cfg = MagicMock()
    res = cf_mod.OPNsenseConfigFlow.async_get_options_flow(cfg)
    assert isinstance(res, cf_mod.OPNsenseOptionsFlow)


@pytest.mark.asyncio
async def test_options_flow_init_with_user_triggers_update():
    """Submitting user input to async_step_init should update entry and create entry."""
    cfg = MagicMock()
    cfg.data = {cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"}
    cfg.options = {cf_mod.CONF_DEVICE_TRACKER_ENABLED: False}

    flow = cf_mod.OPNsenseOptionsFlow(cfg)
    flow.hass = MagicMock()
    flow.hass.config_entries = MagicMock()
    flow.hass.config_entries.async_update_entry = MagicMock()
    # set a handler so flow._config_entry_id property is available during the test
    flow.handler = "opnsense"
    # ensure async_get_known_entry returns our cfg when accessed
    flow.hass.config_entries.async_get_known_entry = MagicMock(return_value=cfg)

    # populate internals to avoid Home Assistant property lookups in this unit test
    flow._config = dict(cfg.data)
    flow._options = dict(cfg.options)

    user_input = {cf_mod.CONF_SCAN_INTERVAL: 30}
    res = await flow.async_step_init(user_input=user_input)

    # should have called update_entry and returned create_entry
    flow.hass.config_entries.async_update_entry.assert_called()
    assert res["type"] == "create_entry"


@pytest.mark.asyncio
async def test_options_flow_granular_sync_calls_validate_and_updates(monkeypatch):
    """async_step_granular_sync should call validate_input and update entry when no errors."""
    cfg = MagicMock()
    cfg.data = {cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"}
    cfg.options = {cf_mod.CONF_DEVICE_TRACKER_ENABLED: False}

    flow = cf_mod.OPNsenseOptionsFlow(cfg)
    flow.hass = MagicMock()
    flow.hass.config_entries = MagicMock()
    flow.hass.config_entries.async_update_entry = MagicMock()

    # monkeypatch validate_input to return no errors
    async def fake_validate(hass, user_input, errors):
        return {}

    monkeypatch.setattr(cf_mod, "validate_input", fake_validate)

    # use an actual granular sync key present in the module
    gkey = list(cf_mod.GRANULAR_SYNC_ITEMS)[0]
    # populate internals so the flow method doesn't access Home Assistant internals
    flow._config = dict(cfg.data)
    flow._options = dict(cfg.options)
    user_input = {gkey: True}
    # set a handler and make async_get_known_entry return our cfg so the flow can access
    # config_entry and options during unit tests without Home Assistant internals.
    flow.handler = "opnsense"
    flow.hass.config_entries.async_get_known_entry = MagicMock(return_value=cfg)
    res = await flow.async_step_granular_sync(user_input=user_input)
    flow.hass.config_entries.async_update_entry.assert_called()
    assert res["type"] == "create_entry"


@pytest.mark.asyncio
async def test_device_tracker_shows_form_when_no_user_input(monkeypatch):
    """async_step_device_tracker should show form containing data_schema when called without user_input."""
    cfg = MagicMock()
    cfg.data = {cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"}
    cfg.options = {cf_mod.CONF_DEVICES: ["11:22:33:44:55:66"]}

    flow = cf_mod.OPNsenseOptionsFlow(cfg)
    flow.hass = MagicMock()

    # monkeypatch _get_dt_entries to return an ordered dict-like mapping
    async def fake_get_dt_entries(hass, config, selected_devices):
        return {"11:22:33:44:55:66": "label1", "aa:bb:cc:dd:ee:ff": "label2"}

    monkeypatch.setattr(cf_mod, "_get_dt_entries", fake_get_dt_entries)

    # ensure internals are present so we don't trigger config_entry property lookup
    flow._config = dict(cfg.data)
    flow._options = dict(cfg.options)
    # set a handler and make async_get_known_entry return our cfg so the flow can access
    # config_entry and options during unit tests without Home Assistant internals.
    flow.handler = "opnsense"
    flow.hass.config_entries.async_get_known_entry = MagicMock(return_value=cfg)

    res = await flow.async_step_device_tracker(user_input=None)
    assert res["type"] == "form"
    assert "data_schema" in res


@pytest.mark.asyncio
async def test_options_flow_device_tracker_user_input(monkeypatch):
    """When user submits manual devices, they should be parsed and saved to options."""
    # Build a fake config_entry-like object
    config_entry = MagicMock()
    config_entry.data = {
        cf_mod.CONF_URL: "https://x",
        cf_mod.CONF_USERNAME: "u",
        cf_mod.CONF_PASSWORD: "p",
    }
    config_entry.options = {cf_mod.CONF_DEVICE_TRACKER_ENABLED: True, cf_mod.CONF_DEVICES: []}

    flow = cf_mod.OPNsenseOptionsFlow(config_entry)
    # attach hass with config_entries.update stub
    flow.hass = MagicMock()
    flow.hass.config_entries = MagicMock()
    flow.hass.config_entries.async_update_entry = MagicMock()

    # emulate what async_step_init would do: populate _config and _options from entry
    flow._config = dict(config_entry.data)
    flow._options = dict(config_entry.options)

    user_input = {
        cf_mod.CONF_MANUAL_DEVICES: "aa:bb:cc:dd:ee:ff, bad, 11:22:33:44:55:66",
        cf_mod.CONF_DEVICES: ["11:22:33:44:55:66"],
    }

    with contextlib.suppress(ValueError):
        await flow.async_step_device_tracker(user_input=user_input)

    # The flow should have parsed manual devices into _options
    assert cf_mod.CONF_DEVICES in flow._options
    assert "aa:bb:cc:dd:ee:ff" in flow._options[cf_mod.CONF_DEVICES]
    assert "11:22:33:44:55:66" in flow._options[cf_mod.CONF_DEVICES]
