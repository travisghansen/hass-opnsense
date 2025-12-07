"""Unit tests for the config flow and options flow of the hass-opnsense integration.

Tests include URL parsing/validation, exception mapping for user input,
and options flow behaviors such as device tracker handling.
"""

import importlib
from unittest.mock import MagicMock
import xmlrpc.client

import aiohttp
import pytest
from yarl import URL

cf_mod = importlib.import_module("custom_components.opnsense.config_flow")


def test_mac_and_ip_and_cleanse():
    """Validate MAC/IP helpers and cleanse sensitive data."""
    assert cf_mod.is_valid_mac_address("aa:bb:cc:dd:ee:ff")
    assert not cf_mod.is_valid_mac_address("not-a-mac")

    # IP validation
    assert cf_mod.is_ip_address("192.168.1.1")
    assert not cf_mod.is_ip_address("not-an-ip")

    # cleanse sensitive data
    msg = "user=admin&pass=secret"
    out = cf_mod.cleanse_sensitive_data(msg, ["secret"])
    assert "[redacted]" in out
    assert "secret" not in out


@pytest.mark.asyncio
async def test_clean_and_parse_url_success_and_failure():
    """Clean and parse URL, fix missing scheme and handle invalid URL."""
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
        ("too_many_redirects", "url_redirect"),
        ("timeout", "connect_timeout"),
        ("server_timeout", "connect_timeout"),
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
        # Simulate an SSL-related client error that maps to "cannot_connect_ssl".
        # ClientSSLError (and its base ClientConnectorError) require a connection
        # key and an underlying os_error; provide a minimal connector-like
        # object and an OSError to construct the exception instance.
        class Conn:
            host = "host.example"
            port = 443
            ssl = None

        exc = aiohttp.ClientSSLError(Conn(), OSError("ssl error"))
    elif exc_key in ("resp_401", "resp_403", "resp_500"):
        status = 401 if exc_key == "resp_401" else 403 if exc_key == "resp_403" else 500

        # Provide minimal request_info with a real_url to satisfy logging/str()
        class RI:
            real_url = URL("http://localhost")

        exc = aiohttp.ClientResponseError(request_info=RI(), history=(), status=status, message="m")
    elif exc_key == "protocol_307":
        exc = xmlrpc.client.ProtocolError("u", 307, "307 Temporary Redirect", {})
    elif exc_key == "too_many_redirects":

        class RI:
            real_url = URL("http://localhost")

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

    async def _raiser(*args, **kwargs):
        raise exc

    monkeypatch.setattr(cf_mod, "_handle_user_input", _raiser)
    errors = {}
    res = await cf_mod.validate_input(
        hass=MagicMock(), user_input={}, errors=errors, config_step="user"
    )
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
async def test_get_dt_entries_sorts_and_includes_selected(monkeypatch, fake_client):
    """Ensure _get_dt_entries returns selected devices first and ARP entries sorted by IP."""

    # Create a client class via fixture and attach a get_arp_table implementation
    client_cls = fake_client()

    async def _get_arp_table(self, resolve_hostnames=True):
        return [
            {"mac": "aa:bb:cc:00:00:01", "hostname": "hostb", "ip": "192.168.1.20"},
            {"mac": "11:22:33:44:55:66", "hostname": "", "ip": "10.0.0.5"},
            {"mac": "bb:cc:dd:00:00:02", "hostname": "hosta", "ip": "192.168.1.10"},
        ]

    setattr(client_cls, "get_arp_table", _get_arp_table)
    monkeypatch.setattr(cf_mod, "OPNsenseClient", client_cls)

    # Patch async_create_clientsession on the module under test to avoid real network I/O
    def _fake_create_clientsession(*args, **kwargs):
        return MagicMock()

    monkeypatch.setattr(cf_mod, "async_create_clientsession", _fake_create_clientsession)

    hass = MagicMock()
    config = {cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"}
    selected = ["aa:bb:cc:00:00:01"]
    res = await cf_mod._get_dt_entries(hass=hass, config=config, selected_devices=selected)

    # ensure selected device is present and IP-based entries are present
    keys = list(res.keys())
    assert "aa:bb:cc:00:00:01" in keys
    assert "11:22:33:44:55:66" in keys
    # Selected device appears first
    assert keys[0] == "11:22:33:44:55:66"
    # IP-labeled entries are sorted numerically (10.0.0.5 before 192.168.1.10 < 192.168.1.20)
    vals = list(res.values())
    assert vals.index("10.0.0.5 [11:22:33:44:55:66]") < vals.index(
        "192.168.1.10 (hosta) [bb:cc:dd:00:00:02]"
    )
    assert vals.index("192.168.1.10 (hosta) [bb:cc:dd:00:00:02]") < vals.index(
        "192.168.1.20 (hostb) [aa:bb:cc:00:00:01]"
    )


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


@pytest.mark.parametrize(
    "input_value,expected",
    [
        (5, 10),  # below minimum -> clamped to 10
        (150, 150),  # within range -> unchanged
        (1000, 300),  # above maximum -> clamped to 300
    ],
)
def test_options_scan_interval_clamp(input_value, expected):
    """_build_options_init_schema should clamp CONF_SCAN_INTERVAL to min/max values."""
    oschema = cf_mod._build_options_init_schema(user_input=None)
    # pass a dict with the scan interval set to the test value
    validated = oschema({cf_mod.CONF_SCAN_INTERVAL: input_value})
    assert validated.get(cf_mod.CONF_SCAN_INTERVAL) == expected


@pytest.mark.parametrize(
    "input_value,expected",
    [
        (-10, 0),  # below minimum -> clamped to 0
        (300, 300),  # within range -> unchanged
        (1200, 1200),  # within new range (20 minutes) -> unchanged
        (3600, 3600),  # at maximum (1 hour) -> unchanged
        (5000, 3600),  # above maximum -> clamped to 3600
    ],
)
def test_options_device_tracker_consider_home_clamp(input_value, expected):
    """_build_options_init_schema should clamp CONF_DEVICE_TRACKER_CONSIDER_HOME to min/max values."""
    oschema = cf_mod._build_options_init_schema(user_input=None)
    # pass a dict with the consider_home value set to the test value
    validated = oschema({cf_mod.CONF_DEVICE_TRACKER_CONSIDER_HOME: input_value})
    assert validated.get(cf_mod.CONF_DEVICE_TRACKER_CONSIDER_HOME) == expected


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
    assert flow._options.get(cf_mod.CONF_SCAN_INTERVAL) == 30


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
    async def fake_validate(hass, user_input, errors, **kwargs):
        return {}

    monkeypatch.setattr(cf_mod, "validate_input", fake_validate)

    # use an actual granular sync key present in the module
    gkey = next(iter(cf_mod.GRANULAR_SYNC_ITEMS))
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
async def test_device_tracker_shows_form_when_no_user_input(monkeypatch, make_config_entry):
    """async_step_device_tracker should show form containing data_schema when called without user_input."""
    cfg = make_config_entry(
        data={cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"},
        options={cf_mod.CONF_DEVICES: ["11:22:33:44:55:66"]},
    )

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
async def test_options_flow_device_tracker_user_input(monkeypatch, make_config_entry):
    """When user submits manual devices, they should be parsed and saved to options."""
    # Build a fake config_entry using shared factory
    config_entry = make_config_entry(
        data={
            cf_mod.CONF_URL: "https://x",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
        },
        options={cf_mod.CONF_DEVICE_TRACKER_ENABLED: True, cf_mod.CONF_DEVICES: []},
    )

    flow = cf_mod.OPNsenseOptionsFlow(config_entry)
    # attach hass with config_entries.update stub
    flow.hass = MagicMock()
    flow.hass.config_entries = MagicMock()
    flow.hass.config_entries.async_update_entry = MagicMock()
    # make the flow aware of its handler so config_entry property works during tests
    flow.handler = "opnsense"
    flow.hass.config_entries.async_get_known_entry = MagicMock(return_value=config_entry)

    # emulate what async_step_init would do: populate _config and _options from entry
    flow._config = dict(config_entry.data)
    flow._options = dict(config_entry.options)

    user_input = {
        cf_mod.CONF_MANUAL_DEVICES: "aa:bb:cc:dd:ee:ff, bad, 11:22:33:44:55:66",
        cf_mod.CONF_DEVICES: ["11:22:33:44:55:66"],
    }

    result = await flow.async_step_device_tracker(user_input=user_input)

    # flow should have returned a create_entry
    assert result["type"] == "create_entry"

    # The flow should have parsed manual devices into _options
    assert cf_mod.CONF_DEVICES in flow._options
    assert "aa:bb:cc:dd:ee:ff" in flow._options[cf_mod.CONF_DEVICES]
    assert "11:22:33:44:55:66" in flow._options[cf_mod.CONF_DEVICES]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "granular_flag, config_step, expected_called",
    [
        # user step: no plugin check no matter the granular sync flag
        (True, "user", False),
        (False, "user", False),
        # granular_sync or reconfigure step: if granular sync is enabled, plugin check should happen
        (True, "granular_sync", True),
        (False, "granular_sync", False),
        (True, "reconfigure", True),
        (False, "reconfigure", False),
    ],
)
async def test_validate_input_user_respects_granular_flag_for_plugin_check(
    monkeypatch, granular_flag, config_step, expected_called, fake_flow_client
):
    """Plugin check not required for config step of user.

    Otherwise, plugin check is required if granular sync options is enabled
    """
    # Use shared fake_flow_client fixture to supply a FakeClient class
    client_cls = fake_flow_client()
    monkeypatch.setattr(cf_mod, "OPNsenseClient", client_cls)

    # avoid real network sessions
    monkeypatch.setattr(cf_mod, "async_create_clientsession", lambda *a, **k: MagicMock())

    user_input = {
        cf_mod.CONF_URL: "https://host.example",
        cf_mod.CONF_USERNAME: "user",
        cf_mod.CONF_PASSWORD: "pass",
        cf_mod.CONF_GRANULAR_SYNC_OPTIONS: granular_flag,
    }
    # Do not set granular sync items here; leave them absent so defaults apply

    # Create a real config flow and stub methods that interact with Home Assistant internals
    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()

    async def _noop(*args, **kwargs):
        return None

    # Prevent base ConfigFlow methods from touching HA internals during unit test
    flow.async_set_unique_id = _noop
    flow._abort_if_unique_id_configured = lambda: None

    # Call the requested config step which will call validate_input internally
    if config_step == "user":
        await flow.async_step_user(user_input=user_input)
    elif config_step == "granular_sync":
        # populate internal config as if the user completed the first step
        flow._config = {
            cf_mod.CONF_URL: "https://host.example",
            cf_mod.CONF_USERNAME: "user",
            cf_mod.CONF_PASSWORD: "pass",
            cf_mod.CONF_GRANULAR_SYNC_OPTIONS: granular_flag,
        }
        await flow.async_step_granular_sync(user_input={})
    elif config_step == "reconfigure":
        # reconfigure should behave like granular_sync for plugin-check testing;
        # populate internal config and invoke the reconfigure step
        reconfigure_entry = MagicMock()
        reconfigure_entry.data = {
            cf_mod.CONF_URL: "https://host.example",
            cf_mod.CONF_USERNAME: "user",
            cf_mod.CONF_PASSWORD: "pass",
            cf_mod.CONF_GRANULAR_SYNC_OPTIONS: granular_flag,
        }
        # Monkeypatch the helper the config flow uses to get the reconfigure entry
        flow._get_reconfigure_entry = lambda: reconfigure_entry
        # Prevent HA internals from being accessed if the flow reaches update/abort paths
        flow.hass.config_entries = MagicMock()
        flow.hass.config_entries.async_update_entry = MagicMock()
        await flow.async_step_reconfigure(user_input={})
    else:
        raise ValueError(f"unknown config_step: {config_step}")

    # ensure client was instantiated
    assert client_cls.last_instance is not None
    # Check whether the plugin check was called according to expected behavior
    called_count = getattr(client_cls.last_instance, "_is_plugin_called", 0)
    if expected_called:
        assert called_count > 0
    else:
        assert called_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "flow_type, require_plugin, expected_called",
    [
        ("config", True, True),
        ("config", False, False),
        ("options", True, True),
        ("options", False, False),
    ],
)
async def test_granular_sync_flow_plugin_check(
    monkeypatch, flow_type, require_plugin, expected_called, fake_flow_client
):
    """Test plugin check behavior when granular sync is enabled and granular items are set.

        For granular_sync step from both ConfigFlow and OptionsFlow:
    - If any SYNC_ITEMS_REQUIRING_PLUGIN is True -> is_plugin_installed should be called.
    - If none are True -> is_plugin_installed should NOT be called.
    """
    # Use shared fake_flow_client fixture
    client_cls = fake_flow_client()
    monkeypatch.setattr(cf_mod, "OPNsenseClient", client_cls)
    monkeypatch.setattr(cf_mod, "async_create_clientsession", lambda *a, **k: MagicMock())

    # Build a user_input payload for granular sync where items in SYNC_ITEMS_REQUIRING_PLUGIN are toggled
    # Start with all granular items as False, then set one plugin-required item True if require_plugin
    granular_input = dict.fromkeys(cf_mod.GRANULAR_SYNC_ITEMS, False)
    if require_plugin:
        # pick the first item that requires plugin
        plugin_item = list(cf_mod.SYNC_ITEMS_REQUIRING_PLUGIN)[0]
        granular_input[plugin_item] = True

    if flow_type == "config":
        # Prepare a config flow and populate internal config
        flow = cf_mod.OPNsenseConfigFlow()
        flow.hass = MagicMock()
        flow._config = {
            cf_mod.CONF_URL: "https://host.example",
            cf_mod.CONF_USERNAME: "user",
            cf_mod.CONF_PASSWORD: "pass",
            cf_mod.CONF_GRANULAR_SYNC_OPTIONS: True,
        }
        # Call the granular sync step which will invoke validate_input -> _handle_user_input
        await flow.async_step_granular_sync(user_input=granular_input)
    else:
        # Options flow branch
        cfg = MagicMock()
        cfg.data = {
            cf_mod.CONF_URL: "https://host.example",
            cf_mod.CONF_USERNAME: "user",
            cf_mod.CONF_PASSWORD: "pass",
            cf_mod.CONF_GRANULAR_SYNC_OPTIONS: True,
        }
        cfg.options = {cf_mod.CONF_DEVICE_TRACKER_ENABLED: False}
        flow = cf_mod.OPNsenseOptionsFlow(cfg)
        flow.hass = MagicMock()
        # emulate HA internals required by the options flow methods in tests
        flow.handler = "opnsense"
        flow.hass.config_entries = MagicMock()
        flow.hass.config_entries.async_get_known_entry = MagicMock(return_value=cfg)
        flow._config = dict(cfg.data)
        flow._options = dict(cfg.options)
        await flow.async_step_granular_sync(user_input=granular_input)

    # Check whether is_plugin_installed was invoked according to expectations
    assert client_cls.last_instance is not None
    called_count = getattr(client_cls.last_instance, "_is_plugin_called", 0)
    if expected_called:
        assert called_count > 0
    else:
        assert called_count == 0
