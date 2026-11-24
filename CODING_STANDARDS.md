# Coding Standards

Rules for code in this repository, written so a reviewer can check a change against them. Anything `ruff`, `mypy`, `pydoclint`, `codespell` or `cspell` already enforces through `prek` is not repeated here; run `prek` and fix what it reports.

The project follows the [Home Assistant developer docs](https://developers.home-assistant.io/docs/) and targets Python 3.14+ and the latest Home Assistant core. Vocabulary in new names, comments, docs and user-facing text comes from [`GLOSSARY.md`](GLOSSARY.md); existing identifiers keep their names unless a change is made for that purpose.

## Architecture

- Integration code lives in `custom_components/opnsense`, one module per concern (entity platforms, coordinators, services, helpers).
- Constants live in `const.py`. Configuration flows live in `config_flow.py`. Config-entry migrations live in `migrate.py`.
- All OPNsense API access goes through `aiopnsense` (`aiopnsense.OPNsenseClient` and `aiopnsense.exceptions`). Backend API behavior belongs in `aiopnsense`, not here.
- Create clients only with `helpers.create_opnsense_client` (or `create_opnsense_client_from_config_entry`) so Home Assistant session handling, TLS options, logging names and `throw_errors` behavior stay consistent.
- Do not reintroduce `pyopnsense`, `client_factory.py`, `client_protocol.py` or tests under `tests/pyopnsense`.
- The pinned `aiopnsense` version in `custom_components/opnsense/manifest.json` and `pyproject.toml` must match. A change that needs new `aiopnsense` behavior ships with a coordinated `aiopnsense` change and an updated pin.
- Reach OPNsense firmware only through `get_firmware_update_info`, `get_host_firmware_version` and `install_firmware`; `get_firmware_requirements` is also allowed because it only reads library constants. Other firmware endpoints can make the Firewall contact its package mirrors on every poll, and `aiopnsense`'s request blocking and hourly check limit apply only through its public methods. `tests/test_firmware_endpoint_guard.py` enforces this.
- The deprecated OPNsense Home Assistant plugin is unsupported. Handle plugin-era entities only as migration or cleanup; add no plugin-backed behavior.
- OPNsense firmware 25.1+ is supported. Firewall and NAT rule switches exist only when the `aiopnsense` firewall payload supports them (currently OPNsense 26.1.1+). Keep the minimum supported firmware in `const.py` and `README.md` consistent, and gate new functionality on firmware in the same way.
- Entity registry and device registry changes, especially legacy firewall/NAT cleanup, affect existing installs. Put them in `migrate.py` and take particular care with them.

## Code

- Annotate every function and class, including return types.
- Do not use `assert` or `cast` in main code. Narrow types with real checks.
- Keep imports at the top of the file.
- Give every file, class and method a docstring, including private and nested methods. Method docstrings use Google style with `Args`, `Returns` and `Raises` where they apply.
- Keep existing comments. Correct a comment when a change makes it wrong; do not delete useful ones.
- Python 3.14 syntax is allowed, including PEP 695 type parameters and PEP 758 grouped exception handlers (`except A, B:`).
- Prefer fixing the root cause over a surface patch. Keep a change to one conceptual concern, and reuse existing helpers before adding new ones.

## Errors and logging

- Log through a module-level `_LOGGER: logging.Logger = logging.getLogger(__name__)`.
- Catch specific exceptions. Do not catch `Exception` or use a bare `except`.
- Add robust error handling and clear debug and info logs.

## Tests

- Use `pytest` with the Home Assistant pytest helpers (for example `MockConfigEntry`), shared fixtures in `conftest.py`, and typed, documented tests.
- One test module per integration source file (`tests/test_<module>.py`). Workflow script tests are the exception and stay separate.
- Test observable behavior at the relevant interface, including failure paths when they matter. Do not write tests that mirror implementation details, assert configuration text or duplicate existing checks.
- Mock `aiopnsense.OPNsenseClient` at the integration boundary. Do not test `aiopnsense` internals here.
- Parameterize instead of duplicating test functions.
- Cover config-entry migrations, entity registry cleanup and firmware-gated behavior whenever setup, coordinator or switch logic changes.
- Use `importlib` only in workflow script tests. Keep `cast` and `Any` to what a test boundary requires.
- Add or update tests when they protect a meaningful behavioral contract or reproduce a bug existing coverage would miss.
- Documentation, declarative configuration and small workflow changes need relevant validators, linters or focused runtime checks first; add automated tests only when executable logic or real operational risk warrants them.

## Documentation

- Update `README.md` and the files in `docs/` when user-visible behavior changes.
