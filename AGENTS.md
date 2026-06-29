# AGENTS

## Purpose

- Provide clear, repo-specific instructions for autonomous agents working in this repository.

## General Guidelines

- Follow Home Assistant developer docs: https://developers.home-assistant.io/docs/.
- Be concise and explain coding steps briefly when making code changes; include code snippets and tests where relevant.
- For non-trivial edits, provide a short plan. For small, low-risk edits, implement and include a one-line summary.
- Focus on a single conceptual change at a time when public APIs or multiple modules are affected.
- Maintain project style and Python 3.14+ compatibility. Target latest Home Assistant core.
- Keep compatibility with the minimum supported OPNsense firmware documented in `custom_components/opnsense/const.py` and `README.md`.
- If deviating from these guidelines, explicitly state which guideline is deviated from and why.

## Agent permissions and venv policy

- Agents may create and use a repository-local venv at `./.venv`. Use `./.venv/bin/python`, `./.venv/bin/pytest`, and `./.venv/bin/prek` for local commands unless using the main checkout venv for a git worktree with no dependency changes.
- The project uses `pyproject.toml` dependency groups (`ha`, `lint`, `pytest`, `dev`). Installing packages from repo manifests into `./.venv` is allowed for running tests or local tooling after approval; avoid unrelated network operations without explicit consent.

## Folder structure (repo-specific)

- `custom_components/opnsense`: integration code.
- `tests`: pytest test suite and fixtures.
- `README.md`: primary documentation.
- `.github/workflows`: GitHub Workflows
- `.github/scripts`: scripts for GitHub Workflows

## Project structure expectations

- Keep code modular: separate files for entity types, services, and utilities.
- Store constants in `const.py` and use a `config_flow.py` for configuration flows.
- `hass-opnsense` now uses the external `aiopnsense` library exclusively for OPNsense API access (https://github.com/Snuffy2/aiopnsense and https://pypi.org/project/aiopnsense).
- Do not reintroduce `pyopnsense`, `client_factory.py`, `client_protocol.py`, or tests under `tests/pyopnsense`. Backend API behavior belongs in `aiopnsense`; this repository should consume it through `aiopnsense.OPNsenseClient` and `aiopnsense.exceptions`.
- Create configured clients through `custom_components/opnsense/helpers.py:create_opnsense_client` so Home Assistant aiohttp session handling, TLS options, logging names, and `throw_errors` behavior stay consistent.
- Keep the pinned `aiopnsense` version in `custom_components/opnsense/manifest.json` and `pyproject.toml` in sync.
- OPNsense Firmware 25.1+ remains supported, but Firewall and NAT rule switches are available only when the aiopnsense firewall payload supports them, currently OPNsense Firmware 26.1.1+.
- The deprecated OPNsense Home Assistant plugin is no longer supported or used. Handle legacy plugin-era entities only as migration or cleanup concerns; do not add new plugin-backed behavior.
- Config-entry migrations live in `custom_components/opnsense/__init__.py`. Be careful with entity registry and device registry changes, especially legacy firewall/NAT entity cleanup, because they affect existing user installations.
- Any changes that require changes to both hass-opnsense and aiopnsense require coordinated branches and PRs in both repositories. Update the aiopnsense pin when dependency behavior changes.

## Coding standards

- Add typing annotations to all functions and classes (including return types).
- Add or update docstrings for all files, classes and methods, including private methods and nested methods. Method docstrings must follow the Google Style.
- Preserve existing comments and keep imports at the top of files.
- Do not use `assert` or `cast` in main code.
- Follow existing repository style; run `prek`.
- Python 3.14 syntax is allowed, including PEP 695 type parameters and PEP 758 grouped exception handlers already used in the codebase.

## Local tooling note

- Use the repo's `prek` and `pytest` commands through the venv selected by the agent permissions and venv policy above.
- By default, run the full pytest suite. If running targeted tests, explain why.
- Avoid recommending `tox`, it is not in use by this repo.

## Error handling & logging

- Use Home Assistant's logging framework.
- Catch specific exceptions (do not catch Exception directly).
- Add robust error handling and clear debug/info logs.
- If tests fail due to missing dev dependencies, either install them into `./.venv` (if allowed) or report exact `pip install` commands.

## Testing

- Use `pytest` and Home Assistant pytest helpers (e.g., `MockConfigEntry`).
- Add typed, well-documented tests in `tests/` and use fixtures in `conftest.py`.
- Use `importlib` only in workflow script tests; minimize `cast` and `Any` unless the test boundary requires them.
- One test module per integration source file; achieve high coverage (target >= 80%).
- Parameterize tests when appropriate; avoid duplicate test functions.
- Mock `aiopnsense.OPNsenseClient` behavior at the integration boundary. Do not add tests for vendored or copied backend-client internals in this repository.
- Cover config-entry migrations, entity registry cleanup, and firmware-gated behavior when changing setup, coordinator, or switch logic.

## PR & branch behavior

- Create branches or PRs only when explicitly requested. Do not open PRs autonomously.

## Network / install consent

- Package installs from repo manifests for local tooling and tests are allowed after approval. Obtain explicit consent before unrelated network operations.

## CI/CD

- Use GitHub Actions for CI/CD where applicable.

## Conventions for changes and documentation

- When editing code, prefer fixing root causes over surface patches.
- Keep changes minimal and consistent with the codebase style.
- Add tests for any changed behavior and update documentation if needed.
