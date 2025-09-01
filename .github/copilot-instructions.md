# hass-opnsense Home Assistant Integration Copilot Instructions

## General Guidelines
- Follow Home Assistant's [developer documentation](https://developers.home-assistant.io/docs/).
- Be chatty and teach about what you are doing while coding.
- Provide code snippets and explanations optimized for clarity and AI-assisted development.
- ALWAYS start by creating a detailed plan BEFORE making any edits.
- Focus on one conceptual change at a time.
- Include concise explanations of what changed and why.
- Always check if the edit maintains the project's coding style.
- Develop with the latest Home Assistant core version.
- Develop for Python 3.13+.

## Folder Structure

- `/custom_components/opnsense`: Contains the integration code.
- `/tests`: Contains the pytest code.
- `/README.md`: Is the primary documentation for the integration.

## Project Structure
- Modular design: distinct files for entity types, services, and utilities.
- Store constants in a separate `const.py` file.
- Use a `config_flow.py` file for configuration flows.

## Coding Standards
- Add typing annotations to all functions and classes, including return types.
- Add descriptive docstrings to all functions and classes (PEP 257 convention). Update existing docstrings if needed.
- Keep all existing comments in files.
- Ensure all imports are put at the top of the file.
- Pre-commit hooks are configured in `/.pre-commit-config.yaml`.
- Ruff enforces code style (settings in `/pyproject.toml`).
- mypy enforces static typing (settings in `/pyproject.toml`).

## Local tooling note
- This repository uses `pre-commit` (configured in `/.pre-commit-config.yaml`) and `pytest` (configured via `pyproject.toml`) as the primary local tooling for formatting, linting, and tests. Avoid recommending `tox` by default — some development environments may still have user-specific VS Code tasks that reference `tox`, which can be misleading. Prefer instructing contributors to run `pre-commit run --all-files` and `pytest` locally.

## Error Handling & Logging
- Implement robust error handling and debug logging.
- Do not catch Exception directly; catch specific exceptions instead.
- Use Home Assistant's built-in logging framework.

## Testing
- Use pytest (not unittest) and pytest plugins for all tests.
- Use pytest-homeassistant-custom-component for Home Assistant–specific testing utilities (prefer MockConfigEntry for config entries) instead of creating custom ones.
- All tests must have typing annotations and robust docstrings.
- Use fixtures and mocks to isolate tests.
- Use conftest.py for shared test utilities and fixtures.
- Parameterize tests instead of creating multiple similar test functions.
- When parameterizing tests, delete any legacy placeholder tests and related comments.
- Don't run pytest with `--disable-warnings` and address all warnings.
- One test file per integration file: every integration source file must have a single corresponding test module; add new unit tests for that integration to that existing test module and do not create additional test modules targeting the same integration. The only allowed exception is end-to-end/integration tests, which belong in a separate test_integration.py. If a test file becomes too large, refactor the integration code or discuss a controlled refactor — do not split tests across multiple modules for the same integration. PRs that add a second test module covering an existing integration should be rejected.
- Achieve at least 80% code coverage.

## CI/CD
- Use GitHub Actions for CI/CD.
