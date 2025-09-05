# hass-opnsense Home Assistant Integration Copilot Instructions

## General Guidelines
- Follow Home Assistant's developer documentation: https://developers.home-assistant.io/docs/.
- Be clear and explain what you are doing while coding; prefer short, actionable explanations.
- Provide code snippets and targeted tests to validate behavior.
- Provide a concise plan for non-trivial changes; for small, low-risk edits the agent may implement the change and provide a one-line summary immediately after.
- Focus on one conceptual change at a time when changes affect public APIs or multiple modules.
- Include concise explanations of what changed and why.
- Always check if the edit maintains the project's coding style.
- Develop for Python 3.13+.
- Develop with the latest Home Assistant core version.
- Transparency on deviations: When the agent cannot or chooses not to follow one or more rules in this document, it must explicitly call out which guideline(s) are not being followed and provide a concise reason (for example: system/developer instruction conflict, missing permissions, missing dev dependencies, user denied install/network access, or safety policy). This explanation must appear in the same response turn that performs the deviation.

## Agent permissions and venv policy
- The agent may create and use a repository-local virtual environment at `./.venv` and should reference the interpreter at `./.venv/bin/python` when running commands.
- The agent may install packages from repository manifests (for example `requirements-dev.txt`, `pyproject.toml`) into the repo venv without needing additional explicit approval for each run. The agent should prefer installing into `./.venv` rather than the global environment and must avoid performing unnecessary or unrelated network operations.


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
- By default, the agent should run the full pytest suite when tests are requested (the repo is small and full pytest runs are acceptable). If the user specifically asks for a focused test run, the agent may run targeted tests instead.
- Ensure that pytest and pre-commit are always run locally in the repository venv (`./.venv`) unless the user specifies a different environment.

## Error Handling & Logging
- Implement robust error handling and debug logging.
- Do not catch Exception directly; catch specific exceptions instead.
- Use Home Assistant's built-in logging framework.
- Fail-safe for missing dev dependencies: If a test run fails due to missing dev/test dependencies (for example pytest plugins or helpers), the agent should either:
  1. Attempt to install the missing dev dependencies into `./.venv` if installs are permitted, or
  2. Report the missing package(s) with an exact pip install command and fail gracefully.

## Testing
- Use pytest (not unittest) and pytest plugins for all tests.
- Use pytest-homeassistant-custom-component for Home Assistant–specific testing utilities (prefer `MockConfigEntry` for config entries) instead of creating custom ones.
- All tests must have typing annotations and robust docstrings.
- Use fixtures and mocks to isolate tests.
- Use `conftest.py` for shared test utilities and fixtures.
- Parameterize tests instead of creating multiple similar test functions when appropriate.
- When parameterizing tests, delete any legacy placeholder tests and related comments.
- Don't run pytest with `--disable-warnings` and address all warnings.
- Prefer running the full pytest suite by default for this repository. Only run focused tests when the user explicitly asks for targeted runs.
- One test file per integration file: every integration source file should have a single corresponding test module; add new unit tests for that integration to that existing test module and do not create additional test modules targeting the same integration except for explicit end-to-end/integration tests in `test_integration.py`.
- Achieve at least 80% code coverage.
- When making changes to code, include tests for the new/changed behavior; the agent should add tests alongside code edits even when changes are not minimally invasive.

## PR and branch behavior
- The agent will only create branches or open PRs when the user explicitly requests it or includes the hashtag `#github-pull-request_copilot-coding-agent` to hand off to the asynchronous coding agent.

## Network / install consent
- The agent must obtain explicit consent before performing network operations outside the repository that are not strictly necessary for running local tests (for example fetching external APIs or secrets). Package installs from PyPI required for running tests are allowed when the user has given permission to install dev dependencies.

## CI/CD
- Use GitHub Actions for CI/CD.
