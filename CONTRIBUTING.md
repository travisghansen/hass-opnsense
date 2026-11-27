# Contribution Guidelines

Contributing to this project should be as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features

## GitHub is Used for Everything

GitHub is used to host code, to track issues and feature requests, as well as accept pull requests.

Pull requests are the best way to propose changes to the codebase.

1. Fork the repo and create your branch from `main`.
2. If you've changed something, update the documentation.
3. Follow [CODING_STANDARDS.md](CODING_STANDARDS.md) and make sure `prek` passes (see [Setting up the Development Environment](#setting-up-the-development-environment)).
4. Start the pull request title with a Conventional Commit prefix such as `fix:`, `feat:` or `chore(deps):`.
5. Issue that pull request!

## Report Bugs Using GitHub's [Issues](../../issues)

GitHub issues are used to track public bugs.  
Report a bug by [opening a new issue](../../issues/new/choose); it's that easy!

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can.
- Show logs
  - [Enable debug logging in Home Assistant](#enable-debug-logging-in-home-assistant)
  - When posting logs for an issue, be sure to include logs for both `custom_components.opnsense` and `aiopnsense` which will both be enabled by changing the config per the instructions below
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

People *love* thorough bug reports. I'm not even kidding.

## Enable debug logging in Home Assistant

To enable, add this or modify the logging section of your Home Assistant configuration.yaml:
```yaml
logger:
  default: warning
  logs:
    custom_components.opnsense: debug
```

> When posting logs for an issue, be sure to include logs for both `custom_components.opnsense` and `aiopnsense` which will both be enabled by changing the config as above

## Use a Consistent Coding Style

Follow [CODING_STANDARDS.md](CODING_STANDARDS.md). Formatting, linting, type checking and spell checking run through [prek](https://prek.j178.dev) hooks (ruff, mypy, pydoclint, codespell and cspell), so `prek` tells you what to fix.

Use the terms in [GLOSSARY.md](GLOSSARY.md) when naming things and writing docs.

## Setting up the Development Environment

The project requires Python 3.14.2 or newer and uses [uv](https://docs.astral.sh/uv/) with the committed `uv.lock`.

1. Install the project and its development dependencies into `.venv`:

   ```bash
   uv sync --group dev
   ```

   You can install a smaller set instead with `--group lint` or `--group pytest`.

2. Install the git hooks:

   ```bash
   uv run prek install
   ```

   This runs the configured checks automatically on each commit.

3. Run the tests and all checks:

   ```bash
   uv run pytest
   uv run prek run --all-files
   ```

CI also runs the tests against the minimum supported Home Assistant release declared in
`hacs.json` (see the matrix in `.github/workflows/pytest_check.yml`). The job resolves the
oldest Home Assistant release at or above that minimum together with a test plugin that
covers it: `pytest-homeassistant` from Home Assistant 2026.11, otherwise its predecessor
`pytest-homeassistant-custom-component`. It installs them with the `pytest-base` group
in a separate environment. Raising the minimum in `hacs.json` is all the job needs.

Import Home Assistant test plugin helpers such as `MockConfigEntry` from `tests.common`
so the tests work with either plugin. To reproduce the job locally, outside the project
`.venv`, run the workflow's minimum steps with `RUNNER_TEMP` set to a scratch directory.
