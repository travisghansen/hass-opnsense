# Contribution guidelines

Contributing to this project should be as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features

## Github is used for everything

Github is used to host code, to track issues and feature requests, as well as accept pull requests.

Pull requests are the best way to propose changes to the codebase.

1. Fork the repo and create your branch from `main`.
2. If you've changed something, update the documentation.
3. Make sure your code lints (using black or Ruff).
4. Issue that pull request!

## Report bugs using Github's [issues](../../issues)

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

## Use a Consistent Coding Style

Use [ruff](https://docs.astral.sh/ruff/) to make sure the code follows the style.

## Setting up the Development Environment

1. Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

2. Activate the virtual environment:

   ```bash
   source .venv/bin/activate
   ```

3. Install the package in editable mode with development dependencies:

   ```bash
   pip install --group dev -e .
   ```

   This will install the core dependencies plus the development tools including:
   - Linting tools (ruff, mypy, etc.)
   - Testing tools (pytest, etc.)
   - Other development utilities

   Alternatively, you can install specific groups:
   - `pip install --group lint -e .` for linting tools only
   - `pip install --group pytest -e .` for testing tools only

4. Install pre-commit hooks:

   ```bash
   pre-commit install
   ```

   This sets up pre-commit to run automatically on commits.

5. Run tests and linting:

   ```bash
   pytest
   pre-commit run --all
   ```

   The `pre-commit run --all` command will run all configured linting and formatting checks.
