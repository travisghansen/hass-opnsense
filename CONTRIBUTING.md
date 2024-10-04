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

Use [black](https://github.com/psf/black) or [Ruff](https://docs.astral.sh/ruff/) to make sure the code follows the style.
