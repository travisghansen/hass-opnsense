# AGENTS

## Purpose

- Provide clear, repo-specific instructions for autonomous agents working in this repository.

## General Guidelines

- Follow Home Assistant developer docs: https://developers.home-assistant.io/docs/.
- Be concise and explain coding steps briefly when making code changes; include code snippets and tests where relevant.
- For non-trivial edits, provide a short plan. For small, low-risk edits, implement and include a one-line summary.
- Focus on a single conceptual change at a time when public APIs or multiple modules are affected.
- Follow `CODING_STANDARDS.md`. Maintain Python 3.14+ compatibility and target latest Home Assistant core.
- Keep compatibility with the minimum supported OPNsense firmware documented in `custom_components/opnsense/const.py` and `README.md`.
- If deviating from these guidelines, explicitly state which guideline is deviated from and why.

## Agent Permissions and Venv Policy

- Agents may create and use a repository-local venv at `./.venv`. Use `./.venv/bin/python`, `./.venv/bin/pytest`, and `./.venv/bin/prek` for local commands unless using the main checkout venv for a git worktree with no dependency changes.
- The project uses `pyproject.toml` dependency groups (`ha`, `lint`, `pytest`, `dev`). Installing packages from repo manifests into `./.venv` is allowed for running tests or local tooling after approval; avoid unrelated network operations without explicit consent.

## Folder Structure (Repo-Specific)

- `custom_components/opnsense`: integration code.
- `tests`: pytest test suite and fixtures.
- `README.md`: primary documentation.
- `CODING_STANDARDS.md`: architecture, code, error-handling and testing standards. Read it before changing code and follow it.
- `CONTRIBUTING.md`: contributor workflow, development setup and pull request conventions.
- `GLOSSARY.md`: domain vocabulary. Use its terms in new names, docs and user-facing text.
- `docs/`: user guides and agent skill configuration (`docs/agents`).
- `.github/workflows`: GitHub Workflows
- `.github/scripts`: scripts for GitHub Workflows

## Local Tooling Note

- Use the repo's `prek` and `pytest` commands through the venv selected by the agent permissions and venv policy above. Follow existing repository style and run `prek`.
- By default, run the full pytest suite. If running targeted tests, explain why.
- If tests fail due to missing dev dependencies, either install them into `./.venv` (if allowed) or report exact `pip install` commands.
- Avoid recommending `tox`, it is not in use by this repo.

## PR & Branch Behavior

- Create branches or PRs only when explicitly requested. Do not open PRs autonomously.
- Pull request titles follow the convention in `CONTRIBUTING.md`.

## Network / Install Consent

- Package installs from repo manifests for local tooling and tests are allowed after approval. Obtain explicit consent before unrelated network operations.

## CI/CD

- Use GitHub Actions for CI/CD where applicable.

## Conventions for Changes and Documentation

- When editing code, prefer fixing root causes over surface patches.
- Keep changes minimal and consistent with the codebase style.
- Verify changes in proportion to their risk and update documentation if needed. Follow the testing standards in `CODING_STANDARDS.md` when deciding whether to add tests.

## Agent skills

### Issue tracker

Issues and specs are local markdown files under `.scratch/<feature>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`), recorded as a `Status:` line in each issue file. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one root `GLOSSARY.md` plus `docs/adr/`. See `docs/agents/domain.md`.
