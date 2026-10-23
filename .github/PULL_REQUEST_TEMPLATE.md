## What does this change?

<!-- One app or one feature per pull request is easiest to review. -->

## How was it verified?

<!-- For checks: Docker image and version you tested against, or links to the upstream source you relied on. -->

## Checklist

- [ ] Checks are read-only, send no credentials and cannot trigger bans or lockouts (see CONTRIBUTING.md)
- [ ] User-facing strings use `_()` / UI keys and have German translations (`pytest tests/test_i18n.py`)
- [ ] Tests added or updated; `pytest`, `ruff check .` and `ruff format --check .` pass
- [ ] README (supported apps) and CHANGELOG updated if relevant
