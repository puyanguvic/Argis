# Release Gates

Use this checklist before publishing a release.

## Required checks

1. Dependency sync:
   - `uv sync`
2. Static checks:
   - `ruff check src tests docs scripts`
3. Test suite:
   - `pytest -k 'not hf_phishing_email_balanced_sample'`

## Required documentation updates

When behavior or interface changes:

1. Update `README.md`
2. Update `docs/design.md`
3. Update `docs/manual.md`
4. Update `CHANGELOG.md`

## API compatibility gate

For API-affecting changes:

1. verify request schema changes are documented
2. verify error codes are stable and documented
3. verify migration notes are provided

## Security gate

1. confirm no new unbounded side effects were introduced
2. confirm API trust boundary remains strict
3. confirm sensitive evidence exposure is intentional and documented

## Release actions

1. create/update release tag
2. publish release notes
3. verify GitHub Pages docs deployment is successful
