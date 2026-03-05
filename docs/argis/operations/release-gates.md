# Release Gates

Checklist before publishing a release.

## Required Checks

1. `uv sync`
2. `ruff check src tests docs scripts`
3. `pytest -k 'not hf_phishing_email_balanced_sample'`

## Required Documentation Updates

1. update `README.md`
2. update the canonical pages under `docs/argis/architecture/`
3. update the canonical pages under `docs/argis/operations/` or `docs/argis/using-argis/`
4. update `CHANGELOG.md`

## API Compatibility Gate

1. document request schema changes
2. preserve and document error codes
3. add migration notes for caller impact

## Security Gate

1. no unbounded side effects
2. API trust boundary remains strict
3. evidence exposure changes are explicit and documented
