# Changelog (Web Summary)

Canonical changelog file: [CHANGELOG.md](https://github.com/puyanguvic/Argis/blob/main/CHANGELOG.md)

## 2026-03-05

### Added

- API input hardening for `/analyze` (`#7`).
- API evidence sanitization + `debug_evidence=true` support (`#8`).
- Deterministic fallback expansion with structured `fallback_reason` (`#9`).

### Changed

- Precheck tuning knobs now affect live scoring behavior (`#10`).
- Policy/threshold semantics aligned; runtime capability metadata corrected (`#11`).
- Documentation updated to reflect API boundaries and response behavior (`#12`).

### Validation

- `ruff check src tests docs scripts`
- `pytest -k 'not hf_phishing_email_balanced_sample'`
