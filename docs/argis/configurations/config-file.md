# Config File

Configuration comes from YAML defaults and environment variables.

## Source of Truth

- defaults: `src/phish_email_detection_agent/config/defaults.yaml`
- loader: `src/phish_email_detection_agent/config/settings.py::load_config`
- env example: `.env.example`

## Common Runtime Variables

### Provider and profile

- `MY_AGENT_APP_PROFILE`
- `OPENAI_API_KEY`

### Deep analysis controls

- `MY_AGENT_APP_ENABLE_DEEP_ANALYSIS`
- `MY_AGENT_APP_ENABLE_URL_FETCH`
- `MY_AGENT_APP_ALLOW_PRIVATE_NETWORK`

### URL fetch limits

- `MY_AGENT_APP_FETCH_TIMEOUT_S`
- `MY_AGENT_APP_FETCH_MAX_REDIRECTS`
- `MY_AGENT_APP_FETCH_MAX_BYTES`
- `MY_AGENT_APP_URL_FETCH_BACKEND=internal|firejail|docker`

## Practical Rule

Enable only the capabilities you need and keep side-effectful features bounded by explicit limits.

Related docs:

- [Using Argis](/argis/using-argis/)
- [Security Boundary](/argis/operations/security-boundary)
- [Release Gates](/argis/operations/release-gates)
