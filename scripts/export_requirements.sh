#!/usr/bin/env bash
set -euo pipefail

uv export --format requirements-txt > requirements.txt
