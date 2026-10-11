#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
if [[ -x ./venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  source ./venv/bin/activate
elif [[ -x /global/bin/krouter/venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  source /global/bin/krouter/venv/bin/activate
fi
export KROUTER_SAFE_MODE="${KROUTER_SAFE_MODE:-0}"
exec python3 dns_app.py
