#!/usr/bin/env bash
# work 트리 상대 경로 — krouterctl 이 주로 사용
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
bash ./router.sh init
exec python3 dhcp_app.py
