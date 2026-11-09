#!/usr/bin/env bash
# Local checkout entrypoint. No downloads, packages, service or firewall changes.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd -- "$ROOT"
export PYTHONUTF8=1
exec python3 -m ftm install "$@"
