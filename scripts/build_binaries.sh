#!/usr/bin/env bash
# Local helper: build sc5 + squidc5 standalone binaries (requires venv + pyinstaller once).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python -m pip install -q -e . "pyinstaller>=6.0"
python packaging/build_binaries.py "$@"
echo "Binaries in: $ROOT/dist/binaries"
