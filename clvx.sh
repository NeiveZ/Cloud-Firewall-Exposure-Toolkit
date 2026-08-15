#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
case "${1:-}" in
  --install) python3 -m pip install --upgrade pip >/dev/null 2>&1 || true; python3 -m pip install -r requirements.txt; echo "[+] CLVX installation complete." ;;
  --check) python3 clvx.py --check ;;
  *) python3 clvx.py "$@" ;;
esac
