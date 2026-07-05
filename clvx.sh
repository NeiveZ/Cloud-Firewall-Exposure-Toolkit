#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

case "${1:-}" in
  --install)
    echo "[*] Installing CLVX optional dependencies..."
    python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
    if [ -f requirements.txt ]; then python3 -m pip install -r requirements.txt; fi
    echo "[+] Installation complete."
    ;;
  --check)
    python3 clvx.py --check
    ;;
  *)
    python3 clvx.py "$@"
    ;;
esac
