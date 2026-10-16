#!/usr/bin/env bash
# NoireBox — venv + deps + tests + API sur 127.0.0.1:8768
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "[*] Création du venv…"
  python3 -m venv .venv
  .venv/bin/pip install -q --upgrade pip
  .venv/bin/pip install -q -r requirements.txt
fi

echo "[*] Tests :"
.venv/bin/pytest -q

echo ""
echo "[✓] API prête : http://127.0.0.1:8768/docs"
exec .venv/bin/uvicorn noirebox.main:app --host 127.0.0.1 --port 8768
