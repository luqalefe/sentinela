#!/usr/bin/env bash
# Sobe o detector Sentinela na porta 8765. Rode UMA vez, deixe este terminal aberto.
set -euo pipefail
cd "$(dirname "$0")/.."

# Chave: usa a existente ou gera uma e salva em .sentinela_key
if [ ! -f .sentinela_key ]; then
  openssl rand -hex 12 > .sentinela_key
  echo ".sentinela_key" >> .gitignore 2>/dev/null || true
fi
export SENTINELA_API_KEY="$(cat .sentinela_key)"

echo "=============================================="
echo " Sentinela no ar:  http://127.0.0.1:8765/"
echo " Chave do painel:  $SENTINELA_API_KEY"
echo "=============================================="
echo "(Deixe aberto. Ctrl+C encerra. Treine o modelo antes com 1x: .venv/bin/python detector/train.py)"
echo

exec .venv/bin/python detector/server.py
