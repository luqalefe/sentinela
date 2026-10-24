#!/usr/bin/env bash
# Dispara uma cena da demo contra o Sentinela (8765). Uso: ./demo/cena.sh <reset|payload|scan|brute|flood|tudo>
set -euo pipefail
cd "$(dirname "$0")/.."
export SENTINELA_API_KEY="$(cat .sentinela_key)"
PY=.venv/bin/python

case "${1:-tudo}" in
  reset)   $PY demo/traffic.py --reset --only payload >/dev/null; echo "demo zerada" ;;
  payload) echo ">> Payloads de ataque (SQLi, XSS, traversal, cmdi) + normais"; $PY demo/traffic.py --only payload ;;
  scan)    echo ">> Varredura de rotas (scan)";        $PY demo/traffic.py --only scan ;;
  brute)   echo ">> Força bruta de login (brute_force)"; $PY demo/traffic.py --only brute ;;
  flood)   echo ">> Rajada de requisições (flood)";     $PY demo/traffic.py --only flood ;;
  tudo)    echo ">> Demo completa";                     $PY demo/traffic.py --reset ;;
  *) echo "uso: $0 <reset|payload|scan|brute|flood|tudo>"; exit 1 ;;
esac
