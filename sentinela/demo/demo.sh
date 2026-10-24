#!/usr/bin/env bash
# Painel de controle da demo do Sentinela.
# Rode UMA vez:  ./demo/demo.sh
# Escolha a cena pelo número; o menu volta sozinho. 0 ou q para sair.
set -uo pipefail
cd "$(dirname "$0")/.."

URL="${SENTINELA_URL:-http://127.0.0.1:8765}"
PY=.venv/bin/python
[ -x "$PY" ] || PY=python3
export SENTINELA_API_KEY="$(cat .sentinela_key 2>/dev/null || echo "")"

c_tit=$'\e[1;36m'; c_ok=$'\e[1;32m'; c_dim=$'\e[2m'; c_warn=$'\e[1;33m'; c_off=$'\e[0m'

checar_servidor() {
  if curl -s --max-time 2 "$URL/health" >/dev/null 2>&1; then
    echo "${c_ok}● detector no ar${c_off} ${c_dim}($URL)${c_off}"
  else
    echo "${c_warn}● detector FORA do ar${c_off} — suba com ./demo/00-subir.sh"
  fi
}

rodar() { echo; "$PY" demo/traffic.py "$@"; echo; echo "${c_dim}— feito. Enter para voltar ao menu —${c_off}"; read -r _; }

menu() {
  clear
  echo "${c_tit}╔══════════════════════════════════════╗${c_off}"
  echo "${c_tit}║        🛡  SENTINELA — DEMO           ║${c_off}"
  echo "${c_tit}╚══════════════════════════════════════╝${c_off}"
  checar_servidor
  echo
  echo "  ${c_ok}1${c_off})  Resetar demo        ${c_dim}(painel verde, zera tudo)${c_off}"
  echo "  ${c_ok}2${c_off})  Payloads de ataque  ${c_dim}(SQLi, XSS, traversal, cmdi)${c_off}"
  echo "  ${c_ok}8${c_off})  PHP 2024 ${c_warn}★${c_off}         ${c_dim}(CVE-2024-4577, CVE-2024-52301, filter chains)${c_off}"
  echo "  ${c_ok}3${c_off})  Scan                ${c_dim}(varredura de rotas → bloqueio)${c_off}"
  echo "  ${c_ok}4${c_off})  Brute force         ${c_dim}(falhas de login)${c_off}"
  echo "  ${c_ok}5${c_off})  Flood               ${c_dim}(rajada → bloqueio)${c_off}"
  echo "  ${c_ok}6${c_off})  TUDO                ${c_dim}(reset + todas as cenas)${c_off}"
  echo "  ${c_ok}7${c_off})  Comportamento       ${c_dim}(scan + brute + flood)${c_off}"
  echo
  echo "  ${c_dim}0 ou q) sair${c_off}"
  echo
  printf "Escolha: "
}

while true; do
  menu
  read -r op || break
  case "$op" in
    1) echo; "$PY" demo/traffic.py --reset --only payload >/dev/null 2>&1; echo "demo zerada."; echo "${c_dim}— Enter —${c_off}"; read -r _ ;;
    2) rodar --only payload ;;
    8) rodar --only php ;;
    3) rodar --only scan ;;
    4) rodar --only brute ;;
    5) rodar --only flood ;;
    6) rodar --reset ;;
    7) echo; "$PY" demo/traffic.py --only scan; "$PY" demo/traffic.py --only brute; "$PY" demo/traffic.py --only flood; echo; echo "${c_dim}— feito. Enter —${c_off}"; read -r _ ;;
    0|q|Q) clear; echo "até a próxima 👋"; exit 0 ;;
    "") : ;;
    *) echo "opção inválida"; sleep 1 ;;
  esac
done
