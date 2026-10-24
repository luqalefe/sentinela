#!/usr/bin/env python3
"""Gerador de tráfego de DEMO do Sentinela (hackathon).

Dispara requisições de teste contra /analyze (simulando o middleware Laravel) e
usa /api/feedback para alimentar a janela por IP. Alvo: a própria instância local.
Não é ferramenta de ataque: são amostras canônicas para validar o detector e a
demo, contra o seu próprio serviço em homologação.

Uso:
  SENTINELA_API_KEY=<chave> python demo/traffic.py [--url http://127.0.0.1:8765] [--reset] [--only payload|scan|brute|flood]
"""
import argparse
import json
import os
import time
import urllib.request
import uuid

# --- Amostras por classe (casos de teste conhecidos, estilo OWASP/suite de WAF) ---
PAYLOADS = {
    "sqli": [
        "1' OR '1'='1",
        "admin' --",
        "1 UNION SELECT username, password FROM users",
        "'; DROP TABLE pedidos; --",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "javascript:alert(1)",
    ],
    "traversal": [
        "../../../../etc/passwd",
        "..\\..\\windows\\win.ini",
        "/var/www/../../etc/passwd",
    ],
    "cmdi": [
        "; cat /etc/passwd",
        "| whoami",
        "$(id)",
        "`ls -la`",
    ],
    "normal": [
        "tenis azul 42",
        "camiseta algodao M",
        "joao@exemplo.com",
    ],
}

# Ataques recentes de PHP (2024-2025) — o diferencial de "atualidade" do pitch.
# São assinaturas de requisição conhecidas, usadas contra o SEU serviço local
# para validar a detecção; não exploram nada de terceiros.
PHP_MODERNO = [
    # CVE-2024-4577 — argument injection no PHP-CGI (Windows, Best-Fit): soft-hyphen
    # %AD escapa o parser e injeta diretivas -d para habilitar include remoto.
    ("cmdi", "%ad-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"),
    ("cmdi", "-d allow_url_include=1 -d auto_prepend_file=php://input"),
    # CVE-2024-52301 — Laravel: troca o ambiente da aplicação via argv na query.
    ("cmdi", "--env=production"),
    ("cmdi", "?--env=local&debug=true"),
    # PHP filter chain — LFI vira RCE sem arquivo, técnica em alta.
    ("traversal", "php://filter/convert.base64-decode/resource=index.php"),
    ("traversal", "php://filter/convert.iconv.utf-8.utf-16|convert.base64-encode/resource=/etc/passwd"),
    ("traversal", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWzBdKTs/Pg=="),
]


def _req(url, key, path, obj=None):
    data = json.dumps(obj).encode() if obj is not None else None
    r = urllib.request.Request(url + path, data=data, method="POST" if data else "GET")
    r.add_header("X-Sentinela-Key", key)
    r.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(r, timeout=5) as resp:
        body = resp.read().decode()
        return resp.status, (json.loads(body) if body.strip() else {})


def analyze(url, key, ip, path, params, method="GET"):
    obj = {"request_id": str(uuid.uuid4()), "ip": ip, "method": method,
           "path": path, "params": params, "user_agent": "demo-traffic/1.0",
           "app": "demo-homolog", "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    return _req(url, key, "/analyze", obj)


def feedback(url, key, ip, path, status, login_failed=False):
    _req(url, key, "/api/feedback",
         {"request_id": str(uuid.uuid4()), "ip": ip, "path": path,
          "status": status, "login_failed": login_failed})


def run_payloads(url, key):
    print("\n== Payloads por classe ==")
    for classe, valores in PAYLOADS.items():
        # IP limpo para os normais (linha-base verde) e um por classe de ataque,
        # para não cair na lista de bloqueio e mascarar os veredictos.
        ip = "203.0.113.5" if classe == "normal" else f"203.0.113.{10 + hash(classe) % 40}"
        for v in valores:
            _, r = analyze(url, key, ip, "/produtos/busca", {"q": v})
            print(f"[{classe:9}] verdict={r.get('verdict'):5} cat={str(r.get('category')):10} "
                  f"risk={r.get('risk')} rule_hit={r.get('rule_hit')}  <- {v[:40]!r}")


def run_php(url, key):
    print("\n== Ataques recentes de PHP (CVE-2024-4577, CVE-2024-52301, filter chains) ==")
    ip = "203.0.113.77"
    for esperado, v in PHP_MODERNO:
        _, r = analyze(url, key, ip, "/index.php", {"page": v})
        marca = "OK" if r.get("verdict") == "block" else "!! PASSOU"
        print(f"[{esperado:9}] {marca:9} verdict={str(r.get('verdict')):5} cat={str(r.get('category')):10} "
              f"rule_hit={r.get('rule_hit')}  <- {v[:52]!r}")


def run_scan(url, key):
    print("\n== Comportamento: scan (muitos 404 em rotas distintas) ==")
    ip = "198.51.100.7"
    for i in range(14):
        analyze(url, key, ip, f"/admin/painel{i}", {})
        feedback(url, key, ip, f"/admin/painel{i}", 404)
    _, r = analyze(url, key, ip, "/qualquer", {})
    print(f"verdict={r.get('verdict')} cat={r.get('category')} source={r.get('source')} ip_blocked={r.get('ip_blocked')}")


def run_brute(url, key):
    print("\n== Comportamento: brute_force (falhas de login) ==")
    ip = "198.51.100.23"
    for _ in range(6):
        analyze(url, key, ip, "/login", {"email": "a@b.com", "password": "x"}, method="POST")
        feedback(url, key, ip, "/login", 401, login_failed=True)
    _, r = analyze(url, key, ip, "/login", {"email": "a@b.com", "password": "y"}, method="POST")
    print(f"verdict={r.get('verdict')} cat={r.get('category')} source={r.get('source')} ip_blocked={r.get('ip_blocked')}")


def run_flood(url, key):
    print("\n== Comportamento: flood (taxa alta) ==")
    ip = "198.51.100.99"
    last = {}
    for _ in range(130):
        _, last = analyze(url, key, ip, "/", {})
    print(f"verdict={last.get('verdict')} cat={last.get('category')} source={last.get('source')} ip_blocked={last.get('ip_blocked')}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8765")
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--only", choices=["payload", "php", "scan", "brute", "flood"])
    a = ap.parse_args()
    key = os.environ.get("SENTINELA_API_KEY")
    if not key:
        raise SystemExit("Defina SENTINELA_API_KEY")
    if a.reset:
        _req(a.url, key, "/api/reset", {})
        print("demo reiniciada")
    only = a.only
    if only in (None, "payload"):
        run_payloads(a.url, key)
    if only in (None, "php"):
        run_php(a.url, key)
    if only in (None, "scan"):
        run_scan(a.url, key)
    if only in (None, "brute"):
        run_brute(a.url, key)
    if only in (None, "flood"):
        run_flood(a.url, key)


if __name__ == "__main__":
    main()
