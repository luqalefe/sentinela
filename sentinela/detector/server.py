"""API de análise, SSE e dashboard do Sentinela (RF3, RF6). Só stdlib + scikit-learn/joblib."""
import hmac
import json
import os
import queue
import sys
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chatlogs  # noqa: E402
from ipwindow import JanelaIP  # noqa: E402
from mask import mask  # noqa: E402
from mitre import tecnica  # noqa: E402
from normalize import normalize  # noqa: E402
import rules  # noqa: E402

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ESTATICO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "index.html")
CATS_PAYLOAD = ("sqli", "xss", "traversal", "cmdi")
TEXTOS_PADRAO = {
    "sqli": "Tentativa de injeção SQL. Use Eloquent/bindings (nunca concatene entrada na query).",
    "xss": "Tentativa de XSS. Escape a saída no Blade ({{ }}) e valide a entrada.",
    "traversal": "Tentativa de path traversal. Valide o caminho contra uma lista permitida e use basename().",
    "cmdi": "Tentativa de injeção de comandos. Nunca passe entrada ao shell; use APIs nativas e validação.",
    "brute_force": "Muitas falhas de login do mesmo IP. Aplique rate limit e bloqueio temporário.",
    "scan": "Varredura de rotas (muitos 404). Aplique rate limit e monitore o IP.",
    "flood": "Taxa de requisições anormalmente alta. Aplique throttle no Laravel/borda.",
}


def _stub_explainer():
    class Explainer:
        # Estopim ainda não entregou explainer.py: texto padrão por classe, sem rede.
        def __init__(self, on_done):
            self.on_done = on_done

        def submit(self, alerta):
            threading.Thread(target=self.on_done, args=(alerta["alert_id"], TEXTOS_PADRAO.get(alerta["category"], "")), daemon=True).start()
    return Explainer


def _carregar_explainer():
    try:
        from explainer import Explainer
        return Explainer
    except ImportError:
        return _stub_explainer()


def _joblib(nome):
    caminho = os.path.join(RAIZ, "models", nome)
    if not os.path.exists(caminho):
        return None
    import joblib
    return joblib.load(caminho)


class Estado:
    def __init__(self, env=os.environ, classificador="auto", anomalia="auto", explainer=None):
        self.chave = env.get("SENTINELA_API_KEY", "")
        self.flag = float(env.get("SENTINELA_FLAG", 0.5))
        self.block = float(env.get("SENTINELA_BLOCK", 0.85))
        # Tamanho de payload HTTP a partir do qual a requisição é tratada como
        # tentativa de exaustão de memória (OOM-DoS). Defesa na borda contra o
        # php2shell / bailout de OOM do FPM (CVE-2026-109618/109619).
        self.oom_bytes = int(env.get("SENTINELA_OOM_BYTES", 1048576))  # 1 MB
        self.log_path = env.get("SENTINELA_LOG", os.path.join(RAIZ, "logs", "alerts.jsonl"))
        self.updates_path = os.path.splitext(self.log_path)[0] + "_updates.jsonl"
        self.clf = _joblib("classifier.joblib") if classificador == "auto" else classificador
        self.anom = _joblib("anomaly.joblib") if anomalia == "auto" else anomalia
        self.janela = JanelaIP(env.get("SENTINELA_LOGIN_PATH", "/login"))
        self.lock = threading.RLock()
        self.assinantes = []
        self.explainer = (explainer or _carregar_explainer())(self._explicacao_pronta)
        try:
            from wa_notify import WhatsAppNotifier
            self.wa = WhatsAppNotifier(env)
        except Exception:
            self.wa = None
        try:
            from advisor import Advisor
            self.advisor = Advisor(env, on_new=self._cve_nova)
        except Exception:
            self.advisor = None
        self.zerar()

    def _cve_nova(self, advisories):
        """Callback do advisor: avisa no WhatsApp sobre vulnerabilidades novas da stack."""
        if not (self.wa and advisories):
            return
        top = advisories[:5]
        linhas = ["🛡️ *Sentinela* — vulnerabilidades na sua stack",
                  f"{len(advisories)} achado(s) do OSV.dev", ""]
        for a in top:
            fix = f" → corrigir em {a['correcao']}" if a.get("correcao") else ""
            linhas.append(f"• {a['pacote']} {a['versao']}: {a['id']} ({a['severidade']}){fix}")
        self.wa.enviar_texto("\n".join(linhas))
        self._carregar_historico()

    def _carregar_historico(self):
        """Repovoa o feed e os contadores com a cauda do alerts.jsonl ao subir,
        para o histórico sobreviver a um reinício. Não é chamado no reset."""
        if not os.path.exists(self.log_path):
            return
        try:
            with open(self.log_path, encoding="utf-8") as f:
                linhas = f.readlines()[-1000:]
        except OSError:
            return
        payload = {"sqli", "xss", "traversal", "cmdi"}
        with self.lock:
            for ln in linhas:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    a = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                self.alertas.append(a)
                cat = a.get("category")
                self.cont["alerts"] += 1
                if cat:
                    self.por_tipo[cat] += 1
                if a.get("verdict") == "block":
                    self.cont["blocks"] += 1
                if cat in payload and not a.get("rule_hit"):
                    self.cont["only_model"] += 1
                try:
                    n = int(str(a.get("alert_id", "a-0")).split("-")[-1])
                    self.seq = max(self.seq, n)
                except (ValueError, IndexError):
                    pass

    def zerar(self):
        with self.lock:
            self.alertas = deque(maxlen=1000)
            self.cont = Counter()
            self.por_tipo = Counter()
            self.janela.reset()
            self.seq = 0
            self.cat_bloqueio = {}

    # --- SSE ---
    def assinar(self):
        q = queue.Queue(maxsize=500)
        with self.lock:
            self.assinantes.append(q)
        return q

    def desassinar(self, q):
        with self.lock:
            if q in self.assinantes:
                self.assinantes.remove(q)

    def emitir(self, evento, dado):
        msg = f"event: {evento}\ndata: {json.dumps(dado, ensure_ascii=False)}\n\n"
        with self.lock:
            for q in self.assinantes:
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    pass  # cliente lento perde evento; nunca trava a análise

    def stats(self):
        with self.lock:
            return {
                "requests": self.cont["requests"], "alerts": self.cont["alerts"],
                "blocks": self.cont["blocks"], "only_model": self.cont["only_model"],
                "false_positives": self.cont["falsos_positivos"],
                "by_type": dict(self.por_tipo), "top_ips": self.janela.top_ips(),
                "blocked_ips": self.janela.lista_bloqueados(),
                "classifier": self.clf is not None,
                "ip_mode": "isolation_forest" if self.anom is not None else "limiares (fallback)",
            }

    # --- análise ---
    def risco_payload(self, params):
        """(risco, categoria, param, valor, rule_hit) do valor mais arriscado."""
        melhor = (0.0, None, None, "", False)
        itens = [(k, str(v)) for k, v in (params or {}).items()]
        normas = [normalize(v) for _, v in itens]
        probas = None
        if self.clf is not None and itens:
            probas = self.clf.predict_proba([v for _, v in itens])
            classes = list(self.clf.classes_)
        for i, (k, v) in enumerate(itens):
            regra = rules.checar(normas[i]) if normas[i] else None
            risco, cat = 0.0, None
            if probas is not None:
                p = dict(zip(classes, probas[i]))
                risco = 1.0 - p.get("normal", 0.0)
                ataques = {c: s for c, s in p.items() if c != "normal"}
                cat = max(ataques, key=ataques.get) if ataques else None
            elif regra:
                risco, cat = 0.9, regra  # sem modelo, a regra é tudo que existe
            if risco > melhor[0] or melhor[1] is None and regra:
                melhor = (risco, cat or regra, k, v, regra is not None)
        return melhor

    def risco_ip(self, ip):
        if self.anom is not None:
            f = self.janela.features(ip)
            if f["req_min"] + f["_n_fb"] == 0:
                return 0.0, None
            x = [[f["req_min"], f["prop_4xx"], f["prop_404"], f["falhas_login"], f["rotas_distintas"], f["payload_medio"]]]
            if self.anom.predict(x)[0] == -1:
                cat = "brute_force" if f["falhas_login"] >= 3 else "scan" if f["prop_404"] >= 0.3 else "flood"
                return 0.9, cat
            return 0.0, None
        return self.janela.risco_limiar(ip)

    def analisar(self, req):
        t0 = time.perf_counter()
        ip = req.get("ip", "")
        params = req.get("params") or {}
        # Tamanho do corpo: o middleware reporta body_bytes (Content-Length real) sem
        # precisar enviar o payload inteiro ao detector — é assim que o OOM é visto na borda.
        tam = max(sum(len(str(v)) for v in params.values()), int(req.get("body_bytes") or 0))
        self.janela.registrar_requisicao(ip, req.get("path", ""), tam)
        r_pay, cat_pay, param, valor, regra = self.risco_payload(params)
        # Payload gigante = provável tentativa de OOM-DoS (memory bomb) pela borda HTTP.
        # Uma regra WAF de assinatura não pega (rule_hit=False); é detecção por tamanho.
        if tam >= self.oom_bytes and self.block > r_pay:
            maior = max(params, key=lambda k: len(str(params[k]))) if params else None
            r_pay, cat_pay, param, valor, regra = self.block, "oom", maior, f"<payload {tam} bytes>", False
        r_ip, cat_ip = self.risco_ip(ip)
        risco = max(r_pay, r_ip)
        origem, cat = ("payload", cat_pay) if r_pay >= r_ip else ("ip_behavior", cat_ip)
        ja_bloqueado = self.janela.bloqueado(ip)
        veredito = "block" if risco >= self.block else "flag" if risco >= self.flag else "allow"
        if ja_bloqueado:
            veredito = "block"
            # Payload limpo de IP já bloqueado ainda precisa de alert_id para o 403 do Laravel:
            # herda a categoria que levou ao bloqueio.
            if cat is None or risco < self.flag:
                cat, origem = self.cat_bloqueio.get(ip, "flood"), "ip_behavior"
            risco = max(risco, self.block)
        if veredito == "block" and not ja_bloqueado:
            if cat:
                self.cat_bloqueio[ip] = cat
            self.janela.registrar_bloqueio(ip)
        alert_id = None
        m = tecnica(cat) if veredito != "allow" else None
        with self.lock:
            self.cont["requests"] += 1
            if veredito != "allow" and cat:
                self.seq += 1
                alert_id = f"a-{self.seq:06d}"
                self.cont["alerts"] += 1
                self.por_tipo[cat] += 1
                if veredito == "block":
                    self.cont["blocks"] += 1
                solo = origem == "payload" and not regra
                if solo:
                    self.cont["only_model"] += 1
        resp = {
            "request_id": req.get("request_id"), "verdict": veredito, "risk": round(risco, 4),
            "category": cat if veredito != "allow" else None, "param": param if origem == "payload" else None,
            "source": origem, "mitre": m, "rule_hit": bool(regra), "ip_blocked": ja_bloqueado or self.janela.bloqueado(ip),
            "alert_id": alert_id, "latency_ms": 0,
        }
        if alert_id:
            alerta = {
                "alert_id": alert_id, "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ip": ip, "method": req.get("method"), "path": req.get("path"), "app": req.get("app"),
                "param": resp["param"], "value_preview": mask(valor)[:80] if origem == "payload" else "",
                "category": cat, "risk": round(risco, 4), "verdict": veredito, "rule_hit": bool(regra),
                "mitre_id": m["id"] if m else None, "explanation": None,
            }
            with self.lock:
                self.alertas.append(alerta)
            self._gravar(alerta)
            self.emitir("alert", alerta)
            if self.wa:
                self.wa.submit(alerta)
            # O explicador roda em thread própria e nunca vê o IP (privacidade, RF5).
            pedido = {k: v for k, v in alerta.items() if k not in ("ip", "explanation")}
            pedido["value"] = mask(valor)[:300] if origem == "payload" else ""
            try:
                self.explainer.submit(pedido)
            except Exception as e:  # noqa: BLE001 - explicação nunca derruba a análise
                print("explainer:", e, file=sys.stderr)
            # LLM-as-detector: segunda opinião assíncrona (ataque x falso positivo).
            # Só para alertas de payload, onde falso positivo faz sentido.
            if origem == "payload":
                threading.Thread(target=self._revisar, args=(pedido,), daemon=True).start()
        self.emitir("request", {"ts": time.time(), "verdict": veredito})
        resp["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        return resp

    def _gravar(self, alerta, caminho=None):
        caminho = caminho or self.log_path
        try:
            os.makedirs(os.path.dirname(caminho), exist_ok=True)
            with open(caminho, "a", encoding="utf-8") as f:
                f.write(json.dumps(alerta, ensure_ascii=False) + "\n")
        except OSError as e:
            print("log:", e, file=sys.stderr)

    def _explicacao_pronta(self, alert_id, texto, provedor=None):
        with self.lock:
            for a in self.alertas:
                if a["alert_id"] == alert_id:
                    a["explanation"] = texto
                    a["explanation_provider"] = provedor
                    break
        self.emitir("alert_update", {"alert_id": alert_id, "explanation": texto, "provider": provedor})
        # alerts.jsonl é append-only; a explicação chega depois e vai para um arquivo de updates.
        linha = {"alert_id": alert_id, "explanation": texto}
        if provedor:
            linha["provider"] = provedor
        self._gravar(linha, self.updates_path)

    def _revisar(self, pedido):
        """Thread: pede a segunda opinião da LLM e anota no alerta (nunca muda o veredito)."""
        try:
            import reviewer
            r = reviewer.revisar(self.explainer, pedido)
        except Exception:  # noqa: BLE001 - sem provedor/erro: alerta fica sem revisão
            return
        alert_id = pedido["alert_id"]
        with self.lock:
            for a in self.alertas:
                if a["alert_id"] == alert_id:
                    a["review"] = r
                    break
            if r["veredito"] == "falso_positivo":
                self.cont["falsos_positivos"] += 1
        self.emitir("alert_review", {"alert_id": alert_id, **r})


def criar_handler(estado):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _json(self, codigo, obj):
            corpo = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(codigo)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(corpo)))
            self.end_headers()
            self.wfile.write(corpo)

        def _autorizado(self, query=None):
            dado = self.headers.get("X-Sentinela-Key") or (query or {}).get("key", [""])[0]
            return bool(estado.chave) and hmac.compare_digest(dado.encode(), estado.chave.encode())

        def _corpo(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > 1_000_000:
                raise ValueError("corpo grande demais")
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path == "/health":
                return self._json(200, {"status": "ok", "classifier": estado.clf is not None})
            if u.path == "/":
                try:
                    with open(ESTATICO, "rb") as f:
                        corpo = f.read()
                except OSError:
                    return self._json(404, {"error": "dashboard ausente"})
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(corpo)))
                self.end_headers()
                return self.wfile.write(corpo)
            if not self._autorizado(q):
                return self._json(401, {"error": "chave inválida"})
            if u.path == "/events":
                return self._sse()
            if u.path == "/api/stats":
                return self._json(200, estado.stats())
            if u.path == "/api/provider":
                if not hasattr(estado.explainer, "provider_publico"):
                    return self._json(501, {"error": "explicador sem suporte a troca de provedor"})
                return self._json(200, estado.explainer.provider_publico())
            if u.path == "/api/alerts":
                lim = int(q.get("limit", ["50"])[0])
                with estado.lock:
                    return self._json(200, list(estado.alertas)[-lim:][::-1])
            if u.path == "/api/advisories":
                if not estado.advisor:
                    return self._json(200, {"habilitado": False, "itens": [], "atualizado_em": None})
                return self._json(200, {"habilitado": estado.advisor.enabled, **estado.advisor.atual()})
            self._json(404, {"error": "não encontrado"})

        def do_POST(self):
            u = urlparse(self.path)
            if not self._autorizado():
                return self._json(401, {"error": "chave inválida"})
            try:
                corpo = self._corpo()
            except (ValueError, json.JSONDecodeError):
                return self._json(400, {"error": "JSON inválido"})
            if u.path == "/analyze":
                return self._json(200, estado.analisar(corpo))
            if u.path == "/api/feedback":
                estado.janela.registrar_feedback(corpo.get("ip", ""), corpo.get("path", ""), int(corpo.get("status") or 0), corpo.get("login_failed", False))
                self.send_response(204)
                self.send_header("Content-Length", "0")
                return self.end_headers()
            if u.path == "/api/unblock":
                estado.janela.desbloquear(corpo.get("ip", ""))
                return self._json(200, {"ok": True})
            if u.path in ("/api/provider", "/api/provider/test"):
                if not hasattr(estado.explainer, "set_provider"):
                    return self._json(501, {"error": "explicador sem suporte a troca de provedor"})
                if u.path.endswith("/test"):
                    ok, msg = estado.explainer.testar()
                    return self._json(200, {"ok": ok, "mensagem": msg})
                try:
                    return self._json(200, estado.explainer.set_provider(corpo))
                except ValueError as e:
                    return self._json(400, {"error": str(e)})
            if u.path == "/api/chat":
                pergunta = str(corpo.get("pergunta") or "").strip()
                if not pergunta:
                    return self._json(400, {"error": "pergunta vazia"})
                with estado.lock:
                    mem = list(estado.alertas)
                alertas = chatlogs.coletar(mem, estado.log_path)
                resposta, provedor = chatlogs.responder(estado.explainer, alertas, pergunta)
                return self._json(200, {"resposta": resposta, "provider": provedor})
            if u.path == "/api/reset":
                estado.zerar()
                estado.emitir("reset", {})
                return self._json(200, {"ok": True})
            if u.path == "/api/advisories/refresh":
                if not estado.advisor:
                    return self._json(200, {"itens": []})
                itens = estado.advisor.atualizar()
                return self._json(200, {"itens": itens, "atualizado_em": estado.advisor.atualizado_em})
            self._json(404, {"error": "não encontrado"})

        def _sse(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            q = estado.assinar()
            try:
                self.wfile.write(b": ok\n\n")
                self.wfile.flush()
                while True:
                    try:
                        msg = q.get(timeout=15)
                    except queue.Empty:
                        msg = ": ping\n\n"
                    self.wfile.write(msg.encode())
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                estado.desassinar(q)
    return H


def servir(estado, host, porta):
    srv = ThreadingHTTPServer((host, porta), criar_handler(estado))
    srv.daemon_threads = True

    def ticker():
        while True:
            time.sleep(1)
            estado.emitir("stats", estado.stats())
    threading.Thread(target=ticker, daemon=True).start()
    return srv


if __name__ == "__main__":
    if not os.environ.get("SENTINELA_API_KEY"):
        sys.exit("Defina SENTINELA_API_KEY (veja .env.example).")
    est = Estado()
    host, porta = os.environ.get("SENTINELA_HOST", "127.0.0.1"), int(os.environ.get("SENTINELA_PORT", 8765))
    print(f"Sentinela em http://{host}:{porta}/  classificador={'sim' if est.clf else 'NÃO (só regras)'}")
    servir(est, host, porta).serve_forever()
