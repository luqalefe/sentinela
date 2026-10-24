import json
import threading
import urllib.error
import urllib.request

import numpy as np

import server


class ClfFalso:
    """Ataque = valor contendo 'ATK'; score fixo, para testar só a decisão."""
    classes_ = np.array(["cmdi", "normal", "sqli", "traversal", "xss"])

    def predict_proba(self, X):
        out = []
        for v in X:
            if "atk90" in v.lower():
                out.append([0, .05, .9, .05, 0])
            elif "atk60" in v.lower():
                out.append([0, .4, .6, 0, 0])
            else:
                out.append([0, .99, .01, 0, 0])
        return np.array(out)


class ExplFalso:
    def __init__(self, on_done):
        self.on_done = on_done
        self.vistos = []

    def submit(self, a):
        self.vistos.append(a)
        self.on_done(a["alert_id"], "explicado")


def estado(tmp_path):
    env = {"SENTINELA_API_KEY": "k", "SENTINELA_LOG": str(tmp_path / "a.jsonl")}
    return server.Estado(env, classificador=ClfFalso(), anomalia=None, explainer=ExplFalso)


def req(valor, ip="9.9.9.9"):
    return {"request_id": "r", "ip": ip, "method": "GET", "path": "/b", "params": {"q": valor}}


def test_limiares(tmp_path):
    e = estado(tmp_path)
    assert e.analisar(req("tenis"))["verdict"] == "allow"
    assert e.analisar(req("atk60"))["verdict"] == "flag"
    r = e.analisar(req("atk90"))
    assert r["verdict"] == "block" and r["category"] == "sqli" and r["alert_id"] == "a-000002"
    assert r["mitre"]["id"] == "T1190" and r["param"] == "q"


def test_so_o_modelo_vs_regra(tmp_path):
    e = estado(tmp_path)
    e.analisar(req("atk90"))
    assert e.stats()["only_model"] == 1
    e.analisar(req("atk90 union select x from y"))
    assert e.stats()["only_model"] == 1


def test_combina_payload_e_ip(tmp_path):
    e = estado(tmp_path)
    for _ in range(5):
        e.janela.registrar_feedback("7.7.7.7", "/login", 401, True)
    r = e.analisar(req("tenis", ip="7.7.7.7"))
    assert r["source"] == "ip_behavior" and r["category"] == "brute_force" and r["verdict"] == "block"


def test_tres_bloqueios_viram_ip_blocked_e_reset(tmp_path):
    e = estado(tmp_path)
    for _ in range(3):
        e.analisar(req("atk90"))
    r = e.analisar(req("tenis"))
    assert r["ip_blocked"] and r["verdict"] == "block"
    e.zerar()
    assert not e.analisar(req("tenis"))["ip_blocked"]
    assert e.stats()["alerts"] == 0


def test_explicacao_atualiza_alerta_e_nao_leva_ip(tmp_path):
    e = estado(tmp_path)
    e.analisar(req("atk90"))
    assert e.alertas[-1]["explanation"] == "explicado"
    assert "ip" not in e.explainer.vistos[0]


def test_http_auth_e_analyze(tmp_path):
    e = estado(tmp_path)
    srv = server.servir(e, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"

    def post(path, obj, chave="k"):
        rq = urllib.request.Request(url + path, json.dumps(obj).encode(), {"X-Sentinela-Key": chave})
        return urllib.request.urlopen(rq)

    try:
        post("/analyze", req("x"), chave="errada")
        assert False
    except urllib.error.HTTPError as err:
        assert err.code == 401
    assert json.load(post("/analyze", req("atk90")))["verdict"] == "block"
    assert post("/api/feedback", {"ip": "1", "path": "/", "status": 404}).status == 204
    assert json.load(urllib.request.urlopen(url + "/health"))["status"] == "ok"
    srv.shutdown()


def test_ip_bloqueado_com_payload_limpo_gera_alerta(tmp_path):
    e = estado(tmp_path)
    for _ in range(3):
        e.analisar(req("atk90"))
    r = e.analisar(req("tenis"))
    assert r["ip_blocked"] and r["alert_id"] and r["category"] == "sqli" and r["source"] == "ip_behavior"


def test_explicacao_regravada_em_updates(tmp_path):
    e = estado(tmp_path)
    e.analisar(req("atk90"))
    linha = json.loads((tmp_path / "a_updates.jsonl").read_text().splitlines()[-1])
    assert linha == {"alert_id": "a-000001", "explanation": "explicado"}


# --- /api/provider (troca de provedor do explicador pela tela) ---
class ExplProvedor(ExplFalso):
    def __init__(self, on_done):
        super().__init__(on_done)
        self.cfg = {"preset": "deepseek", "api_key": "sk-segredo-1234567890abcd"}

    def provider_publico(self):
        return {"preset": self.cfg["preset"], "configurada": True, "ultimos4": self.cfg["api_key"][-4:]}

    def set_provider(self, d):
        if not str(d.get("base_url", "")).startswith("http"):
            raise ValueError("base_url inválida")
        self.cfg["preset"] = d["preset"]
        return self.provider_publico()

    def testar(self):
        return True, "ok"


def _api_provider(tmp_path, metodo, caminho, corpo=None, chave="k"):
    env = {"SENTINELA_API_KEY": "k", "SENTINELA_LOG": str(tmp_path / "a.jsonl")}
    est = server.Estado(env, classificador=ClfFalso(), anomalia=None, explainer=ExplProvedor)
    srv = server.servir(est, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = urllib.request.Request("http://127.0.0.1:%d%s" % (srv.server_address[1], caminho), method=metodo,
                                   data=json.dumps(corpo).encode() if corpo is not None else None,
                                   headers={"X-Sentinela-Key": chave, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()
    finally:
        srv.shutdown()


def test_get_provider_sem_vazar_chave(tmp_path):
    codigo, corpo = _api_provider(tmp_path, "GET", "/api/provider")
    assert codigo == 200 and "sk-segredo" not in corpo and '"ultimos4": "abcd"' in corpo


def test_provider_exige_chave(tmp_path):
    assert _api_provider(tmp_path, "GET", "/api/provider", chave="errada")[0] == 401
    assert _api_provider(tmp_path, "POST", "/api/provider", {}, chave="errada")[0] == 401


def test_post_provider_troca_em_memoria(tmp_path):
    codigo, corpo = _api_provider(tmp_path, "POST", "/api/provider", {"preset": "ollama", "base_url": "http://127.0.0.1:11434/v1", "model": "m"})
    assert codigo == 200 and '"preset": "ollama"' in corpo and "sk-segredo" not in corpo
    assert _api_provider(tmp_path, "POST", "/api/provider", {"preset": "x", "base_url": "ftp://a"})[0] == 400
    assert json.loads(_api_provider(tmp_path, "POST", "/api/provider/test", {})[1])["ok"] is True


# --- /api/chat ---
def _chat(tmp_path, pergunta, explainer=ExplFalso):
    env = {"SENTINELA_API_KEY": "k", "SENTINELA_LOG": str(tmp_path / "a.jsonl")}
    est = server.Estado(env, classificador=ClfFalso(), anomalia=None, explainer=explainer)
    est.analisar(req("atk90", ip="203.0.113.7"))
    srv = server.servir(est, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = urllib.request.Request("http://127.0.0.1:%d/api/chat" % srv.server_address[1], method="POST",
                                   data=json.dumps({"pergunta": pergunta}).encode(),
                                   headers={"X-Sentinela-Key": "k", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())
    finally:
        srv.shutdown()


def test_chat_local_sem_provedor(tmp_path):
    codigo, j = _chat(tmp_path, "qual IP mais atacou?")
    assert codigo == 200 and j["provider"] == "local" and "203.0.113.7" in j["resposta"] and "sqli" in j["resposta"]


def test_chat_sem_chave_no_corpo(tmp_path):
    class ExplSemChave(ExplProvedor):
        def perguntar(self, msgs):
            raise RuntimeError("sem chave")
    codigo, j = _chat(tmp_path, "resumo", ExplSemChave)
    assert j["provider"] == "local" and j["resposta"] and "sk-segredo" not in json.dumps(j)


def test_chat_com_provedor_mascara_ip_e_traduz_de_volta(tmp_path):
    vistos = {}

    class ExplLLM(ExplFalso):
        def perguntar(self, msgs):
            vistos["prompt"] = json.dumps(msgs)
            return "O IP-1 atacou mais.", "Ollama local · m"
    codigo, j = _chat(tmp_path, "quem atacou?", ExplLLM)
    assert "203.0.113.7" not in vistos["prompt"] and "IP-1" in vistos["prompt"]
    assert j["resposta"] == "O 203.0.113.7 atacou mais." and j["provider"] == "Ollama local · m"


def test_chat_pergunta_vazia(tmp_path):
    assert _chat(tmp_path, "  ")[0] == 400


def test_oom_payload_gigante_bloqueia(tmp_path):
    e = estado(tmp_path)
    e.oom_bytes = 1_000_000  # garante o limiar no teste
    r = e.analisar(req("A" * 1_200_000))
    assert r["verdict"] == "block"
    assert r["category"] == "oom"
    assert r["mitre"]["id"] == "T1499"
    assert r["rule_hit"] is False


def test_oom_payload_pequeno_nao_dispara(tmp_path):
    e = estado(tmp_path)
    e.oom_bytes = 1_000_000
    assert e.analisar(req("tenis azul"))["category"] != "oom"
