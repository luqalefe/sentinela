import json
import os, sys, threading
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))
import pytest
import explainer
from explainer import Explainer, texto_padrao


@pytest.fixture
def ambiente(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_ENABLED", "true")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "chave-de-teste")


def _rodar(alertas, chamar):
    feitos, evento = [], threading.Event()

    def on_done(alert_id, texto, rotulo=None):
        feitos.append((alert_id, texto))
        if len(feitos) == len(alertas):
            evento.set()

    ex = Explainer(on_done)
    ex._chamar = chamar
    for a in alertas:
        ex.submit(a)
    assert evento.wait(3)
    return feitos


def alerta(i, valor="' or 1=1 --", cat="sqli"):
    return {"alert_id": "a-%06d" % i, "category": cat, "risk": 0.9, "path": "/busca",
            "param": "q", "value_preview": valor}


def test_cache_por_hash_do_payload_normalizado(ambiente):
    chamadas = []
    feitos = _rodar([alerta(1, "%27%20OR%201=1%20--"), alerta(2, "' or 1=1 --")],
                    lambda a, cfg=None: chamadas.append(1) or "explicação")
    assert len(chamadas) == 1
    assert [t for _, t in feitos] == ["explicação", "explicação"]


def test_fallback_em_falha(ambiente):
    def quebra(a, cfg=None):
        raise TimeoutError()
    feitos = _rodar([alerta(1)], quebra)
    assert feitos[0] == ("a-000001", texto_padrao("sqli"))


def test_sem_chave_usa_padrao(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    feitos = _rodar([alerta(1, cat="xss")], lambda a, cfg=None: pytest.fail("não deveria chamar"))
    assert feitos[0][1] == texto_padrao("xss")


def test_desligado_usa_padrao(ambiente, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_ENABLED", "false")
    feitos = _rodar([alerta(1, cat="cmdi")], lambda a, cfg=None: pytest.fail("não deveria chamar"))
    assert feitos[0][1] == texto_padrao("cmdi")


def test_falha_nao_entra_no_cache(ambiente):
    estados = iter([TimeoutError(), "ok"])

    def chamar(a, cfg=None):
        e = next(estados)
        if isinstance(e, Exception):
            raise e
        return e
    feitos = _rodar([alerta(1), alerta(2)], chamar)
    assert feitos[1][1] == "ok"


def test_payload_enviado_mascarado_e_sem_ip(ambiente, monkeypatch):
    enviado = {}

    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self, *a): return b'{"choices":[{"message":{"content":"ok"}}]}'

    def falso(req, timeout):
        enviado["corpo"] = req.data.decode()
        enviado["timeout"] = timeout
        return Resp()
    monkeypatch.setattr(explainer.urllib.request, "urlopen", falso)
    a = alerta(1, "x@y.com 123.456.789-09")
    a["ip"] = "203.0.113.10"
    feitos = []
    ev = threading.Event()
    ex = Explainer(lambda i, t, r=None: (feitos.append(t), ev.set()))
    ex.submit(a)
    assert ev.wait(3)
    assert feitos == ["ok"]
    assert "[email]" in enviado["corpo"] and "[cpf]" in enviado["corpo"]
    assert "x@y.com" not in enviado["corpo"] and "203.0.113.10" not in enviado["corpo"]
    assert enviado["timeout"] == 15


def test_categoria_desconhecida_tem_texto():
    assert texto_padrao("qualquer")


def _ex():
    return Explainer(lambda *a: None)


def test_get_nunca_vaza_a_chave(ambiente, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-segredo-1234567890abcd")
    pub = _ex().provider_publico()
    assert pub["configurada"] is True and pub["ultimos4"] == "abcd"
    assert "sk-segredo" not in json.dumps(pub)


def test_chave_curta_nao_mostra_nem_ultimos4(ambiente, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "curta123")
    assert _ex().provider_publico()["ultimos4"] is None


def test_troca_em_memoria_limpa_cache_e_zera_chave(ambiente):
    ex = _ex()
    ex._cache["x"] = ("t", "r")
    pub = ex.set_provider({"preset": "ollama", "base_url": "http://127.0.0.1:11434/v1/", "model": "llama3.1"})
    assert pub["preset"] == "ollama" and pub["base_url"] == "http://127.0.0.1:11434/v1"
    assert pub["configurada"] is False and pub["ativo"] is True  # ollama não exige chave
    assert ex._cache == {}


def test_troca_aplica_nova_chave_e_modelo(ambiente):
    ex = _ex()
    pub = ex.set_provider({"preset": "openai", "base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini", "api_key": "sk-nova-000011112222"})
    assert pub["rotulo"].startswith("OpenAI") and pub["ultimos4"] == "2222" and pub["ativo"] is True


def test_base_url_invalida(ambiente):
    with pytest.raises(ValueError):
        _ex().set_provider({"preset": "vllm", "base_url": "file:///etc/passwd", "model": "m"})


def test_explicacao_usa_provedor_ativo_e_rotulo(ambiente, monkeypatch):
    ex = _ex()
    ex.set_provider({"preset": "ollama", "base_url": "http://127.0.0.1:11434/v1", "model": "m1"})
    visto = {}
    monkeypatch.setattr(ex, "_chamar_api", lambda cfg, msgs, n: visto.update(cfg=cfg) or "texto")
    texto, rotulo = ex._explicar(alerta(1))
    assert texto == "texto" and rotulo == "Ollama local · m1" and visto["cfg"]["base_url"].endswith("/v1")


def test_testar_nao_ecoa_a_chave(ambiente, monkeypatch):
    ex = _ex()
    monkeypatch.setattr(ex, "_chamar_api", lambda *a: (_ for _ in ()).throw(RuntimeError("falhou com chave-de-teste")))
    ok, msg = ex.testar()
    assert ok is False and "chave-de-teste" not in msg
