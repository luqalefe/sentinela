from ipwindow import JanelaIP


class Relogio:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_janela_expira_em_60s():
    r = Relogio()
    j = JanelaIP(agora=r)
    for _ in range(5):
        j.registrar_requisicao("1.1.1.1", "/a")
    assert j.features("1.1.1.1")["req_min"] == 5
    r.t += 61
    assert j.features("1.1.1.1")["req_min"] == 0


def test_bloqueio_apos_3_em_5min_e_expira_em_10min():
    r = Relogio()
    j = JanelaIP(agora=r)
    j.registrar_bloqueio("2.2.2.2")
    j.registrar_bloqueio("2.2.2.2")
    assert not j.bloqueado("2.2.2.2")
    j.registrar_bloqueio("2.2.2.2")
    assert j.bloqueado("2.2.2.2")
    r.t += 599
    assert j.bloqueado("2.2.2.2")
    r.t += 2
    assert not j.bloqueado("2.2.2.2")


def test_tres_bloqueios_fora_de_5min_nao_bloqueiam():
    r = Relogio()
    j = JanelaIP(agora=r)
    for _ in range(3):
        j.registrar_bloqueio("3.3.3.3")
        r.t += 200
    assert not j.bloqueado("3.3.3.3")


def test_fallback_brute_force_scan_flood():
    j = JanelaIP(agora=Relogio())
    for _ in range(5):
        j.registrar_feedback("a", "/login", 401, login_falhou=True)
    assert j.risco_limiar("a")[1] == "brute_force"
    for i in range(12):
        j.registrar_requisicao("b", f"/x{i}")
        j.registrar_feedback("b", f"/x{i}", 404)
    assert j.risco_limiar("b")[1] == "scan"
    for _ in range(130):
        j.registrar_requisicao("c", "/")
    assert j.risco_limiar("c")[1] == "flood"
    j.registrar_requisicao("d", "/")
    assert j.risco_limiar("d") == (0.0, None)


def test_desbloquear():
    j = JanelaIP(agora=Relogio())
    for _ in range(3):
        j.registrar_bloqueio("e")
    j.desbloquear("e")
    assert not j.bloqueado("e")
