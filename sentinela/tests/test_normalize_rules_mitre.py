from mitre import tecnica
from normalize import normalize
import rules


def test_decode_dois_niveis_e_minusculas():
    assert normalize("%2527%20OR%201=1") == "' or 1=1"


def test_vazios():
    assert normalize("") == ""
    assert normalize(None) == ""


def test_um_nivel_nao_decodifica_o_terceiro():
    assert normalize("%252527") == "%27"


def test_regras_por_classe():
    assert rules.checar("1 union select a from b") == "sqli"
    assert rules.checar("<script>x</script>") == "xss"
    assert rules.checar("../../etc/passwd") == "traversal"
    assert rules.checar("a; cat /x") == "cmdi"
    assert rules.checar("tenis azul") is None


def test_mitre():
    assert tecnica("sqli")["id"] == "T1190"
    assert tecnica("brute_force")["id"] == "T1110"
    assert tecnica("scan")["id"] == "T1595"
    assert tecnica("flood")["id"] == "T1498"
    assert tecnica("normal") is None
