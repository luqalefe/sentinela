import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))
from mask import mask


def test_email():
    assert mask("fale com ana.silva+x@exemplo.com.br ok") == "fale com [email] ok"


def test_cpf_formatado_e_cru():
    assert mask("cpf 123.456.789-09") == "cpf [cpf]"
    assert mask("cpf 12345678909") == "cpf [cpf]"


def test_telefone():
    assert mask("(68) 99258-2319") == "[telefone]"
    assert mask("+55 68 99258-2319") == "[telefone]"


def test_cartao():
    assert mask("4111 1111 1111 1111") == "[cartao]"
    assert mask("4111-1111-1111-1111") == "[cartao]"


def test_texto_normal_intacto():
    assert mask("tenis azul 42") == "tenis azul 42"
    assert mask("") == ""
    assert mask(None) == ""


def test_payload_de_ataque_preservado():
    assert mask("' OR 1=1 --") == "' OR 1=1 --"
