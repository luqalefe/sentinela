"""Mascara dados pessoais antes de qualquer texto sair do detector (DeepSeek, logs)."""
import re

# Ordem importa: e-mail primeiro (contém dígitos), cartão antes de CPF/telefone
# porque 16 dígitos seriam engolidos parcialmente pelo padrão de telefone.
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_CARTAO = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_CPF = re.compile(r"(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)")
_TELEFONE = re.compile(r"(?<!\d)(?:\+?55[ -]?)?(?:\(?\d{2}\)?[ -]?)?9?\d{4}[ -]?\d{4}(?!\d)")


def _so_digitos(s):
    return re.sub(r"\D", "", s)


def _cartao(m):
    # 14+ dígitos: telefone com +55 tem 13 e precisa cair no padrão de telefone.
    return "[cartao]" if 14 <= len(_so_digitos(m.group())) <= 19 else m.group()


def mask(texto):
    if not texto:
        return texto or ""
    texto = _EMAIL.sub("[email]", texto)
    texto = _CARTAO.sub(_cartao, texto)
    texto = _CPF.sub("[cpf]", texto)
    texto = _TELEFONE.sub("[telefone]", texto)
    return texto
