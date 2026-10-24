"""Regex estilo WAF básico, em paralelo ao modelo (RF4). Propositalmente simples: o contraste é o argumento."""
import re

_REGRAS = {
    "sqli": re.compile(r"(\bunion\b\s+(all\s+)?\bselect\b|\bor\b\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s+table|--\s*$)"),
    "xss": re.compile(r"(<\s*script|javascript:|onerror\s*=|onload\s*=)"),
    "traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd)"),
    "cmdi": re.compile(r"(;\s*(cat|ls|id|whoami|rm|wget|curl)\b|\|\s*(cat|ls|id|whoami)\b|`[^`]+`|\$\()"),
}


def checar(valor_normalizado):
    """Devolve a classe da primeira regra que casa, ou None."""
    for classe, rx in _REGRAS.items():
        if rx.search(valor_normalizado):
            return classe
    return None
