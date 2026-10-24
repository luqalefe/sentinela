"""Regex estilo WAF básico, em paralelo ao modelo (RF4). Propositalmente simples: o contraste é o argumento."""
import re

_REGRAS = {
    "sqli": re.compile(r"(\bunion\b\s+(all\s+)?\bselect\b|\bor\b\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s+table|--\s*$)"),
    "xss": re.compile(r"(<\s*script|javascript:|onerror\s*=|onload\s*=)"),
    # traversal clássico + wrappers/filter chains de PHP (LFI→RCE, em alta em 2024-25).
    "traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|php://filter|convert\.base64|php://input|data://|expect://)"),
    # cmdi clássico + argument injection moderno de PHP:
    #  - CVE-2024-4577 (PHP-CGI): soft-hyphen \xad ou "-d" injetando diretivas
    #  - allow_url_include / auto_prepend_file → RCE
    #  - CVE-2024-52301 (Laravel): troca de ambiente via ?--env=
    "cmdi": re.compile(
        r"(;\s*(cat|ls|id|whoami|rm|wget|curl)\b|\|\s*(cat|ls|id|whoami)\b|`[^`]+`|\$\("
        r"|allow_url_include|auto_prepend_file|\xad|(^|[\s/])-d\s|--env\s*=)"
    ),
}


def checar(valor_normalizado):
    """Devolve a classe da primeira regra que casa, ou None."""
    for classe, rx in _REGRAS.items():
        if rx.search(valor_normalizado):
            return classe
    return None
