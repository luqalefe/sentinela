"""Normalização do valor antes de classificar: o atacante codifica, o modelo não deve se enganar."""
from urllib.parse import unquote_plus


def normalize(valor, niveis=2):
    if not valor:
        return ""
    s = str(valor)
    # Dois níveis pegam %2527 → %27 → ', o truque clássico de dupla codificação.
    for _ in range(niveis):
        novo = unquote_plus(s)
        if novo == s:
            break
        s = novo
    return s.lower().strip()
