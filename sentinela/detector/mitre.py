"""Mapa classe → técnica MITRE ATT&CK (RF8). Ids na ordem em que o dashboard os mostra."""

_T1190 = {"id": "T1190", "name": "Exploit Public-Facing Application"}

MITRE = {
    "sqli": _T1190,
    "xss": _T1190,
    "traversal": _T1190,
    "cmdi": _T1190,
    "brute_force": {"id": "T1110", "name": "Brute Force"},
    "scan": {"id": "T1595", "name": "Active Scanning"},
    "flood": {"id": "T1498", "name": "Network Denial of Service"},
}

# Técnicas secundárias da tabela do RF8 (cmdi também é T1059, traversal também é T1083).
SECUNDARIAS = {
    "cmdi": {"id": "T1059", "name": "Command and Scripting Interpreter"},
    "traversal": {"id": "T1083", "name": "File and Directory Discovery"},
}


def tecnica(categoria):
    return MITRE.get(categoria)
