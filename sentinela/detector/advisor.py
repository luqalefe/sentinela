"""Advisor de vulnerabilidades: cruza as stacks das aplicações com CVEs do OSV.dev.

Autônomo e assíncrono — NUNCA no caminho da requisição. Lê os componentes de
(a) lock files dos apps (composer.lock, package-lock.json) e (b) um stacks.json
manual, consulta a API pública do OSV (https://osv.dev) e devolve as
vulnerabilidades conhecidas com severidade e versão de correção.

Fonte: OSV.dev — base agregada (GitHub Advisory, NVD, PyPA, etc.), sem chave.
"""
import json
import os
import threading
import time
import urllib.request

OSV_URL = "https://api.osv.dev/v1/query"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"


# ---------- leitura das stacks ----------
def _componentes_de_composer(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    out = []
    for grupo in ("packages", "packages-dev"):
        for p in d.get(grupo, []):
            v = str(p.get("version", "")).lstrip("v")
            if p.get("name") and v:
                out.append({"ecosystem": "Packagist", "name": p["name"], "version": v})
    return out


def _componentes_de_npm(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    out = []
    for caminho, p in (d.get("packages") or {}).items():
        nome = p.get("name") or (caminho.split("node_modules/")[-1] if caminho else "")
        v = p.get("version")
        if nome and v:
            out.append({"ecosystem": "npm", "name": nome, "version": v})
    return out


def carregar_stacks(stacks_file):
    """Lê stacks.json: {"apps":[{"name","lock"}], "componentes":[{ecosystem,name,version}]}."""
    comps = []
    if not stacks_file or not os.path.exists(stacks_file):
        return comps
    try:
        with open(stacks_file, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return comps
    base = os.path.dirname(os.path.abspath(stacks_file))
    for app in cfg.get("apps", []):
        lock = app.get("lock", "")
        lock = lock if os.path.isabs(lock) else os.path.join(base, lock)
        if not os.path.exists(lock):
            continue
        try:
            novos = _componentes_de_composer(lock) if "composer" in lock else _componentes_de_npm(lock)
        except (OSError, json.JSONDecodeError, KeyError):
            novos = []
        for c in novos:
            c["origem"] = app.get("name", os.path.basename(lock))
        comps += novos
    for c in cfg.get("componentes", []):
        if c.get("ecosystem") and c.get("name") and c.get("version"):
            comps.append({**c, "origem": c.get("origem", "manual")})
    # dedupe por (ecosystem,name,version)
    vistos, saida = set(), []
    for c in comps:
        chave = (c["ecosystem"], c["name"], c["version"])
        if chave not in vistos:
            vistos.add(chave)
            saida.append(c)
    return saida


# ---------- consulta OSV ----------
def _severidade(vuln):
    sev = vuln.get("severity") or []
    for s in sev:
        if s.get("type", "").startswith("CVSS") and s.get("score"):
            return s["score"]
    ds = (vuln.get("database_specific") or {}).get("severity")
    return ds or "—"


def _correcao(vuln):
    for af in vuln.get("affected", []):
        for rng in af.get("ranges", []):
            for ev in rng.get("events", []):
                if ev.get("fixed"):
                    return ev["fixed"]
    return None


def _post(url, obj, timeout):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _get(url, timeout):
    with urllib.request.urlopen(urllib.request.Request(url), timeout=timeout) as r:
        return json.load(r)


def consultar_osv(componentes, timeout=12):
    """Uma chamada em lote (querybatch) para todos os componentes; detalhe só dos que têm vuln."""
    if not componentes:
        return []
    queries = [{"package": {"ecosystem": c["ecosystem"], "name": c["name"]}, "version": c["version"]}
               for c in componentes]
    # querybatch aceita muitos; fatiamos em blocos por segurança.
    resultados = []
    for i in range(0, len(queries), 200):
        try:
            d = _post(OSV_BATCH, {"queries": queries[i:i + 200]}, timeout)
            resultados += d.get("results", [])
        except Exception:  # noqa: BLE001 - rede indisponível não derruba o advisor
            resultados += [{} for _ in queries[i:i + 200]]
    advisories, cache = [], {}
    for c, res in zip(componentes, resultados):
        for ref in (res or {}).get("vulns", []):
            vid = ref.get("id")
            if not vid:
                continue
            if vid not in cache:
                try:
                    cache[vid] = _get(OSV_VULN + vid, timeout)
                except Exception:  # noqa: BLE001
                    cache[vid] = {"id": vid}
            v = cache[vid]
            cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), vid)
            advisories.append({
                "origem": c.get("origem", ""),
                "pacote": c["name"], "ecosystem": c["ecosystem"], "versao": c["version"],
                "id": cve, "osv_id": vid,
                "resumo": (v.get("summary") or v.get("details", "")[:160] or "").strip(),
                "severidade": _severidade(v),
                "correcao": _correcao(v),
                "ref": f"https://osv.dev/vulnerability/{vid}",
            })
    # ordena por severidade numérica desc quando houver
    def chave(a):
        try:
            return -float(a["severidade"])
        except (TypeError, ValueError):
            return 0.0
    advisories.sort(key=chave)
    return advisories


class Advisor:
    def __init__(self, env=os.environ, on_new=None):
        self.enabled = env.get("ADVISOR_ENABLED", "false").lower() == "true"
        self.stacks_file = env.get("ADVISOR_STACKS_FILE", "")
        self.intervalo = int(env.get("ADVISOR_REFRESH_HOURS", 12)) * 3600
        self.on_new = on_new  # callback(advisories) p/ WhatsApp dos novos críticos
        self.advisories = []
        self.atualizado_em = None
        self._lock = threading.Lock()
        if self.enabled:
            threading.Thread(target=self._loop, daemon=True).start()

    def atual(self):
        with self._lock:
            return {"atualizado_em": self.atualizado_em, "itens": list(self.advisories)}

    def atualizar(self):
        comps = carregar_stacks(self.stacks_file)
        novos = consultar_osv(comps)
        with self._lock:
            antigos = {a["osv_id"] for a in self.advisories}
            self.advisories = novos
            self.atualizado_em = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            criticos_novos = [a for a in novos if a["osv_id"] not in antigos]
        if criticos_novos and self.on_new:
            try:
                self.on_new(criticos_novos)
            except Exception:  # noqa: BLE001
                pass
        return novos

    def _loop(self):
        while True:
            try:
                self.atualizar()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(self.intervalo)
