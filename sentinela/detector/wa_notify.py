"""Notificação de alertas no WhatsApp via Evolution API (número pareado).

Modo RESUMO AGRUPADO: junta os alertas que chegam numa janela curta e envia UMA
mensagem com a contagem por tipo, top IPs e os piores casos. Nunca manda uma
mensagem por alerta — a demo gera centenas e isso floodaria/banir o número.

Tudo opcional e por env; desligado por padrão. A chave da Evolution nunca é
registrada em log nem devolvida. Roda numa thread própria, fora do caminho da
requisição.
"""
import json
import os
import threading
import time
import urllib.request

try:
    from mask import mask
except ImportError:  # quando importado como pacote
    from .mask import mask


class WhatsAppNotifier:
    def __init__(self, env=os.environ):
        self.enabled = env.get("WA_ALERTS_ENABLED", "false").lower() == "true"
        self.base = (env.get("WA_EVOLUTION_BASE_URL") or env.get("EVOLUTION_BASE_URL") or "http://localhost:8081").rstrip("/")
        self.instance = env.get("WA_EVOLUTION_INSTANCE") or env.get("EVOLUTION_INSTANCE") or "pulso"
        self.key = env.get("WA_EVOLUTION_API_KEY") or env.get("EVOLUTION_API_KEY") or ""
        self.to = env.get("WA_ALERT_TO", "")
        self.window = int(env.get("WA_SUMMARY_SECONDS", 30))
        # Só notifica veredictos deste nível para cima.
        self.only_block = env.get("WA_ONLY_BLOCK", "true").lower() == "true"

        self._buf = []
        self._lock = threading.Lock()
        self._stop = False
        if self.enabled and self.to and self.key:
            threading.Thread(target=self._loop, daemon=True).start()

    def submit(self, alerta):
        """Enfileira um alerta para o próximo resumo. Nunca bloqueia nem lança."""
        if not (self.enabled and self.to and self.key):
            return
        if self.only_block and alerta.get("verdict") != "block":
            return
        with self._lock:
            self._buf.append(alerta)

    def _loop(self):
        while not self._stop:
            time.sleep(self.window)
            with self._lock:
                lote, self._buf = self._buf, []
            if lote:
                try:
                    self._enviar(self._resumir(lote))
                except Exception as e:  # nunca derruba o servidor por causa do WhatsApp
                    print(f"[wa_notify] falha ao enviar: {type(e).__name__}", flush=True)

    def _resumir(self, lote):
        por_tipo, por_ip = {}, {}
        for a in lote:
            por_tipo[a.get("category")] = por_tipo.get(a.get("category"), 0) + 1
            por_ip[a.get("ip")] = por_ip.get(a.get("ip"), 0) + 1
        top_tipo = sorted(por_tipo.items(), key=lambda kv: -kv[1])
        top_ip = sorted(por_ip.items(), key=lambda kv: -kv[1])[:3]
        # Pior caso individual (maior risco), com payload mascarado e truncado.
        pior = max(lote, key=lambda a: a.get("risk", 0))
        preview = mask(str(pior.get("value_preview", "")))[:80]

        linhas = [
            "🛡️ *Sentinela* — alerta de segurança",
            f"{len(lote)} bloqueio(s) nos últimos {self.window}s",
            "",
            "*Por tipo:* " + ", ".join(f"{t}: {n}" for t, n in top_tipo),
            "*Top IPs:* " + ", ".join(f"{ip} ({n})" for ip, n in top_ip),
            "",
            f"*Pior caso:* {pior.get('category')} risk={pior.get('risk')} "
            f"em {pior.get('method')} {pior.get('path')} (MITRE {pior.get('mitre_id')})",
        ]
        if preview:
            linhas.append(f"payload: `{preview}`")
        return "\n".join(linhas)

    def enviar_texto(self, texto):
        """Envio avulso (ex.: advisor de CVEs). Respeita enabled/chave/destino."""
        if not (self.enabled and self.to and self.key):
            return
        try:
            self._enviar(texto)
        except Exception as e:  # noqa: BLE001
            print(f"[wa_notify] falha ao enviar: {type(e).__name__}", flush=True)

    def _enviar(self, texto):
        url = f"{self.base}/message/sendText/{self.instance}"
        corpo = json.dumps({"number": self.to, "text": texto}).encode()
        req = urllib.request.Request(url, data=corpo, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("apikey", self.key)
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
