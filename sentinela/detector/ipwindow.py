"""Janela deslizante por IP (RF2), lista de bloqueio (RF3.5) e fallback por limiares."""
import threading
import time
from collections import defaultdict, deque

JANELA = 60
BLOQ_N, BLOQ_JANELA, BLOQ_DURACAO = 3, 300, 600

# Limiares do fallback; o servidor pode sobrescrever.
LIMIARES = {"flood_rpm": 120, "scan_404": 0.5, "scan_rotas": 10, "scan_min_req": 10, "brute_falhas": 5}


class JanelaIP:
    def __init__(self, login_path="/login", agora=time.time):
        self.login_path = login_path
        self.agora = agora
        self.lock = threading.Lock()
        self.eventos = defaultdict(deque)   # ip -> (ts, path, status|None, login_falhou, tamanho)
        self.bloqueios = defaultdict(deque)  # ip -> ts dos bloqueios
        self.ate = {}                        # ip -> fim do bloqueio

    def _podar(self, ip, t):
        d = self.eventos[ip]
        while d and t - d[0][0] > JANELA:
            d.popleft()
        return d

    def registrar_requisicao(self, ip, path, tamanho=0):
        t = self.agora()
        with self.lock:
            self._podar(ip, t).append((t, path, None, False, tamanho))

    def registrar_feedback(self, ip, path, status, login_falhou=False):
        t = self.agora()
        with self.lock:
            # O status chega depois da resposta; vira evento próprio para contar 4xx/404.
            self._podar(ip, t).append((t, path, status, bool(login_falhou), 0))

    def features(self, ip):
        t = self.agora()
        with self.lock:
            d = self._podar(ip, t)
            reqs = [e for e in d if e[2] is None]
            fb = [e for e in d if e[2] is not None]
        n = len(reqs)
        nfb = len(fb)
        return {
            "req_min": float(n),
            "prop_4xx": sum(1 for e in fb if 400 <= e[2] < 500) / nfb if nfb else 0.0,
            "prop_404": sum(1 for e in fb if e[2] == 404) / nfb if nfb else 0.0,
            "falhas_login": float(sum(1 for e in fb if e[3])),
            "rotas_distintas": float(len({e[1] for e in reqs})),
            "payload_medio": sum(e[4] for e in reqs) / n if n else 0.0,
            "_n_fb": nfb,
        }

    def risco_limiar(self, ip, limiares=None):
        """Fallback sem modelo: (risco, categoria) pelas regras do RF2.4."""
        L = {**LIMIARES, **(limiares or {})}
        f = self.features(ip)
        if f["falhas_login"] >= L["brute_falhas"]:
            return 0.9, "brute_force"
        if f["_n_fb"] >= L["scan_min_req"] and f["prop_404"] >= L["scan_404"] and f["rotas_distintas"] >= L["scan_rotas"]:
            return 0.9, "scan"
        if f["req_min"] >= L["flood_rpm"]:
            return 0.9, "flood"
        return 0.0, None

    # --- lista de bloqueio ---
    def registrar_bloqueio(self, ip):
        t = self.agora()
        with self.lock:
            d = self.bloqueios[ip]
            d.append(t)
            while d and t - d[0] > BLOQ_JANELA:
                d.popleft()
            if len(d) >= BLOQ_N:
                self.ate[ip] = t + BLOQ_DURACAO
                d.clear()

    def bloqueado(self, ip):
        with self.lock:
            fim = self.ate.get(ip)
            if fim is None:
                return False
            if self.agora() >= fim:
                del self.ate[ip]
                return False
            return True

    def desbloquear(self, ip):
        with self.lock:
            self.ate.pop(ip, None)
            self.bloqueios.pop(ip, None)

    def lista_bloqueados(self):
        t = self.agora()
        with self.lock:
            return {ip: round(fim - t) for ip, fim in self.ate.items() if fim > t}

    def top_ips(self, k=5):
        with self.lock:
            return sorted(((ip, len(d)) for ip, d in self.eventos.items() if d), key=lambda x: -x[1])[:k]

    def reset(self):
        with self.lock:
            self.eventos.clear()
            self.bloqueios.clear()
            self.ate.clear()
