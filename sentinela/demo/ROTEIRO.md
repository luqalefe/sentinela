# Roteiro da demo — Sentinela (5 min)

Dois terminais abertos + o dashboard no navegador.

## Antes de começar (uma vez)
```bash
cd ~/code/hackathon-ataques/sentinela
chmod +x demo/*.sh

# (opcional, mas recomendado) treinar o modelo com o CSV do time:
#   coloque data/train.csv (colunas: value,label) e rode:
# .venv/bin/python detector/train.py

# (opcional) ligar a explicação em linguagem natural:
#   export DEEPSEEK_API_KEY=... antes de subir, ou configure o provedor no painel
```

## Terminal 1 — sobe o detector (deixe aberto)
```bash
./demo/00-subir.sh
```
Ele imprime a URL (`http://127.0.0.1:8765/`) e a **chave do painel**. Abra a URL no navegador e cole a chave em "X-Sentinela-Key" → Conectar.

## Terminal 2 — as cenas (uma por vez, durante a fala)

**1. Linha-base verde** — abra o painel ao lado, mostre os contadores zerados.
```bash
./demo/cena.sh reset
```

**2. Ataques aparecendo** — payloads clássicos; veja o feed, os tipos, o score e o MITRE.
```bash
./demo/cena.sh payload
```

**3. Explicação do alerta** — abra um alerta no feed e leia a explicação (DeepSeek, ou texto padrão sem chave).

**4. "Só o modelo pegou"** — compare modelo × regra estática no contador (precisa do modelo treinado).

**5. Comportamento por IP** — varredura, força bruta e rajada; o IP entra na lista de bloqueio.
```bash
./demo/cena.sh scan
./demo/cena.sh brute
./demo/cena.sh flood
```

**6. Chat de logs** — no painel, pergunte em português, ex.: *"qual IP mais atacou e de que tipo?"*.

**7. Slide de métricas** — `models/confusion.png` (gerado pelo train.py) e a arquitetura.

## Dica
- Para reensaiar do zero a qualquer momento: `./demo/cena.sh reset`.
- Tudo roda em `127.0.0.1`; são amostras de teste contra o seu próprio serviço.
