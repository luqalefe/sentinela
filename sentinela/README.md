# Sentinela

Detector de ataques HTTP para app Laravel em homologação. Requisitos: `../docs/requisitos.md`.

## Rodar
```
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env   # e exporte as variáveis (set -a; . ./.env; set +a)
.venv/bin/python detector/train.py          # lê data/train.csv (value,label) → models/
.venv/bin/python detector/server.py         # sobe API + dashboard em http://127.0.0.1:8765/
.venv/bin/python -m pytest tests
```
O dashboard (`/`) pede a chave na primeira abertura (SENTINELA_API_KEY).
Sem `models/classifier.joblib` o servidor sobe só com regras; sem `models/anomaly.joblib` usa limiares por IP.

## Latência
`/analyze`, 200 requisições benignas seguidas (localhost, 2 parâmetros, classificador TF-IDF+LR treinado num CSV sintético pequeno): **p95 = 0,56 ms** (média 0,55 ms, medida no cliente, incluindo HTTP). Meta RNF1: < 30 ms. Refazer com o modelo real do time, que é maior.

## Logs
`logs/alerts.jsonl` guarda o alerta ao nascer (explanation null); a explicação do DeepSeek chega depois e é anexada em `logs/alerts_updates.jsonl` (`{alert_id, explanation}`).
