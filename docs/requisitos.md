# Sentinela — Requisitos da ferramenta de detecção de ataques
24/10/2026 · @lucas

## Visão geral
Serviço que analisa cada requisição de um app Laravel em homologação, classifica o risco com um modelo de ML open source e mostra os alertas num painel ao vivo. Cada alerta vem com uma explicação em português gerada pelo DeepSeek. MVP funcional e demonstrável hoje, no hackathon.

## Objetivo do MVP
- Classificar valores de parâmetros HTTP em normal, sqli, xss, traversal ou cmdi com modelo treinado localmente (scikit-learn).
- Detectar comportamento anômalo por IP (rajadas, muitos 404, muitas falhas de login) com Isolation Forest.
- Bloquear requisições acima de um limiar de risco via middleware Laravel, com 403.
- Alertas em tempo real num dashboard: tipo, IP, rota, score, técnica MITRE ATT&CK.
- Explicação do alerta e sugestão de correção via DeepSeek, assíncrona.

## Fora de escopo
- Gerar datasets de ataque ou scripts que disparam tráfego malicioso: o time fornece dados e scripts de demo.
- Produção, alta disponibilidade, multi-tenant, autenticação no dashboard.
- Tráfego de rede (pacotes) ou endpoints: só a camada HTTP da aplicação.

## Arquitetura e stack
O middleware envia o resumo da requisição e espera só o veredito (até 300 ms). Alertas vão ao dashboard por SSE; a explicação do DeepSeek é pedida em segundo plano. Depois da resposta, o Laravel devolve o status HTTP para alimentar a janela por IP.
- Detector: Python 3.10+, http.server + ThreadingHTTPServer, scikit-learn, joblib.
- LLM: DeepSeek via API compatível com OpenAI, com urllib (sem SDK).
- Dashboard: HTML + JS puro, Chart.js via CDN, SSE.
- Integração: middleware Laravel com o client Http nativo.

```
sentinela/
  detector/
    server.py          # API, SSE, decisão, lista de bloqueio
    train.py           # RF1
    train_anomaly.py   # RF2
    normalize.py  mask.py  rules.py  mitre.py  explainer.py  ipwindow.py
    static/index.html  # dashboard
  data/                # CSVs fornecidos pelo time (fora do git)
  models/              # artefatos gerados
  logs/alerts.jsonl
  tests/
  laravel/
    app/Http/Middleware/SentinelaGuard.php
    config/sentinela.php
    resources/views/sentinela/blocked.blade.php
  .env.example  requirements.txt  README.md
```

## Requisitos funcionais
### RF1 — Treino do classificador de payloads
1. detector/train.py lê data/train.csv (colunas value, label; 5 classes).
2. Adaptador para o CSIC 2010 HTTP (requisições → valores de parâmetros); rótulo binário normal/ataque (ver questão em aberto).
3. Pipeline: URL decode (até 2 níveis), minúsculas, TfidfVectorizer(analyzer='char_wb', ngram_range=(2,5)) + LogisticRegression(class_weight='balanced').
4. Split 80/20 estratificado; salva models/classifier.joblib e models/metrics.json (acurácia, precisão/recall por classe, matriz de confusão).
5. Imprime métricas e gera models/confusion.png para o pitch.

### RF2 — Anomalia por IP
1. Janela deslizante de 60 s por IP: req/min, proporção 4xx, proporção 404, falhas de login (rota configurável), rotas distintas, tamanho médio de payload.
2. detector/train_anomaly.py treina IsolationForest sobre data/normal_windows.csv → models/anomaly.joblib.
3. Sem modelo, fallback por regras de limiar configuráveis, indicado no dashboard.
4. Rótulos: brute_force (falhas de login), scan (muitos 404 e rotas distintas), flood (taxa alta).

### RF3 — API de análise
1. Servidor Python (stdlib + scikit-learn) em SENTINELA_PORT (8765).
2. POST /analyze: analisa cada valor de parâmetro; maior score de ataque = risk.
3. risk = max(payload_risk, ip_risk).
4. allow/flag/block por SENTINELA_FLAG (0.5) e SENTINELA_BLOCK (0.85).
5. IP com 3 bloqueios em 5 min → lista de bloqueio por 10 min (ip_blocked na resposta).
6. GET /health, GET /api/stats, GET /api/alerts?limit=50, POST /api/unblock, POST /api/reset.

### RF4 — Comparação com regras estáticas
1. rules.py: poucas regex estilo WAF básico, em paralelo ao modelo.
2. Cada alerta tem rule_hit; dashboard mostra contador "detectado só pelo modelo" (argumento principal do pitch).

### RF5 — Explicador DeepSeek
1. Para cada flag/block, enfileira explicação em thread separada; nunca no caminho da requisição.
2. POST {DEEPSEEK_BASE_URL}/chat/completions com DEEPSEEK_MODEL.
3. Prompt: em português, até 120 palavras: o que o padrão tenta, impacto, correção em Laravel (Eloquent/bindings, escape no Blade, validação de caminho).
4. Cache por hash do payload normalizado.
5. 1 chamada simultânea, timeout 15 s. Erro ou sem chave → texto padrão por classe.
6. Chega ao dashboard como atualização do alerta exibido.

### RF6 — Dashboard ao vivo
1. Página única em GET /, sem build: HTML + JS puro + Chart.js via CDN.
2. SSE em GET /events.
3. Contadores (requisições, alertas, bloqueios, "só o modelo pegou"), gráfico req/s por veredito, distribuição por tipo, top IPs, feed.
4. Feed: hora, IP, método, rota, tipo, score, MITRE, veredito, explicação quando chegar.
5. Payload truncado (80 chars) com escape HTML; nunca renderizado como HTML.
6. Botões: desbloquear IP, resetar demo.

### RF7 — Middleware Laravel
1. App\Http\Middleware\SentinelaGuard + config/sentinela.php, Laravel 10 e 11+ (instruções Kernel.php e bootstrap/app.php).
2. Resumo: IP (proxies confiáveis), método, path, query, corpo (form/JSON achatado chave → valor), user-agent.
3. Remove except_fields (password, password_confirmation, _token, token, card_number, cvv) e todos os cookies.
4. Http::timeout(0.3) em /analyze; detector fora ou lento → fail-open + log.
5. block → 403 com view "Requisição bloqueada pelo Sentinela" e alert_id. flag → passa com header X-Sentinela-Risk.
6. terminate: envia status HTTP para /api/feedback.
7. .env: SENTINELA_ENABLED, SENTINELA_URL, SENTINELA_MODE (monitor | enforce).

### RF8 — MITRE ATT&CK (dicionário em mitre.py)
| Classe | Técnica | ID |
|---|---|---|
| sqli, xss, traversal, cmdi | Exploit Public-Facing Application | T1190 |
| cmdi | Command and Scripting Interpreter | T1059 |
| traversal | File and Directory Discovery | T1083 |
| brute_force | Brute Force | T1110 |
| scan | Active Scanning | T1595 |
| flood | Network Denial of Service | T1498 |

## Requisitos não funcionais
| ID | Requisito | Meta |
|---|---|---|
| RNF1 | Latência /analyze (p95, sem LLM) | < 30 ms |
| RNF2 | Disponibilidade | Fail-open |
| RNF3 | Dependências Python | só scikit-learn, joblib, numpy, matplotlib; servidor stdlib |
| RNF4 | Versões | Python 3.10+; PHP 8.1+, Laravel 10/11+ |
| RNF5 | Armazenamento | memória (últimos 1.000 alertas) + logs/alerts.jsonl |
| RNF6 | Configuração | env vars + .env.example |
| RNF7 | Execução | `python detector/server.py` sobe tudo |

## Privacidade (DeepSeek)
- Envia só: classe, score, rota, nome do parâmetro, valor truncado em 300 chars. Nunca IP, cookies, headers, e-mails, documentos.
- Mascarar e-mail, CPF, telefone, cartão por regex antes do envio.
- DEEPSEEK_ENABLED=false desliga a chamada; painel usa textos padrão.
- DEEPSEEK_BASE_URL pode apontar para instância própria (vLLM) sem mudar código.

## Segurança do Sentinela
- Escuta em 127.0.0.1 por padrão (SENTINELA_HOST).
- /analyze e /api/* exigem X-Sentinela-Key == SENTINELA_API_KEY.
- Chave DeepSeek só em env; nunca em log, resposta ou dashboard.
- Toda saída da LLM e todo payload exibido com escape.

## Contratos
POST /analyze — requisição
```json
{"request_id":"uuid","ip":"203.0.113.10","method":"GET","path":"/produtos/busca",
 "params":{"q":"tenis azul","page":"2"},"user_agent":"Mozilla/5.0 ...","app":"ecommerce-homolog","ts":"2026-10-24T14:30:00Z"}
```
POST /analyze — resposta
```json
{"request_id":"...","verdict":"allow | flag | block","risk":0.93,"category":"sqli","param":"q",
 "source":"payload | ip_behavior","mitre":{"id":"T1190","name":"Exploit Public-Facing Application"},
 "rule_hit":false,"ip_blocked":false,"alert_id":"a-000123","latency_ms":4.2}
```
POST /api/feedback: `{"request_id":"...","ip":"...","path":"...","status":404,"login_failed":false}` → 204.

SSE GET /events:
- `request` → {ts, verdict} a cada requisição.
- `alert` → Alerta completo.
- `alert_update` → {alert_id, explanation}.
- `stats` → contadores a cada 1 s.

Alerta (logs/alerts.jsonl): alert_id (sequencial), ts (ISO UTC), ip, method, path, app, param (maior risco), value_preview (80 chars, mascarado), category (5 payload + 3 comportamento), risk (0–1), verdict (flag|block), rule_hit, mitre_id, explanation (ou null).

## Variáveis de ambiente
| var | padrão | uso |
|---|---|---|
| SENTINELA_HOST | 127.0.0.1 | interface |
| SENTINELA_PORT | 8765 | porta |
| SENTINELA_API_KEY | (obrigatória) | X-Sentinela-Key |
| SENTINELA_FLAG | 0.5 | limiar alerta |
| SENTINELA_BLOCK | 0.85 | limiar bloqueio |
| SENTINELA_LOGIN_PATH | /login | falhas de login |
| DEEPSEEK_ENABLED | true | liga explicação |
| DEEPSEEK_BASE_URL | https://api.deepseek.com | API OpenAI-compatível |
| DEEPSEEK_MODEL | deepseek-chat | modelo |
| DEEPSEEK_API_KEY | (obrigatória se habilitado) | chave |

## Critérios de aceite
- [ ] train.py gera classifier.joblib, metrics.json, confusion.png sobre o CSV do time.
- [ ] Macro F1 ≥ 0,90 no teste.
- [ ] /analyze p95 < 30 ms com 200 requisições seguidas.
- [ ] Detector desligado → Laravel responde normal (fail-open).
- [ ] enforce: acima do limiar → 403 com alert_id.
- [ ] Senha, _token e cookies nunca chegam ao detector.
- [ ] Alerta no dashboard < 1 s; explicação depois, sem travar feed.
- [ ] Sem DEEPSEEK_API_KEY → texto padrão, sem erro.
- [ ] Contador "só o modelo" funciona.
- [ ] "Resetar demo" zera contadores, alertas e bloqueios.

## Testes (pytest, sem deps extras)
- Normalização: decode 2 níveis, minúsculas, vazios.
- Mascaramento: e-mail, CPF, telefone, cartão → [email], [cpf] etc.
- Decisão: limiares e combinação payload × IP.
- Janela por IP: expira em 60 s; bloqueio expira em 10 min.
- Explicador: cache por hash, fallback em falha/timeout.
- Middleware (PHPUnit): except_fields, timeout/fail-open, 403 em block.

## Roteiro da demo (5 min)
1. App de homolog + dashboard lado a lado; navegação normal, painel verde.
2. Script de tráfego do time; alertas com tipo, score, MITRE.
3. Abrir alerta e ler explicação do DeepSeek.
4. Caso "só o modelo pegou" vs regra estática.
5. enforce: 403 e IP na lista de bloqueio.
6. Slide de métricas (confusion.png) e arquitetura.

## Questão em aberto
CSIC 2010 é binário. Padrão sugerido: 5 classes do CSV do time; CSIC só como teste extra binário.

## Ordem de implementação
Fatias que já rodam, cada passo testável. Não gerar datasets de ataque nem scripts de tráfego: usar o que o time puser em data/, e um CSV pequeno só com valores normais para testes.
1. Estrutura, requirements.txt, .env.example, README.
2. normalize.py, mask.py, mitre.py, rules.py com testes.
3. train.py (RF1).
4. server.py com /health e /analyze só com classificador (RF3 1–4).
5. Janela por IP, fallback de limiares, /api/feedback, lista de bloqueio (RF2, RF3 5–6).
6. Dashboard SSE (RF6).
7. Middleware Laravel (RF7): monitor, depois enforce.
8. Explicador DeepSeek com fila, cache, fallback (RF5).
9. train_anomaly.py, se der tempo.
10. Critérios de aceite e roteiro de ponta a ponta.

Corte se apertar: pular 9 e reduzir dashboard a contadores + feed. Mínimo para a demo: 3, 4, 6, 7, 8.
