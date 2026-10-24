# Como o Sentinela usa IA

Documento honesto de onde a IA entra na detecção e no envio de alertas — e onde **não** entra. Isso importa para o Q&A do pitch: se um juiz perguntar "é a LLM que detecta?", a resposta precisa estar certa.

---

## Resumo em uma frase

> A **detecção** é feita por **machine learning + heurística + regra estática** (dentro do detector). A **LLM** (DeepSeek, Ollama, etc.) só **explica** o alerta e responde o **chat de logs** — ela não decide bloqueio.

Separar isso é de propósito: a decisão de bloquear precisa ser **determinística e em < 30 ms**, no caminho da requisição. Uma chamada a LLM é lenta (segundos) e não-determinística, então fica fora do caminho crítico, sempre em segundo plano.

---

## 1. Detecção — onde a inteligência mora

A decisão final é `risk = max(risco_payload, risco_ip)`, comparada aos limiares `SENTINELA_FLAG` (0.5) e `SENTINELA_BLOCK` (0.85). Três fontes alimentam esse risco:

### a) Classificador de payload — ML (o "modelo" do pitch)
`detector/train.py` → `detector/server.py`

- **Modelo:** `TfidfVectorizer(analyzer="char_wb", ngram_range=(2,5))` + `LogisticRegression(class_weight="balanced")` (scikit-learn), salvo em `models/classifier.joblib`.
- **Por que char n-gram:** ataques são jogos de caracteres (`' OR 1=1`, `<script>`, `../`). N-gramas de caractere capturam variações e ofuscação que uma lista de palavras não pega — é o que dá o contador **"só o modelo pegou"**.
- **Entrada:** cada valor de parâmetro é normalizado (URL-decode até 2 níveis + minúsculas) antes de classificar. Usa-se o **maior score de ataque** entre os parâmetros.
- **Sem o modelo treinado:** o servidor sobe mesmo assim e cai no item (c), as regras.

> Isso é IA no sentido de **aprendizado de máquina**, não LLM. É um modelo pequeno, local, open source, que roda em milissegundos.

### b) Anomalia de comportamento por IP — ML / heurística
`detector/ipwindow.py`

- Janela deslizante de 60s por IP com: req/min, proporção de 4xx e 404, falhas de login, rotas distintas e tamanho médio de payload.
- **Com modelo:** `IsolationForest` (`models/anomaly.joblib`) classifica a janela como anômala.
- **Sem modelo (fallback):** limiares configuráveis → `brute_force` / `scan` / `flood`. O painel mostra qual modo está ativo.

### c) Regra estática — WAF de assinatura (baseline, não é IA)
`detector/rules.py`

- Poucas regex no estilo WAF básico, rodando **em paralelo** ao modelo.
- Serve de **contraste**: cada alerta marca `rule_hit`. Quando o modelo/heurística pega e a regra **não**, incrementa **"só o modelo pegou"** — o argumento central do pitch.
- Também cobre as CVEs recentes de PHP (2024-4577, 52301, filter chains) por assinatura.

### d) OOM-DoS — heurística de tamanho
`detector/server.py`

- Se o corpo da requisição passa de `SENTINELA_OOM_BYTES` (1 MB), vira categoria `oom` (MITRE T1499). Defesa na borda contra a memory bomb (CVE-2026-109618). O middleware reporta só o `body_bytes`, não o payload inteiro.

---

## 2. Explicação com LLM — a IA generativa

`detector/explainer.py`

Para cada alerta `flag`/`block`, uma **thread separada** (nunca o caminho da requisição) chama um modelo via API **compatível com OpenAI**:

1. **Prompt:** pede, em português e em até 120 palavras, o que o padrão tenta fazer, o impacto e a **correção em Laravel** (Eloquent/bindings, escape no Blade, validação de caminho).
2. **Cache por hash** do payload normalizado — o mesmo padrão não gera nova chamada.
3. **1 chamada simultânea, timeout curto.** Em erro ou sem chave → **texto padrão por classe** (a demo nunca quebra).
4. A explicação chega ao painel como atualização do alerta já exibido (evento SSE `alert_update`).

**Provedor trocável na tela** (`/api/provider`): DeepSeek, OpenAI, OpenRouter, Groq (pagos) ou **Ollama / vLLM** (open source, roda local). Reforça o requisito de "modelo open source" no pitch — e a chave nunca volta para a tela nem para log.

### Privacidade enviada à LLM
`detector/mask.py`

- Vai só: classe, score, rota, nome do parâmetro e o valor truncado em 300 chars. **Nunca** IP, cookies, headers.
- E-mail, CPF, telefone e cartão são **mascarados** por regex antes do envio (`[email]`, `[cpf]`…).

---

## 3. Chat de logs — LLM sobre os dados
`detector/chatlogs.py` → `POST /api/chat`

- Monta o contexto a partir dos alertas em memória + cauda do `alerts.jsonl` (contagem por tipo/veredito, top IPs, janela).
- Manda ao **mesmo provedor** do explicador e responde em linguagem natural.
- **Sem chave/provedor:** devolve um **resumo determinístico** dos números (sem LLM), `provider="local"`.
- Privacidade: IPs viram `IP-1`, `IP-2`… no prompt e são traduzidos de volta na resposta.

---

## 4. Envio dos alertas no WhatsApp
`detector/wa_notify.py`

- Modo **resumo agrupado**: junta os bloqueios numa janela curta e manda **uma** mensagem (contagem por tipo, top IPs, pior caso). Nunca uma mensagem por alerta — centenas floodariam o número.
- Entrega via **Evolution API** (`POST /message/sendText/{instância}`), em thread própria, fora do caminho da requisição.
- Desligado por padrão; tudo por env (`WA_ALERTS_ENABLED`, `WA_ALERT_TO`, `WA_EVOLUTION_*`). Chave nunca em log nem resposta.

---

## E a "skill de cybersec"?

Não há, neste ambiente, uma skill do Claude que faça **detecção de ataques em tempo real** — e nem faria sentido no caminho da requisição (latência e não-determinismo). A única skill de segurança disponível é `security-review`, que revisa **código** em busca de vulnerabilidades (útil no desenvolvimento, não em runtime).

A detecção do Sentinela é **código próprio**: modelo scikit-learn + Isolation Forest + regras + heurística de tamanho. A IA generativa (LLM) entra como camada **assíncrona**, nunca no bloqueio:

- **Explicador** (`explainer.py`) — descreve o alerta e a correção.
- **Chat de logs** (`chatlogs.py`) — perguntas sobre os alertas.
- **LLM-as-detector / revisor** (`reviewer.py`) — segunda opinião por alerta: ataque real ou provável **falso positivo**, com confiança e motivo. Aparece como badge no feed e no contador `false_positives`. Não muda o veredito.

## 5. Advisor de CVEs por stack — proativo

`detector/advisor.py` → `GET /api/advisories`

Fora da detecção de tráfego, o Sentinela também **antecipa**: lê os componentes das apps de `composer.lock` / `package-lock.json` e de um `stacks.json`, consulta o **OSV.dev** (base agregada de GitHub Advisory, NVD, PyPA…) em lote e lista as vulnerabilidades conhecidas com severidade e **versão de correção**. Roda num intervalo configurável, fora do caminho da requisição, e avisa no WhatsApp quando surge CVE nova. É dado de fonte oficial, não heurística.
