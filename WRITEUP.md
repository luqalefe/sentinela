# Sentinela — Write-up

**Detecção de padrões de ataque em tempo real para aplicações Laravel, com IA e modelos open source.**

- **Repositório:** https://github.com/luqalefe/sentinela
- **Stack:** Python (stdlib + scikit-learn) · Laravel 10/11 · HTML/JS + Chart.js (SSE) · LLM OpenAI-compatível (DeepSeek/Ollama/vLLM) · Evolution API · OSV.dev

---

## 1. O problema

Um WAF de regex vê a **assinatura**, não a **intenção**. Ataques ofuscados, CVEs novas de PHP e abuso de comportamento passam direto por regras estáticas. Quando o time percebe, já virou incidente — e ninguém sabe explicar o que aconteceu nem o que corrigir.

## 2. A solução

O Sentinela analisa cada requisição HTTP de um app Laravel em homologação, combina **três sinais de detecção**, bloqueia na borda e mostra tudo num painel ao vivo — cada alerta com explicação em português e a correção recomendada. Depois, vai além da reação: **antecipa** as CVEs da própria stack.

## 3. O que faz

1. **Classifica payloads** com modelo de ML local (scikit-learn: TF-IDF char n-gram + Regressão Logística): `sqli`, `xss`, `traversal`, `cmdi`, `normal`.
2. **Vigia comportamento por IP** (janela de 60s): rajadas, varredura e força bruta (Isolation Forest, com limiares de fallback).
3. **Bloqueia na borda** via middleware Laravel (403). *Fail-open*: detector fora não derruba o app.
4. **Explica** cada alerta em português com LLM (ataque, impacto, correção em Laravel). Provedor trocável na tela.
5. **Revisa (LLM-as-detector)**: 2ª opinião da IA por alerta — ataque real ou provável **falso positivo**, sem mudar o veredito.
6. **Antecipa CVEs**: cruza a stack das apps (`composer.lock`/`package-lock.json` + `stacks.json`) com o **OSV.dev** e lista o que atualizar.
7. **Avisa no WhatsApp** (Evolution API): resumo agrupado dos bloqueios e das CVEs novas.
8. **Chat de logs**: perguntas em linguagem natural ("qual IP mais atacou?").

## 4. Arquitetura

```
App Laravel (middleware)  →  Detector Python /analyze (<30ms)  →  Painel ao vivo (SSE)
                          ←  veredito allow/flag/block
Detector  ·→ IA: explicador + revisor de falso positivo (assíncrono)
          ·→ WhatsApp (resumo agrupado)
Advisor   ·→ OSV.dev × stacks das apps  →  painel + WhatsApp
```

**Onde a IA entra:** a *detecção* é ML + heurística + regra estática — determinística e em <30 ms, no caminho da requisição. A *LLM* é camada **assíncrona**: explica, revisa falso positivo e responde o chat — **nunca** decide o bloqueio. É o que mantém latência e previsibilidade.

## 5. Diferenciais

- **"Só o modelo pegou"**: contador na tela com os ataques que a IA/heurística flagrou e a regra estática não — o valor da camada de IA, medido ao vivo.
- **Atualidade**: bloqueia CVEs recentes de PHP — **CVE-2024-4577** (arg injection no PHP-CGI), **CVE-2024-52301** (env do Laravel), **PHP filter chains**, e **OOM-DoS** (CVE-2026-109618) pela borda HTTP, mapeadas a MITRE ATT&CK (T1190, T1059, T1083, T1499).
- **Open source de ponta a ponta**: modelo local + LLM trocável para Ollama/vLLM. Nenhuma dependência de nuvem proprietária.
- **Privacidade por desenho**: senha, token e cookies nunca saem do app; e-mail/CPF/telefone/cartão mascarados antes de ir à LLM; IPs anonimizados no chat; chaves só em env.
- **Da reação à antecipação**: detecta o ataque **e** diz o que corrigir antes do próximo (advisor OSV.dev).

## 6. Como rodar

```bash
cd sentinela
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env
# opcional: treinar o modelo (data/train.csv com colunas value,label)
.venv/bin/python detector/train.py
SENTINELA_API_KEY=troque-esta-chave .venv/bin/python detector/server.py   # http://127.0.0.1:8765/
```

**Demo (menu interativo):** `./demo/demo.sh` — escolha a cena (payloads, PHP 2024, OOM 2026, scan/brute/flood) e veja o painel reagir ao vivo.

## 7. O que está pronto

Detector, API, dashboard, chat de logs, troca de provedor, middleware Laravel, explicador, revisor de falso positivo, advisor de CVEs (OSV.dev), alertas no WhatsApp, cobertura das CVEs 2024 + OOM 2026. **49 testes passando.**

## 8. Limitações honestas

- Sem `data/train.csv` real, a detecção de payload roda **só por regras** — o Macro-F1 do modelo (meta ≥ 0,90) ainda não foi medido.
- O detector de OOM cobre a superfície **HTTP**; o vetor via **socket FPM** (que contorna o nginx) exige um *sidecar* que faça tail do log do FPM — já desenhado, não implementado.
- O advisor consulta o OSV.dev em runtime; depende de rede.

## 9. Próximos passos

Treinar o modelo com dataset real (e medir o F1), o sidecar do log do FPM para o vetor via socket, e um relatório de recomendações priorizado por exposição real (via MCP) a partir do `/api/advisories`.
