# OpenSOC · ai-triage

Python (FastAPI) service that receives **Wazuh** alerts and triages them with a **pluggable
LLM** (Anthropic, OpenAI or local Ollama), backed by **RAG over Markdown runbooks**, and returns
a **structured JSON** verdict: severity, summary, MITRE ATT&CK technique, recommended actions
and confidence.

The agent is designed on the assumption that **alert content is hostile**: prompt injection
defenses, strict output validation, PII redaction before calling the LLM, chained audit log
and token limits. See the [threat model (OWASP Top 10 for LLM
2025)](docs/THREAT_MODEL.md).

```
Wazuh ──▶ custom-ai-triage.py ──HTTP──▶ ai-triage ──▶ LLM (Anthropic | OpenAI | Ollama | mock)
  ▲                                        │  RAG: runbooks/*.md (BM25)
  └──── "ai-triage" event (rule 1009xx) ◀──┘  audit: audit.jsonl (hash chain + HMAC)
```

## Pipeline

1. **Input**: Bearer token, per-client rate limit, size limit, schema validation.
2. **Sanitization**: Unicode normalization (NFKC, no invisible/bidi/control characters), depth and size limits.
3. **Prompt injection detection** on every value and key (incl. base64 and Unicode *tag smuggling*).
4. **PII and secret redaction** with per-request stable pseudonyms (`[IP_EXTERNAL_1]`, `[USER_1]`...).
5. **RAG**: BM25 over runbook sections + boosts for `rule.id`, MITRE and Wazuh groups.
6. **Prompt**: rules in the system prompt, escaped alert JSON inside `<alert_data_{nonce}>`, canary.
7. **LLM** with input/output token limits, global budget, concurrency and timeout.
8. **Output validation**: single JSON object, strict schema, URLs/HTML/dangerous actions removed, grounding.
9. **Deterministic guardrails**: severity floor relative to Wazuh, mandatory human review when appropriate.
10. **Local re-hydration** of PII (optional) and **audit logging**.

If the LLM fails, the budget runs out, or the LLM returns garbage or leaks its prompt, a
**deterministic triage** based on the Wazuh rule and the retrieved runbook is applied: no alert is lost.

## Quick start

### Local (no LLM, `mock` provider)

```bash
cd ai-triage
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
export TRIAGE_API_TOKEN=$(openssl rand -hex 32)
python -m ai_triage            # listens on :8000
```

```bash
curl -s -X POST http://localhost:8000/v1/triage \
  -H "Authorization: Bearer $TRIAGE_API_TOKEN" -H 'Content-Type: application/json' \
  --data @tests/data/ssh_bruteforce.json | jq
```

### Docker

```bash
docker build -t opensoc/ai-triage:0.1.0 .
```

```bash
docker run --rm -p 8000:8000 --read-only --tmpfs /tmp --cap-drop ALL \
  -v ai-triage-audit:/var/log/ai-triage --env-file .env opensoc/ai-triage:0.1.0
```

Behind a TLS-inspecting proxy, pass its CA as a build secret (it does not end up in the image):
`docker build --secret id=pip_ca,src=/path/ca.crt .`. To pin the base image by digest:
`--build-arg PYTHON_IMAGE=python:3.13-slim@sha256:<digest>`.

### Integration into `/infra` (Docker Compose)

`compose.yaml` is a fragment ready to be included from the `/infra` project
(Compose ≥ 2.20):

```yaml
# infra/docker-compose.yml
include:
  - path: ../ai-triage/compose.yaml

services:
  wazuh.manager:
    # ...
    networks: [opensoc]   # to reach http://ai-triage:8000
```

Create `ai-triage/.env` from `.env.example` (the service **does not start** without
`TRIAGE_API_TOKEN`). The service publishes no ports on the host and runs as an unprivileged
user with a read-only filesystem, no capabilities and limited memory/CPU. Optional Ollama:
`docker compose --profile ollama up -d`.

## Wazuh integration

On the manager:

1. Copy `integrations/wazuh/custom-ai-triage.py` to `/var/ossec/integrations/`
   (`chown root:wazuh`, `chmod 750`).
2. Add the block from `integrations/wazuh/ossec-integration.xml` to `ossec.conf`
   (with `<api_key>` = `TRIAGE_API_TOKEN`; `<level>` controls which alerts are triaged, and the cost).
3. Copy `integrations/wazuh/ai_triage_rules.xml` to `/var/ossec/etc/rules/` and restart the manager.

The script sends the alert to the service and injects the verdict back into Wazuh as a JSON event
(`integration: ai-triage`), which rules 100900–100905 turn into alerts visible in the
dashboard (level according to severity; 100905 = prompt injection attempt). It includes a *loop guard*:
events of the `ai_triage` group are never forwarded again (and the service rejects them with 409).

## API

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/triage` | Body: Wazuh alert (JSON). Auth: `Authorization: Bearer <token>` or `X-API-Key`. |
| `GET` | `/healthz` | Liveness. |
| `GET` | `/readyz` | Provider and loaded/rejected runbooks. |

Response (abridged example):

```json
{
  "request_id": "4571105c690c42aebb7b966e6c6f93bb",
  "alert_id": "1762247564.4471",
  "rule_id": "5712",
  "triage": {
    "severity": "high",
    "summary": "SSH brute force from 185.220.101.47 against user deploy on web-prod-01.",
    "mitre": {"technique_id": "T1110.001", "technique_name": "Password Guessing", "tactic": "Credential Access"},
    "recommended_actions": [
      {"step": "Check whether there was a successful logon (rule 5715) from the source IP.", "runbook_id": "ssh-brute-force"},
      {"step": "Block the source IP on the perimeter firewall.", "runbook_id": "ssh-brute-force"}
    ],
    "confidence": 0.85
  },
  "analysis": {
    "engine": "llm",
    "provider": "anthropic",
    "model": "<configured model>",
    "baseline_severity": "medium",
    "requires_human_review": false,
    "guardrails": [],
    "prompt_injection": {"suspected": false, "score": 0, "indicators": []},
    "pii": {"redacted": {"IP_EXTERNAL": 1, "IP_INTERNAL": 1, "USER": 1}, "rehydrated": true},
    "runbooks": ["ssh-brute-force"],
    "alert_truncated": false,
    "fallback_reason": null,
    "attempts": 1,
    "usage": {"input_tokens": 1830, "output_tokens": 240, "estimated_prompt_tokens": 1926},
    "latency_ms": 2310
  }
}
```

`triage` always has exactly the five fields of the contract. `analysis` explains how it was
obtained: engine (`llm` or `fallback` and its reason), guardrails applied, injection suspicion
(only rule names and field paths, never the text), count of redacted PII and token usage.

## Configuration

Environment variables (`TRIAGE_` prefix; see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `TRIAGE_LLM_PROVIDER` | `mock` | `anthropic`, `openai`, `ollama` or `mock` (heuristic, no network). |
| `TRIAGE_LLM_MODEL` | — | Exact model identifier. Required except for `mock`. |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | — | Key for the chosen provider. |
| `TRIAGE_LLM_BASE_URL` | per provider | Alternative endpoint (Ollama, OpenAI-compatible server, proxy). |
| `TRIAGE_LLM_TEMPERATURE` | `0.0` | `none` to not send it (models that do not accept it). |
| `TRIAGE_LLM_MAX_INPUT_TOKENS` / `_MAX_OUTPUT_TOKENS` | `6000` / `1024` | Per-call limits. |
| `TRIAGE_LLM_TIMEOUT_S` / `_MAX_RETRIES` / `_MAX_CONCURRENCY` | `30` / `1` / `4` | Robustness and concurrency. |
| `TRIAGE_TOKEN_BUDGET_PER_MINUTE` | `150000` | Global budget; once exhausted, deterministic triage. |
| `TRIAGE_RATE_LIMIT_PER_MINUTE` | `120` | Requests per client (HTTP 429). |
| `TRIAGE_MAX_BODY_BYTES` | `262144` | Maximum alert size (HTTP 413). |
| `TRIAGE_API_TOKEN` | — | Inbound token (≥ 16 characters). Required. |
| `TRIAGE_ALLOW_UNAUTHENTICATED` | `false` | Development only. |
| `TRIAGE_ENABLE_DOCS` | `false` | Exposes `/docs` and `/openapi.json`. |
| `TRIAGE_RUNBOOKS_DIR` | `./runbooks` | Runbook directory (read-only). |
| `TRIAGE_RAG_TOP_K` / `_MAX_CONTEXT_TOKENS` | `3` / `2000` | Maximum runbooks and context tokens. |
| `TRIAGE_AUDIT_LOG_PATH` | `-` (stdout) | In the image: `/var/log/ai-triage/audit.jsonl`. |
| `TRIAGE_AUDIT_HMAC_KEY` | — | HMAC key for the audit chain (recommended). |
| `TRIAGE_AUDIT_INCLUDE_PROMPTS` | `false` | Stores the (already redacted) user turn in the audit log. |
| `TRIAGE_PII_REDACT_IPS` | `true` | Pseudonymize IPs. |
| `TRIAGE_PII_REHYDRATE_OUTPUT` | `true` | Restore the values locally in the response. |
| `TRIAGE_PII_EXTRA_USER_KEYS` | — | Additional fields to treat as user names (CSV). |
| `TRIAGE_PII_KEEP_USERNAMES` | `root,admin,...` | System accounts that are not pseudonymized. |
| `TRIAGE_INJECTION_POLICY` | `flag` | `flag` (harden) or `block` (do not send to the LLM). |
| `TRIAGE_INJECTION_THRESHOLD` | `3` | Score from which an injection is suspected. |
| `TRIAGE_SEVERITY_MAX_DOWNGRADE` | `1` | Levels the LLM may lower relative to Wazuh. |
| `TRIAGE_URL_ALLOWLIST` | `attack.mitre.org,documentation.wazuh.com` | Domains allowed in the output. |
| `TRIAGE_OUTPUT_LANGUAGE` | `en` | Language of the summary and actions (e.g. `es` for Spanish; the deterministic fallback texts exist in `en` and `es`). |

### Providers

All of them implement `LLMProvider.complete(LLMRequest) -> LLMResponse`
(`src/ai_triage/llm/base.py`). Adding one = one class + one branch in `llm/factory.py`.

| Provider | Endpoint | Notes |
|---|---|---|
| `anthropic` | Messages API (`/v1/messages`) | `stop_reason=max_tokens` → invalid output; `refusal` → fallback. |
| `openai` | Chat Completions (`/chat/completions`) | JSON mode; `TRIAGE_LLM_BASE_URL` for compatible servers (vLLM, LM Studio). |
| `ollama` | `/api/chat` | Decoding constrained by JSON Schema; `num_ctx` sized so the system prompt is never truncated. |
| `mock` | — | Simulated LLM: heuristic and deterministic. Used in tests and for offline demos. |

## Runbooks (RAG)

10 sample runbooks in `runbooks/` (SSH brute force, malware, ransomware, PowerShell,
privileged accounts, web attacks, FIM, exfiltration, sudo escalation, log deletion).
Format:

```markdown
---
id: ssh-brute-force                # [a-z0-9-], unique
title: SSH brute force and password spraying
mitre: [T1110, T1110.001]          # validated
tactics: [Credential Access]
wazuh_groups: [sshd, authentication_failures]
wazuh_rules: ["5710", "5712"]
keywords: [ssh, brute force]       # terms used by the Wazuh rules
severity_hint: medium
---
# Title
## Indicators
## Triage            ← response sections: prioritized in the context
## Containment
## Eradication and recovery
## Escalation
## False positives
```

Runbooks are validated, scanned for prompt injection and hashed at startup; invalid or
suspicious ones are rejected (see `/readyz` and the `service_start` audit event). A section that
matches only one query term is ignored unless that term is part of the runbook metadata (title,
keywords, groups), so incidental words do not pull in an unrelated runbook.

## Audit

Every triage produces a JSONL record with: client (token hash), alert/rule ids, hash of
the alert and of the prompt, hashes of the LLM responses, errors, the **redacted** triage and
`analysis`. Records are hash-chained (HMAC when a key is set):

```bash
python -m ai_triage.security.audit verify /var/log/ai-triage/audit.jsonl
```

## Tests

```bash
pip install -e '.[dev]'
pytest
ruff check . && ruff format --check .
```

The suite uses a **simulated LLM** (`MockLLMProvider` / `ScriptedLLM`) that reproduces
valid answers, garbage, truncated outputs, timeouts, provider errors, system prompt leaks
and a "naive" model that obeys the injection. The HTTP adapters are tested with
`httpx.MockTransport` and the Wazuh script against a real uvicorn server.

## Layout

```
ai-triage/
├── src/ai_triage/
│   ├── main.py            # FastAPI app, auth, HTTP limits
│   ├── pipeline.py        # triage orchestration
│   ├── prompts.py         # system prompt, delimiters, token budget
│   ├── fallback.py        # deterministic triage without LLM
│   ├── models.py          # Wazuh alert, output contract, MITRE
│   ├── config.py
│   ├── llm/               # interface + anthropic, openai, ollama, mock
│   ├── rag/               # runbook loading and BM25
│   └── security/          # sanitize, injection, redaction, output_validation, guardrails, limits, audit
├── runbooks/              # 10 sample runbooks
├── integrations/wazuh/    # integratord script, rules and ossec.conf block
├── tests/
├── docs/THREAT_MODEL.md
├── Dockerfile · compose.yaml · requirements.lock · .env.example
```
