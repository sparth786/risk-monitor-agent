# Risk Monitor Agent: Strands + Amazon Bedrock + AgentCore Runtime

An AI agent that takes a batch of transactions, uses an LLM on Amazon Bedrock to decide which
ones look suspicious, calls a webhook to notify the risk team, and returns a summary. It is
packaged as an ARM64 container for **Amazon Bedrock AgentCore Runtime**, and the same image
runs locally with Docker Compose.

The answers to the written questions are in **[ANSWERS.md](ANSWERS.md)**.

```
           POST /invocations  {tenant_id, transactions[]}
                    |
          +---------v----------+   tenant config (Secrets Manager / file):
          |  app/main.py       |   webhook URL, HMAC secret, prompt pin, thresholds
          |  validate, resolve |<-- tenant from JWT claim (AgentCore authorizer)
          |  tenant            |
          +---------+----------+
                    |
          +---------v----------+   deterministic signals: amount outlier vs. customer
          |  app/signals.py    |   median, velocity, odd hour, risky merchant, duplicates
          +---------+----------+
                    |
          +---------v-------------------------------+
          |  Strands Agent  (app/agent.py)          |
          |  BedrockModel + system prompt vN        |---- tool: notify_risk_team(ids, severity, reason)
          |  structured output -> RiskAssessment    |          bound to THIS tenant's webhook
          +---------+-------------------------------+                  |
                    |  safety net: severe findings the LLM didn't       v
                    |  alert on are sent anyway (app/agent.py)   signed POST (HMAC-SHA256,
                    v                                           retries, SSRF guard)
          { findings[], notifications[], summary, prompt_version, agent_version, ... }
```

## How it works

- **The LLM reasons; code guarantees.** Deterministic signals are added to the prompt as hints.
  The LLM (Amazon Nova Pro by default, or any Bedrock model with tool use, via Strands' `BedrockModel`) decides what is suspicious, calls
  `notify_risk_team`, and returns a typed `RiskAssessment`. Code then drops any IDs the model
  made up, removes duplicate alerts, and sends any severe finding the model forgot to alert on.
- **It degrades instead of failing.** If Bedrock errors (throttling or an outage), the request
  falls back to the rules-only assessment (`analysis_mode: "rules_fallback"`), so alerts still
  go out.
- **Versioned prompts.** `app/prompts/v1.md` and `v2.md` are immutable, and each tenant is pinned
  to one. See ANSWERS.md §1.
- **Tenant isolation.** Webhook URLs and secrets are server-side only. The tool is bound to the
  request's tenant, and the tenant comes from the JWT claim. See ANSWERS.md §3.
- **Webhooks.** HMAC-SHA256 signature (`X-Risk-Signature` over `"{timestamp}.{body}"`), an
  idempotency key that stays the same across retries, exponential backoff on 5xx/429, no
  redirects, and private/metadata IPs blocked.

## Repository layout

| Path | Purpose |
|---|---|
| `app/main.py` | AgentCore entrypoint (`BedrockAgentCoreApp`: `POST /invocations`, `GET /ping` on :8080) |
| `app/agent.py` | `RiskMonitor` orchestration, `StrandsBedrockAnalyzer` (real LLM), `MockAnalyzer` (offline) |
| `app/tools.py` | `notify_risk_team` Strands tool, bound to the tenant for each request |
| `app/webhook.py` | Signed, retrying, SSRF-safe webhook client |
| `app/signals.py` | Deterministic pre-screen and rules fallback |
| `app/prompts/` | Versioned system prompts |
| `app/tenants.py`, `app/config.py` | Tenant registry (file / env / Secrets Manager), env-driven settings |
| `config/tenants.example.json` | Two demo tenants (`acme`, `globex`) |
| `mock_webhook/server.py` | Local webhook receiver that verifies signatures (docker-compose) |
| `receiver/lambda_function.py` | Risk-team webhook receiver on AWS Lambda (function URL): verifies each tenant's HMAC, rejects replays |
| `scripts/agentcore_deploy.py` | Deploy / promote / rollback / status on AgentCore (boto3) |
| `scripts/evaluate.py`, `evals/golden.json` | Golden-set eval and smoke test with precision/recall gate |
| `.github/workflows/ci-cd.yml`, `rollback.yml` | CI/CD pipeline and one-click rollback |
| `infra/iam/` | IAM policy templates (AgentCore execution role, GitHub OIDC deploy role) |
| `tests/` | 79 tests (unit, real Strands loop with a scripted model, HTTP, isolation, deploy tooling) |

## Local setup

Requirements: Python 3.12+ and Docker with Compose.

```bash
make install            # creates .venv and installs requirements-dev.txt
make lint test          # ruff + pytest (no AWS needed)
make eval               # golden-set eval in-process with the mock LLM
```

### Run with Docker Compose

```bash
mkdir -p ~/.aws                       # compose mounts it; if missing, Docker creates it owned by root
docker compose up --build -d          # offline: LLM_PROVIDER=mock (rules engine stands in for the LLM)
curl -s -X POST localhost:8080/invocations \
  -H 'Content-Type: application/json' -d @scripts/sample_transactions.json | python3 -m json.tool
docker compose logs mock-webhook       # shows the signed alert the webhook received
python3 scripts/evaluate.py --target http://localhost:8080
docker compose down
```

To use **real Bedrock** locally, your AWS credentials in `~/.aws` must have Bedrock model
access:

```bash
LLM_PROVIDER=bedrock AWS_PROFILE=default AWS_REGION=us-east-1 \
BEDROCK_MODEL_ID=us.amazon.nova-pro-v1:0 docker compose up --build -d
```

> Check the exact model / inference-profile ID in the Bedrock console (Model catalog, or
> Cross-region inference) for your region, and set it through `BEDROCK_MODEL_ID`.

## API

`POST /invocations`. On AgentCore, call it with
`bedrock-agentcore:InvokeAgentRuntime(agentRuntimeArn, qualifier="prod", payload=...)`.

```json
{
  "tenant_id": "acme",
  "transactions": [
    {"transaction_id": "t-004", "amount": 9500.0, "merchant": "CryptoXchange Ltd",
     "timestamp": "2026-11-20T03:14:00Z", "customer_id": "cust-17", "currency": "USD"}
  ],
  "prompt_version": "v2",
  "dry_run": false
}
```

`transaction_id` and `currency` are optional. `prompt_version` is optional and only accepted
if it is enabled for that tenant. `dry_run` analyses without calling the webhook.

Response:

```json
{
  "request_id": "...", "tenant_id": "acme", "agent_version": "<git sha>",
  "prompt_version": "v1", "model_id": "us.amazon.nova-pro-v1:0", "analysis_mode": "llm",
  "transactions_analyzed": 9, "flagged_count": 2,
  "findings": [{"transaction_id": "t-004", "customer_id": "cust-17", "risk_score": 92,
                "severity": "critical", "reasons": ["..."]}],
  "notifications": [{"transaction_ids": ["t-004"], "severity": "critical", "source": "agent_tool",
                     "status": "sent", "attempts": 1, "http_status": 200, "error": null}],
  "summary": "..."
}
```

Errors return `{error, request_id, details?}` with a status: 400 (missing tenant or bad prompt
version), 401/403 (authentication or tenant mismatch), 404 (unknown tenant), 422 (validation).

Webhook event sent to the tenant's URL:

```json
{"event_type": "risk.detected", "tenant_id": "acme", "request_id": "...", "severity": "critical",
 "reason": "...", "transactions": [...], "agent_version": "...", "prompt_version": "v1", "detected_at": "..."}
```

The headers are `X-Risk-Signature: sha256=<hmac>`, `X-Risk-Timestamp`, `X-Idempotency-Key` and
`X-Tenant-Id`. Receivers verify the signature with `app.webhook.verify`.

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `LLM_PROVIDER` | `bedrock` | `bedrock` or `mock` (offline) |
| `BEDROCK_MODEL_ID` | `us.amazon.nova-pro-v1:0` | Bedrock model / inference profile (any Converse model with tool use) |
| `MAX_TOKENS` | `4096` | Max output tokens (Nova Pro's limit is lower than Claude's) |
| `TEMPERATURE` | unset | Set `0` for Nova; leave unset for Claude (it rejects sampling params) |
| `AWS_REGION` | `us-east-1` | Bedrock region |
| `AGENT_VERSION` | `dev` | Set to the git SHA at build time |
| `DEFAULT_PROMPT_VERSION` | `v1` | Used if a tenant doesn't pin one |
| `TENANTS_SECRET_ID` / `TENANTS_CONFIG_JSON` / `TENANTS_CONFIG_PATH` | example file | Tenant registry source (first one set wins) |
| `REQUIRE_JWT_TENANT`, `TENANT_JWT_CLAIM` | `false`, `tenant_id` | Require the tenant from the JWT claim |
| `WEBHOOK_TIMEOUT_SECONDS`, `WEBHOOK_MAX_ATTEMPTS` | `5`, `3` | Delivery tuning |
| `ALLOW_INSECURE_WEBHOOKS`, `ALLOW_PRIVATE_WEBHOOKS` | `false` | Local-dev only (compose) |
| `RULES_FALLBACK_ON_LLM_ERROR` | `true` | Fall back to rules if Bedrock fails |

## CI/CD: how a change reaches production

`.github/workflows/ci-cd.yml`:

1. **Pull request:** ruff, pytest, golden eval with the mock LLM, and a Docker Compose smoke test
   of the real container.
2. **Push to `main`:**
   - Build a `linux/arm64` image and push it to ECR, tagged with the git SHA, which is also baked
     in as `AGENT_VERSION`.
   - `agentcore_deploy.py deploy` creates a **new immutable runtime version** and points the
     **`staging` endpoint** at it.
   - Run the golden eval against `staging` on **real Bedrock**. If precision or recall falls below
     0.9, the pipeline stops. If the model is unreachable and the agent falls back to its rules, the
     run gets a ⚠️ "LLM not used" warning but is not failed. To make that case fatal too, set the
     repo variable `EVAL_REQUIRE_MODE=llm`, so prod can only receive versions the LLM has been
     evaluated on.
   - **Manual approval:** the GitHub environment `production` has required reviewers.
   - `promote` moves the **`prod` endpoint** to the exact version tested in staging, then runs a
     prod smoke test (dry run). If the smoke test fails, the pipeline rolls back automatically.
3. **`rollback.yml`:** a one-click workflow that moves `prod` back to the previous version,
   or to one you choose.

**Example: a prompt update.** Add `app/prompts/v3.md`, then set a tenant's `prompt_version` (or
`allowed_prompt_versions` for a canary) in the tenant config and push. The tests check the new
prompt. The new image becomes runtime version N+1 on `staging`, and the eval runs against real
Bedrock. After approval, `prod` moves to N+1. Clients keep calling the same ARN with
`qualifier=prod`.

**Example: a config change** (model ID, thresholds, default prompt). Change the repository
variable or the `--env` value in the deploy step and push, or re-run the workflow. It follows
the same path and produces a new runtime version, so it can be rolled back the same way.

Required GitHub repository variables: `AWS_REGION`, `AWS_DEPLOY_ROLE_ARN`, `ECR_REPOSITORY`,
`AGENTCORE_RUNTIME_NAME`, `AGENTCORE_EXECUTION_ROLE_ARN`, `BEDROCK_MODEL_ID`,
`TENANTS_SECRET_ID`. Also create the GitHub environments `staging` and `production` (with
required reviewers on `production`).

## Webhook receiver on AWS

`receiver/lambda_function.py` plays the customers' risk-team endpoint in AWS. It runs as a
Lambda function behind a public HTTPS function URL:

- `POST /hooks/{tenant_id}` verifies `X-Risk-Signature` with **that tenant's** secret, read from the
  same `risk-monitor/tenants` secret the agent uses. It rejects tampered bodies, the wrong
  tenant's secret, cross-tenant payloads and timestamps older than 5 minutes (replays), and
  logs each accepted alert as one JSON line to CloudWatch (`/aws/lambda/risk-monitor-webhook-receiver`).
- `GET /health` returns `{"ok": true}`.
- IAM: `infra/iam/receiver-role-*.json` plus the AWS-managed `AWSLambdaBasicExecutionRole`.

Each tenant's `webhook_url` in the tenant secret is `https://<function-url>/hooks/<tenant_id>`.

- **Sizing.** Give the function 512 MB, which also buys it more CPU. At 128 MB a cold start (loading
  boto3 plus fetching the secret) took about 5.7 s, which is past the agent's 5 s webhook timeout, so the
  agent retried. At 512 MB a cold start takes about 1.3 s and a warm call about 2 ms.
- **Delivery is at least once.** A timeout or a 5xx triggers a retry, so the same alert can arrive more
  than once. Every attempt carries the same `X-Idempotency-Key`, which is `{request_id}:{sorted txn ids}`.
  A production consumer should de-duplicate on that key, for example with a DynamoDB conditional put.
  This demo receiver only logs it.

## Deploying to AWS

The deployment tooling is ready: `scripts/agentcore_deploy.py`, the IAM templates in
`infra/iam/`, and the pipeline. In short: create an ECR repo, the AgentCore execution role,
the tenants secret and a GitHub OIDC role. Then push the image and run
`agentcore_deploy.py deploy`. A full step-by-step guide is provided separately.

> **OIDC `sub` format.** GitHub may issue `sub` claims that carry immutable IDs, in the form
> `repo:OWNER@OWNER_ID/REPO@REPO_ID:ref:refs/heads/main`. The trust template accepts both
> this form and the legacy `repo:OWNER/REPO:...` form. If `configure-aws-credentials` fails
> with "Not authorized to perform sts:AssumeRoleWithWebIdentity", look up the failed
> `AssumeRoleWithWebIdentity` event in CloudTrail. Its `userIdentity.userName` is the exact
> `sub` that GitHub sent.

## Tests

```bash
make test   # 79 tests, ~1s, no network/AWS
```

The tests cover:
- the real Strands agent loop, driven by a scripted model: a tool call followed by structured
  output, rejection of IDs the model made up, and the safety-net alert
- the webhook: signature, retries and backoff, no retry on 4xx, SSRF blocking
- orchestration: deduplication, dry run, failed delivery, the Bedrock-failure fallback, and
  prompt-version pinning and canaries
- the HTTP contract and error codes
- tenant isolation: separate URLs and secrets, payload injection, JWT tenant mismatch
- the deploy/promote/rollback flow, against a fake AgentCore control plane
- the golden eval
