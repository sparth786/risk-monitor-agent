# Part 4: Written Answers

## 1. Shipping a prompt change without breaking existing users. What does versioning look like?

There are two independent version axes, and each response reports both
(`agent_version` and `prompt_version`). A logged `prompt_fingerprint` hash ties each
request to the exact prompt text.

| Axis | What it is | Where |
|---|---|---|
| **Prompt version** | Immutable files `app/prompts/v1.md`, `v2.md`, ... A change is a *new file*, never an edit. | `app/prompts/` |
| **Agent/runtime version** | Every deploy (new image or new env config) creates a new **immutable AgentCore runtime version**. Endpoints `staging` and `prod` are movable pointers to a version. | `scripts/agentcore_deploy.py` |

Rollout steps:
1. **Add `v2.md` alongside `v1.md`.** Every tenant stays pinned to its current
   `prompt_version` in tenant config, so deploying the new code changes nothing for them.
2. **CI gates.** Unit tests check that every prompt version loads and keeps its required
   safety rules. The golden-set eval (`evals/golden.json`) measures precision and recall;
   any change that adds false positives or misses fraud fails the build.
3. **Staging.** The new runtime version goes to the `staging` endpoint, and the golden eval
   runs again against real Bedrock. Prod moves only after that passes *and* a human approves
   (the GitHub `production` environment).
4. **Canary by tenant.** Add `v2` to one tenant's `allowed_prompt_versions` and send a share of
   its traffic with `"prompt_version": "v2"`, or switch an internal or friendly tenant to `v2`.
   Compare the flag rate, alert volume and analyst dispositions against `v1`.
5. **Promote.** Flip tenants' pins to `v2` one by one. Keep `v1` in the image until no
   tenant uses it.
6. **Contract stability.** The response schema is additive-only. A breaking API change would
   ship as a new major version on a separate endpoint, never in place.

## 2. The new version starts producing false positives. How do you roll back quickly?

Pick the lever that matches where the problem is. All of them take seconds to minutes and
none needs a rebuild:

- **Prompt-level (affects only the canary tenants):** set the tenant's `prompt_version` back
  to `v1` in the tenant config (Secrets Manager). This is a config update, and the old prompt
  is still in the image.
- **Runtime-level (a bad image, model, or config):** run the `rollback` workflow (one click) or
  `python scripts/agentcore_deploy.py rollback --runtime-name risk_monitor --endpoint prod`.
  It moves the `prod` endpoint back to the previous immutable version, which is recorded on the
  endpoint at promotion time. The old version is still provisioned, so the switch is near
  instant, and clients keep calling the same ARN with `qualifier=prod`.
- **Automatic:** the prod post-promotion smoke test triggers the same rollback on failure. In
  production I would also add a CloudWatch alarm on flag rate or alert volume per tenant against
  its baseline, which pages on-call or triggers the rollback workflow.

Afterwards: add the false-positive cases to `evals/golden.json` so the regression can't ship
again, then fix forward with `v3`. Webhook alerts carry `prompt_version` and `agent_version`,
so the risk team can bulk-dismiss alerts raised by the bad version.

## 3. Two customers use this agent. How do you keep their data, webhook URLs, and results completely separate?

**Identity is authenticated, never self-declared.** In production, AgentCore's inbound JWT
authorizer (Cognito or another IdP, with one app client per customer) validates the token.
The container reads the tenant from the token's `tenant_id` claim. A payload `tenant_id` that
disagrees is rejected with 403, and `REQUIRE_JWT_TENANT=true` makes the token mandatory.

**Destinations and secrets are server-side only.**
- Webhook URLs and HMAC secrets live in the tenant registry (Secrets Manager). The request
  schema forbids extra fields, so a caller can't supply `webhook_url`.
- The LLM never sees the URL or secret. Its `notify_risk_team` tool is built per request and
  bound to that tenant, so it can only choose *which of this batch's* transactions to report.
  IDs outside the batch are ignored.
- Each tenant has its own signing secret, so a receiver can verify an alert really is theirs.
  Delivery blocks private and metadata IPs (SSRF) and does not follow redirects.

**Compute and memory isolation.**
- Each AgentCore session runs in its own isolated microVM. Callers use a fresh
  `runtimeSessionId` per request (or per tenant), never shared across tenants.
- A new Strands `Agent` is created for every request, with no conversation history or memory
  carried over. Signals are computed only from the request's own batch, with no cross-request
  caches.

**Results and observability.** Responses go back only to the caller. Every log line, webhook
and response is tagged with `tenant_id` and `request_id`. If results were persisted, they
would go in a store partitioned by tenant (for example, a DynamoDB partition key of
`tenant_id` with IAM `dynamodb:LeadingKeys` conditions, or an S3 prefix per tenant with a KMS
key per tenant).

**For stricter customers (silo model):** deploy a dedicated AgentCore runtime per tenant from
the same image and pipeline, with its own execution role, secret and KMS key, or even a
separate AWS account. The code doesn't change, because tenant selection is pure configuration.

Tests in `tests/test_api.py` prove that each tenant's alerts go only to its own webhook, signed
with its own secret, and that payload attempts to redirect webhooks or impersonate tenants are
rejected.
