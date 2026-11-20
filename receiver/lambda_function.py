"""Risk-team webhook receiver (AWS Lambda + function URL).

Stands in for each customer's risk-team endpoint:
  POST /hooks/{tenant_id}  -> verifies the X-Risk-Signature HMAC with THAT tenant's secret,
                              rejects stale timestamps (replay protection), logs the alert.
  GET  /health             -> {"ok": true}

Per-tenant secrets come from the same Secrets Manager secret the agent uses
(TENANTS_SECRET_ID), so there is a single source of truth. Stdlib + boto3 only (both are
in the Lambda Python runtime), so it deploys as a single file.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

MAX_SKEW_SECONDS = int(os.getenv("MAX_SKEW_SECONDS", "300"))
_secrets_cache: dict[str, str] = {}
_cache_loaded_at = 0.0
CACHE_TTL_SECONDS = 300


def _load_secrets() -> dict[str, str]:
    """{tenant_id: webhook_secret}, cached for a few minutes."""
    global _secrets_cache, _cache_loaded_at
    if _secrets_cache and time.time() - _cache_loaded_at < CACHE_TTL_SECONDS:
        return _secrets_cache
    import boto3

    raw = boto3.client("secretsmanager").get_secret_value(SecretId=os.environ["TENANTS_SECRET_ID"])["SecretString"]
    data = json.loads(raw)
    tenants = data.get("tenants", []) if isinstance(data, dict) else data
    _secrets_cache = {t["tenant_id"]: t["webhook_secret"] for t in tenants}
    _cache_loaded_at = time.time()
    return _secrets_cache


def _response(status: int, body: dict) -> dict:
    return {"statusCode": status, "headers": {"Content-Type": "application/json"}, "body": json.dumps(body)}


def _log(**fields) -> None:
    print(json.dumps(fields, default=str))  # one JSON line per event -> CloudWatch Logs Insights friendly


def verify(secret: str, timestamp: str, body: bytes, signature: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def handler(event: dict, context=None, secrets_loader=_load_secrets, now=time.time) -> dict:
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    parts = [p for p in event.get("rawPath", "/").split("/") if p]

    if method == "GET" and parts == ["health"]:
        return _response(200, {"ok": True})
    if method != "POST" or len(parts) != 2 or parts[0] != "hooks":
        return _response(404, {"error": "not found"})

    tenant_id = parts[1]
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    body = event.get("body") or ""
    raw = base64.b64decode(body) if event.get("isBase64Encoded") else body.encode()
    signature = headers.get("x-risk-signature", "")
    timestamp = headers.get("x-risk-timestamp", "")

    try:
        secret = secrets_loader().get(tenant_id)
    except Exception as exc:  # secret missing / no permission: fail closed, clearly
        _log(result="error", reason="secrets_unavailable", error=f"{type(exc).__name__}: {exc}")
        return _response(503, {"error": "receiver not configured"})
    if secret is None:
        _log(result="rejected", reason="unknown_tenant", tenant_id=tenant_id)
        return _response(404, {"error": "unknown tenant"})
    try:
        skew = abs(now() - int(timestamp))
    except ValueError:
        skew = None
    if skew is None or skew > MAX_SKEW_SECONDS:
        _log(result="rejected", reason="stale_or_missing_timestamp", tenant_id=tenant_id)
        return _response(401, {"error": "stale or missing timestamp"})
    if not verify(secret, timestamp, raw, signature):
        _log(result="rejected", reason="bad_signature", tenant_id=tenant_id)
        return _response(401, {"error": "bad signature"})

    alert = json.loads(raw)
    if alert.get("tenant_id") != tenant_id:  # signed by this tenant but addressed to another: refuse
        _log(result="rejected", reason="tenant_mismatch", tenant_id=tenant_id, claimed=alert.get("tenant_id"))
        return _response(403, {"error": "tenant mismatch"})

    _log(
        result="accepted",
        tenant_id=tenant_id,
        idempotency_key=headers.get("x-idempotency-key"),
        severity=alert.get("severity"),
        transaction_ids=[t.get("transaction_id") for t in alert.get("transactions", [])],
        reason=alert.get("reason"),
        prompt_version=alert.get("prompt_version"),
        agent_version=alert.get("agent_version"),
    )
    return _response(200, {"received": True})
