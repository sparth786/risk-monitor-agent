"""The Lambda receiver must accept exactly what app.webhook sends, and nothing else."""

import base64
import json

import httpx
import pytest

from app.webhook import WebhookClient
from receiver import lambda_function as rx
from tests.conftest import public_resolver

SECRETS = {"acme": "acme-secret-0123456789", "globex": "globex-secret-9876543210"}


def loader():
    return SECRETS


def capture_signed_request(tenant, event_body):
    """Send through the real WebhookClient and capture what hit the wire."""
    captured = {}

    def handler(request):
        captured["request"] = request
        return httpx.Response(200)

    wc = WebhookClient(transport=httpx.MockTransport(handler), resolver=public_resolver, sleep=lambda s: None)
    assert wc.send(tenant, event_body).ok
    return captured["request"]


def to_lambda_event(request, path=None, b64=False):
    body = request.content
    return {
        "rawPath": path or f"/hooks/{request.headers['X-Tenant-Id']}",
        "requestContext": {"http": {"method": "POST"}},
        "headers": dict(request.headers),
        "body": base64.b64encode(body).decode() if b64 else body.decode(),
        "isBase64Encoded": b64,
    }


def call(event, now=None):
    kwargs = {"secrets_loader": loader}
    if now is not None:
        kwargs["now"] = lambda: now
    resp = rx.handler(event, **kwargs)
    return resp["statusCode"], json.loads(resp["body"])


@pytest.mark.parametrize("b64", [False, True])
def test_accepts_genuine_alert(acme, b64, capsys):
    req = capture_signed_request(acme, {"tenant_id": "acme", "severity": "critical", "transactions": []})
    assert call(to_lambda_event(req, b64=b64)) == (200, {"received": True})
    assert '"result": "accepted"' in capsys.readouterr().out


def test_rejects_tampered_body(acme):
    req = capture_signed_request(acme, {"tenant_id": "acme", "severity": "low"})
    event = to_lambda_event(req)
    event["body"] = event["body"].replace("low", "critical")
    assert call(event)[0] == 401


def test_rejects_other_tenants_secret(acme, globex):
    # Signed with globex's secret, delivered to acme's hook -> must fail.
    req = capture_signed_request(globex, {"tenant_id": "globex"})
    assert call(to_lambda_event(req, path="/hooks/acme"))[0] == 401


def test_rejects_cross_tenant_payload(acme):
    req = capture_signed_request(acme, {"tenant_id": "globex"})
    assert call(to_lambda_event(req))[0] == 403


def test_rejects_replay(acme):
    req = capture_signed_request(acme, {"tenant_id": "acme"})
    ts = int(req.headers["X-Risk-Timestamp"])
    assert call(to_lambda_event(req), now=ts + 3600)[0] == 401


def test_missing_secret_fails_closed():
    def broken():
        raise RuntimeError("ResourceNotFoundException")

    event = {"rawPath": "/hooks/acme", "requestContext": {"http": {"method": "POST"}}, "body": "{}"}
    resp = rx.handler(event, secrets_loader=broken)
    assert resp["statusCode"] == 503


def test_unknown_tenant_and_routes():
    assert call({"rawPath": "/hooks/nobody", "requestContext": {"http": {"method": "POST"}}, "body": "{}"})[0] == 404
    assert call({"rawPath": "/health", "requestContext": {"http": {"method": "GET"}}}) == (200, {"ok": True})
    assert call({"rawPath": "/other", "requestContext": {"http": {"method": "GET"}}})[0] == 404
