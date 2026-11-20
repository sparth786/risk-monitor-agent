import httpx
import pytest

from app.tenants import TenantConfig
from app.webhook import WebhookBlockedError, WebhookClient, sign, verify
from tests.conftest import Recorder, public_resolver


def client(recorder, **kw):
    kw.setdefault("resolver", public_resolver)
    return WebhookClient(transport=httpx.MockTransport(recorder), sleep=lambda s: None, **kw)


def test_signature_roundtrip():
    sig = sign("secret", "123", b"{}")
    assert verify("secret", "123", b"{}", sig)
    assert not verify("other", "123", b"{}", sig)
    assert not verify("secret", "124", b"{}", sig)


def test_send_signs_and_sets_headers(acme, recorder):
    result = client(recorder).send(acme, {"hello": "world"}, idempotency_key="k1")
    assert result.ok and result.attempts == 1
    req = recorder.requests[0]
    assert req.headers["X-Tenant-Id"] == "acme"
    assert req.headers["X-Idempotency-Key"] == "k1"
    assert verify("acme-secret-0123456789", req.headers["X-Risk-Timestamp"], req.content, req.headers["X-Risk-Signature"])


def test_retries_on_5xx_then_succeeds(acme):
    rec = Recorder([503, 500, 200])
    result = client(rec, max_attempts=3).send(acme, {}, idempotency_key="same")
    assert result.ok and result.attempts == 3
    assert {r.headers["X-Idempotency-Key"] for r in rec.requests} == {"same"}


def test_no_retry_on_4xx(acme):
    rec = Recorder([400, 200])
    result = client(rec, max_attempts=3).send(acme, {})
    assert not result.ok and result.attempts == 1 and result.status_code == 400


def test_retry_on_connection_error(acme):
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            raise httpx.ConnectError("boom")
        return httpx.Response(200)

    wc = WebhookClient(transport=httpx.MockTransport(handler), resolver=public_resolver, sleep=lambda s: None)
    assert wc.send(acme, {}).ok and len(calls) == 2


def test_gives_up_after_max_attempts(acme):
    rec = Recorder([500, 500, 500])
    result = client(rec, max_attempts=3).send(acme, {})
    assert not result.ok and result.attempts == 3


@pytest.mark.parametrize(
    "url",
    [
        "https://169.254.169.254/latest/meta-data",
        "https://127.0.0.1/hook",
        "https://10.0.0.5/hook",
    ],
)
def test_blocks_private_ip_literals(url, recorder):
    tenant = TenantConfig(tenant_id="evil", webhook_url=url, webhook_secret="x" * 16)
    result = client(recorder).send(tenant, {})
    assert not result.ok and result.error.startswith("blocked")
    assert recorder.requests == []


def test_blocks_hostname_resolving_to_private(recorder):
    tenant = TenantConfig(tenant_id="evil", webhook_url="https://internal.example/hook", webhook_secret="x" * 16)
    wc = client(recorder, resolver=lambda h: ["192.168.1.10"])
    assert not wc.send(tenant, {}).ok
    assert recorder.requests == []


def test_http_requires_opt_in(recorder):
    wc = client(recorder)
    with pytest.raises(WebhookBlockedError):
        wc.check_url("http://hooks.example/x")
    client(recorder, allow_insecure=True).check_url("http://hooks.example/x")


def test_private_allowed_for_local_dev(recorder):
    client(recorder, allow_insecure=True, allow_private=True).check_url("http://127.0.0.1:9000/x")
