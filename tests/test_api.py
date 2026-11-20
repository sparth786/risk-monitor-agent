"""HTTP contract (AgentCore: POST /invocations, GET /ping) and tenant isolation."""

import base64
import json

import pytest
from starlette.testclient import TestClient

from app import main
from app.agent import MockAnalyzer, RiskMonitor
from app.config import Settings
from app.tenants import TenantRegistry


def jwt(claims: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.sig"


@pytest.fixture
def api(registry, webhook, recorder):
    def make(**settings_kw):
        settings = Settings(llm_provider="mock", **settings_kw)
        monitor = RiskMonitor(MockAnalyzer(), webhook, agent_version="sha-test", default_prompt_version="v1")
        main.set_service(main.Service(settings=settings, tenants=registry, monitor=monitor))
        return TestClient(main.app)

    yield make
    main.set_service(None)


def test_ping(api):
    assert api().get("/ping").status_code == 200


def test_invocation_returns_summary(api, sample_payload, recorder):
    resp = api().post("/invocations", json=sample_payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tenant_id"] == "acme" and body["transactions_analyzed"] == 9
    assert body["flagged_count"] == len(body["findings"]) > 0
    assert body["prompt_version"] == "v1" and body["agent_version"] == "sha-test"
    assert body["summary"]
    assert recorder.requests[0].url.host == "hooks.acme.example"


@pytest.mark.parametrize(
    "payload,status",
    [
        ({"tenant_id": "acme", "transactions": []}, 422),
        ({"tenant_id": "acme", "transactions": [{"amount": "lots"}]}, 422),
        ({"transactions": [{"amount": 1, "merchant": "m", "timestamp": "2026-01-01T00:00:00Z", "customer_id": "c"}]}, 400),
        (
            {
                "tenant_id": "nobody",
                "transactions": [{"amount": 1, "merchant": "m", "timestamp": "2026-01-01T00:00:00Z", "customer_id": "c"}],
            },
            404,
        ),
        (
            {
                "tenant_id": "acme",
                "prompt_version": "v99",
                "transactions": [{"amount": 1, "merchant": "m", "timestamp": "2026-01-01T00:00:00Z", "customer_id": "c"}],
            },
            400,
        ),
    ],
)
def test_bad_requests(api, payload, status):
    resp = api().post("/invocations", json=payload)
    assert resp.status_code == status, resp.text
    assert "request_id" in resp.json()


def test_payload_cannot_override_webhook_url(api, sample_payload, recorder):
    sample_payload["webhook_url"] = "https://attacker.example/steal"
    assert api().post("/invocations", json=sample_payload).status_code == 422
    assert recorder.requests == []


# --- tenant isolation --------------------------------------------------------
def test_each_tenant_alerts_only_its_own_webhook_with_its_own_secret(api, sample_payload, recorder, registry):
    client = api()
    client.post("/invocations", json=sample_payload)
    client.post("/invocations", json={**sample_payload, "tenant_id": "globex"})
    by_host = {}
    for req in recorder.requests:
        by_host.setdefault(req.url.host, []).append(req)
    assert set(by_host) == {"hooks.acme.example", "alerts.globex.example"}
    from app.webhook import verify

    for host, tenant_id in [("hooks.acme.example", "acme"), ("alerts.globex.example", "globex")]:
        secret = registry.get(tenant_id).webhook_secret.get_secret_value()
        other = registry.get("globex" if tenant_id == "acme" else "acme").webhook_secret.get_secret_value()
        for req in by_host[host]:
            body = json.loads(req.content)
            assert body["tenant_id"] == tenant_id and req.headers["X-Tenant-Id"] == tenant_id
            ts, sig = req.headers["X-Risk-Timestamp"], req.headers["X-Risk-Signature"]
            assert verify(secret, ts, req.content, sig) and not verify(other, ts, req.content, sig)


def test_tenant_policies_differ(api, sample_payload):
    client = api()
    acme = client.post("/invocations", json=sample_payload).json()
    globex = client.post("/invocations", json={**sample_payload, "tenant_id": "globex"}).json()
    assert acme["prompt_version"] == "v1" and globex["prompt_version"] == "v2"
    assert acme["request_id"] != globex["request_id"]


def test_jwt_tenant_claim_wins(api, sample_payload):
    client = api()
    payload = {k: v for k, v in sample_payload.items() if k != "tenant_id"}
    resp = client.post("/invocations", json=payload, headers={"Authorization": f"Bearer {jwt({'tenant_id': 'globex'})}"})
    assert resp.status_code == 200 and resp.json()["tenant_id"] == "globex"


def test_jwt_tenant_mismatch_forbidden(api, sample_payload):
    resp = api().post(
        "/invocations", json=sample_payload, headers={"Authorization": f"Bearer {jwt({'tenant_id': 'globex'})}"}
    )
    assert resp.status_code == 403


def test_jwt_required_mode(api, sample_payload):
    resp = api(require_jwt_tenant=True).post("/invocations", json=sample_payload)
    assert resp.status_code == 401


def test_malformed_token(api, sample_payload):
    resp = api().post("/invocations", json=sample_payload, headers={"Authorization": "Bearer nope"})
    assert resp.status_code == 401


# --- config / service wiring -------------------------------------------------
def test_example_tenant_file_loads():
    reg = TenantRegistry.from_file(main.Settings().tenants_config_path)
    assert reg.ids() == ["acme", "globex"]


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "MOCK")
    monkeypatch.setenv("BEDROCK_MODEL_ID", "some-model")
    monkeypatch.setenv("ALLOW_INSECURE_WEBHOOKS", "true")
    monkeypatch.setenv(
        "TENANTS_CONFIG_JSON",
        json.dumps({"tenants": [{"tenant_id": "solo", "webhook_url": "https://x.example", "webhook_secret": "s" * 16}]}),
    )
    s = Settings.from_env()
    assert s.llm_provider == "mock" and s.model_id == "some-model" and s.allow_insecure_webhooks
    assert s.load_tenants().ids() == ["solo"]
    service = main.build_service(s)
    assert isinstance(service.monitor.analyzer, MockAnalyzer)


def test_build_service_bedrock_does_not_call_aws(monkeypatch):
    service = main.build_service(Settings(llm_provider="bedrock", model_id="m", aws_region="us-east-1"))
    assert service.monitor.analyzer.model_id == "m"


def test_unknown_provider():
    with pytest.raises(ValueError):
        main.build_service(Settings(llm_provider="nope"))


@pytest.mark.parametrize(
    "bad",
    [
        {"tenant_id": "Bad Id!"},
        {"webhook_url": "ftp://x"},
        {"webhook_url": "https://user:pw@x.example"},
        {"webhook_secret": "short"},
    ],
)
def test_tenant_config_validation(bad):
    base = {"tenant_id": "ok", "webhook_url": "https://x.example", "webhook_secret": "s" * 16}
    with pytest.raises(ValueError):
        TenantRegistry.from_data({"tenants": [{**base, **bad}]})


def test_duplicate_tenants_rejected():
    t = {"tenant_id": "ok", "webhook_url": "https://x.example", "webhook_secret": "s" * 16}
    with pytest.raises(ValueError):
        TenantRegistry.from_data([t, t])


def test_bedrock_model_config_for_nova(monkeypatch):
    """Nova: temperature 0 is sent; Claude-style config (unset) sends no sampling params."""
    from app.agent import StrandsBedrockAnalyzer

    monkeypatch.setenv("TEMPERATURE", "0")
    monkeypatch.setenv("MAX_TOKENS", "4096")
    s = Settings.from_env()
    assert s.model_id == "us.amazon.nova-pro-v1:0" and s.temperature == 0.0 and s.max_tokens == 4096
    analyzer = main.build_service(s).monitor.analyzer
    cfg = analyzer._build_model().get_config()
    assert cfg["model_id"] == "us.amazon.nova-pro-v1:0" and cfg["temperature"] == 0.0 and cfg["max_tokens"] == 4096

    unset = StrandsBedrockAnalyzer("us.anthropic.claude-x", "us-east-1")._build_model().get_config()
    assert "temperature" not in unset
