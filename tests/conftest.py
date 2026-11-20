from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from app.models import AnalyzeRequest
from app.tenants import TenantConfig, TenantRegistry
from app.webhook import WebhookClient

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def sample_payload() -> dict:
    return json.loads((ROOT / "scripts" / "sample_transactions.json").read_text())


@pytest.fixture
def sample_request(sample_payload) -> AnalyzeRequest:
    return AnalyzeRequest.model_validate(sample_payload)


@pytest.fixture
def acme() -> TenantConfig:
    return TenantConfig(
        tenant_id="acme",
        webhook_url="https://hooks.acme.example/risk",
        webhook_secret="acme-secret-0123456789",
        prompt_version="v1",
        allowed_prompt_versions=["v2"],
        notify_min_severity="high",
    )


@pytest.fixture
def globex() -> TenantConfig:
    return TenantConfig(
        tenant_id="globex",
        webhook_url="https://alerts.globex.example/hook",
        webhook_secret="globex-secret-9876543210",
        prompt_version="v2",
        notify_min_severity="medium",
        high_amount_threshold=2000,
    )


@pytest.fixture
def registry(acme, globex) -> TenantRegistry:
    return TenantRegistry([acme, globex])


class Recorder:
    """httpx MockTransport that records requests and replies with scripted statuses."""

    def __init__(self, statuses: list[int] | None = None):
        self.statuses = list(statuses or [])
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status = self.statuses.pop(0) if self.statuses else 200
        return httpx.Response(status, json={"ok": status < 300})

    def bodies(self) -> list[dict]:
        return [json.loads(r.content) for r in self.requests]


@pytest.fixture
def recorder() -> Recorder:
    return Recorder()


def public_resolver(host: str) -> list[str]:
    return ["93.184.216.34"]


@pytest.fixture
def webhook(recorder) -> WebhookClient:
    return WebhookClient(transport=httpx.MockTransport(recorder), resolver=public_resolver, sleep=lambda s: None)
