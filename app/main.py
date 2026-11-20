"""AgentCore Runtime entrypoint.

`BedrockAgentCoreApp` serves the AgentCore HTTP contract on port 8080:
  POST /invocations   -> `invoke` below
  GET  /ping          -> health check
The same container runs locally (docker-compose) and on AgentCore Runtime.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import uuid
from dataclasses import dataclass

from bedrock_agentcore.runtime import BedrockAgentCoreApp
from pydantic import ValidationError
from starlette.responses import JSONResponse

from app.agent import MockAnalyzer, PromptVersionNotAllowedError, RiskMonitor, StrandsBedrockAnalyzer
from app.config import Settings
from app.models import AnalyzeRequest
from app.prompts import UnknownPromptVersionError
from app.tenants import TenantRegistry, UnknownTenantError
from app.webhook import WebhookClient

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("risk_monitor")


@dataclass
class Service:
    settings: Settings
    tenants: TenantRegistry
    monitor: RiskMonitor


def build_service(settings: Settings | None = None) -> Service:
    settings = settings or Settings.from_env()
    if settings.llm_provider == "mock":
        analyzer = MockAnalyzer()
    elif settings.llm_provider == "bedrock":
        analyzer = StrandsBedrockAnalyzer(
            settings.model_id, settings.aws_region, settings.max_tokens, temperature=settings.temperature
        )
    else:
        raise ValueError(f"unknown LLM_PROVIDER '{settings.llm_provider}'")
    webhook = WebhookClient(
        timeout=settings.webhook_timeout_seconds,
        max_attempts=settings.webhook_max_attempts,
        allow_insecure=settings.allow_insecure_webhooks,
        allow_private=settings.allow_private_webhooks,
    )
    monitor = RiskMonitor(
        analyzer,
        webhook,
        agent_version=settings.agent_version,
        default_prompt_version=settings.default_prompt_version,
        rules_fallback_on_error=settings.rules_fallback_on_llm_error,
    )
    return Service(settings=settings, tenants=settings.load_tenants(), monitor=monitor)


_service: Service | None = None


def get_service() -> Service:
    global _service
    if _service is None:
        _service = build_service()
    return _service


def set_service(service: Service | None) -> None:
    """Test hook."""
    global _service
    _service = service


class TenantAuthError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _jwt_claims(headers: dict[str, str]) -> dict | None:
    """Read claims from the forwarded bearer token.

    Signature verification is done by AgentCore's inbound JWT authorizer before the request
    reaches the container, so here we only decode the payload segment.
    """
    auth = next((v for k, v in headers.items() if k.lower() == "authorization"), "")
    if not auth.lower().startswith("bearer "):
        return None
    try:
        segment = auth.split()[1].split(".")[1]
        return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except (IndexError, ValueError):
        raise TenantAuthError(401, "malformed bearer token") from None


def resolve_tenant_id(payload_tenant: str | None, headers: dict[str, str], settings: Settings) -> str:
    claims = _jwt_claims(headers)
    token_tenant = claims.get(settings.tenant_jwt_claim) if claims else None
    if token_tenant:
        if payload_tenant and payload_tenant != token_tenant:
            raise TenantAuthError(403, "tenant_id does not match the authenticated tenant")
        return str(token_tenant)
    if settings.require_jwt_tenant:
        raise TenantAuthError(401, "authenticated tenant required")
    if not payload_tenant:
        raise TenantAuthError(400, "tenant_id is required")
    return payload_tenant


def _error(status: int, message: str, request_id: str, details=None) -> JSONResponse:
    body = {"error": message, "request_id": request_id}
    if details is not None:
        body["details"] = details
    return JSONResponse(body, status_code=status)


def handle(payload: dict, headers: dict[str, str] | None = None, session_id: str | None = None):
    request_id = str(uuid.uuid4())
    service = get_service()
    if not isinstance(payload, dict):
        return _error(400, "payload must be a JSON object", request_id)
    try:
        request = AnalyzeRequest.model_validate(payload)
    except ValidationError as exc:
        return _error(422, "invalid request", request_id, json.loads(exc.json(include_url=False, include_input=False)))
    try:
        tenant_id = resolve_tenant_id(request.tenant_id, headers or {}, service.settings)
        tenant = service.tenants.get(tenant_id)
    except TenantAuthError as exc:
        return _error(exc.status, str(exc), request_id)
    except UnknownTenantError:
        return _error(404, "unknown tenant", request_id)
    try:
        response = service.monitor.run(request, tenant, request_id)
    except (PromptVersionNotAllowedError, UnknownPromptVersionError) as exc:
        return _error(400, f"prompt version not available: {exc}", request_id)
    logger.info(
        "done tenant=%s request=%s session=%s flagged=%d notifications=%d",
        tenant.tenant_id,
        request_id,
        session_id,
        response.flagged_count,
        len(response.notifications),
    )
    return response.model_dump(mode="json")


app = BedrockAgentCoreApp()


@app.entrypoint
def invoke(payload, context):
    return handle(payload, getattr(context, "request_headers", None) or {}, getattr(context, "session_id", None))


if __name__ == "__main__":
    app.run(port=int(os.getenv("PORT", "8080")), host=os.getenv("HOST") or None)
