"""Runtime settings, read from environment variables (12-factor).

Everything that changes between environments (model, region, tenant source, prompt
default) is an env var set by the deploy pipeline, so a config change is a redeploy of
the same image with different values - no code change needed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from app.tenants import TenantRegistry

ROOT = Path(__file__).resolve().parent.parent


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    llm_provider: str = "bedrock"  # "bedrock" | "mock"
    model_id: str = "us.amazon.nova-pro-v1:0"
    aws_region: str = "us-east-1"
    max_tokens: int = 4096  # Nova Pro output limit is lower than Claude's; raise for other models
    temperature: float | None = None  # set 0 for Nova (greedy = reliable tool calls); leave unset for Claude
    agent_version: str = "dev"
    default_prompt_version: str = "v1"
    # Tenant config source (first one set wins): Secrets Manager -> inline JSON -> file.
    tenants_secret_id: str | None = None
    tenants_config_json: str | None = None
    tenants_config_path: str = str(ROOT / "config" / "tenants.example.json")
    # Tenant identity: when set, tenant comes from this JWT claim (AgentCore validates the JWT).
    tenant_jwt_claim: str = "tenant_id"
    require_jwt_tenant: bool = False
    # Webhook delivery.
    webhook_timeout_seconds: float = 5.0
    webhook_max_attempts: int = 3
    allow_insecure_webhooks: bool = False  # allow http:// (docker-compose only)
    allow_private_webhooks: bool = False  # allow private IPs (docker-compose only)
    # If Bedrock fails, still alert using deterministic rules instead of failing the request.
    rules_fallback_on_llm_error: bool = True
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            llm_provider=os.getenv("LLM_PROVIDER", cls.llm_provider).lower(),
            model_id=os.getenv("BEDROCK_MODEL_ID", cls.model_id),
            aws_region=os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", cls.aws_region)),
            max_tokens=int(os.getenv("MAX_TOKENS", cls.max_tokens)),
            temperature=float(os.environ["TEMPERATURE"]) if os.getenv("TEMPERATURE") else None,
            agent_version=os.getenv("AGENT_VERSION", cls.agent_version),
            default_prompt_version=os.getenv("DEFAULT_PROMPT_VERSION", cls.default_prompt_version),
            tenants_secret_id=os.getenv("TENANTS_SECRET_ID") or None,
            tenants_config_json=os.getenv("TENANTS_CONFIG_JSON") or None,
            tenants_config_path=os.getenv("TENANTS_CONFIG_PATH", cls.tenants_config_path),
            tenant_jwt_claim=os.getenv("TENANT_JWT_CLAIM", cls.tenant_jwt_claim),
            require_jwt_tenant=_bool("REQUIRE_JWT_TENANT", cls.require_jwt_tenant),
            webhook_timeout_seconds=float(os.getenv("WEBHOOK_TIMEOUT_SECONDS", cls.webhook_timeout_seconds)),
            webhook_max_attempts=int(os.getenv("WEBHOOK_MAX_ATTEMPTS", cls.webhook_max_attempts)),
            allow_insecure_webhooks=_bool("ALLOW_INSECURE_WEBHOOKS", cls.allow_insecure_webhooks),
            allow_private_webhooks=_bool("ALLOW_PRIVATE_WEBHOOKS", cls.allow_private_webhooks),
            rules_fallback_on_llm_error=_bool("RULES_FALLBACK_ON_LLM_ERROR", cls.rules_fallback_on_llm_error),
        )

    def load_tenants(self) -> TenantRegistry:
        if self.tenants_secret_id:
            return TenantRegistry.from_secrets_manager(self.tenants_secret_id, self.aws_region)
        if self.tenants_config_json:
            return TenantRegistry.from_json(self.tenants_config_json)
        return TenantRegistry.from_file(self.tenants_config_path)
