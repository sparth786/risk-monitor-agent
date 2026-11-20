"""Per-tenant configuration and registry.

Webhook URLs and signing secrets live ONLY here (loaded server-side from a file,
an env var, or AWS Secrets Manager). They are never accepted from a request payload,
which is what keeps one customer from redirecting alerts or reading another's data.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from app.models import Severity

logger = logging.getLogger(__name__)

TENANT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")


class UnknownTenantError(LookupError):
    pass


class TenantConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str
    name: str = ""
    webhook_url: str
    webhook_secret: SecretStr = Field(min_length=16)
    prompt_version: str = "v1"
    allowed_prompt_versions: list[str] = Field(default_factory=list)
    notify_min_severity: Severity = Severity.HIGH
    high_amount_threshold: float = Field(default=5000.0, gt=0)

    @field_validator("tenant_id")
    @classmethod
    def _valid_id(cls, value: str) -> str:
        if not TENANT_ID_RE.match(value):
            raise ValueError("tenant_id must be lowercase alphanumeric, '-' or '_' (2-64 chars)")
        return value

    @field_validator("webhook_url")
    @classmethod
    def _valid_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in ("https", "http") or not parsed.hostname:
            raise ValueError("webhook_url must be an absolute http(s) URL")
        if parsed.username or parsed.password:
            raise ValueError("webhook_url must not embed credentials")
        return value

    def prompt_versions(self) -> set[str]:
        return {self.prompt_version, *self.allowed_prompt_versions}


class TenantRegistry:
    def __init__(self, tenants: list[TenantConfig]):
        self._tenants: dict[str, TenantConfig] = {}
        for tenant in tenants:
            if tenant.tenant_id in self._tenants:
                raise ValueError(f"duplicate tenant_id {tenant.tenant_id}")
            self._tenants[tenant.tenant_id] = tenant

    def get(self, tenant_id: str) -> TenantConfig:
        try:
            return self._tenants[tenant_id]
        except KeyError:
            raise UnknownTenantError(tenant_id) from None

    def ids(self) -> list[str]:
        return sorted(self._tenants)

    # ---- loaders -------------------------------------------------------
    @classmethod
    def from_data(cls, data: dict | list) -> TenantRegistry:
        items = data.get("tenants", []) if isinstance(data, dict) else data
        return cls([TenantConfig.model_validate(item) for item in items])

    @classmethod
    def from_json(cls, raw: str) -> TenantRegistry:
        return cls.from_data(json.loads(raw))

    @classmethod
    def from_file(cls, path: str | Path) -> TenantRegistry:
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    @classmethod
    def from_secrets_manager(cls, secret_id: str, region: str | None = None) -> TenantRegistry:
        import boto3  # imported lazily so local/dev runs don't need AWS

        client = boto3.client("secretsmanager", region_name=region)
        raw = client.get_secret_value(SecretId=secret_id)["SecretString"]
        return cls.from_json(raw)


def is_private_address(host: str) -> bool:
    """True for loopback / RFC1918 / link-local (e.g. the 169.254.169.254 metadata endpoint)."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
