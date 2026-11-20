"""Signed, retrying webhook delivery with SSRF protection."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import socket
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from app.tenants import TenantConfig, is_private_address

logger = logging.getLogger(__name__)

SIGNATURE_HEADER = "X-Risk-Signature"
TIMESTAMP_HEADER = "X-Risk-Timestamp"
IDEMPOTENCY_HEADER = "X-Idempotency-Key"
TENANT_HEADER = "X-Tenant-Id"

Resolver = Callable[[str], list[str]]


class WebhookBlockedError(ValueError):
    """Raised when a webhook URL is not allowed (scheme / private network)."""


@dataclass
class DeliveryResult:
    ok: bool
    attempts: int
    status_code: int | None = None
    error: str | None = None


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """HMAC-SHA256 over ``"{timestamp}.{body}"`` - receivers verify this to trust the alert."""
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def verify(secret: str, timestamp: str, body: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign(secret, timestamp, body), signature)


def _default_resolver(host: str) -> list[str]:
    return list({info[4][0] for info in socket.getaddrinfo(host, None)})


class WebhookClient:
    def __init__(
        self,
        *,
        timeout: float = 5.0,
        max_attempts: int = 3,
        backoff_seconds: float = 0.5,
        allow_insecure: bool = False,
        allow_private: bool = False,
        resolver: Resolver | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.max_attempts = max(1, max_attempts)
        self.backoff_seconds = backoff_seconds
        self.allow_insecure = allow_insecure
        self.allow_private = allow_private
        self._resolver = resolver or _default_resolver
        self._sleep = sleep
        # follow_redirects=False: a redirect could bounce us to an internal address.
        self._client = httpx.Client(timeout=timeout, transport=transport, follow_redirects=False)

    def check_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" and not (self.allow_insecure and parsed.scheme == "http"):
            raise WebhookBlockedError(f"scheme '{parsed.scheme}' not allowed")
        host = parsed.hostname or ""
        if self.allow_private:
            return
        addresses = [host] if is_private_address(host) else self._resolver(host)
        if any(is_private_address(a) for a in addresses):
            raise WebhookBlockedError(f"host '{host}' resolves to a private address")

    def send(self, tenant: TenantConfig, event: dict, idempotency_key: str | None = None) -> DeliveryResult:
        try:
            self.check_url(tenant.webhook_url)
        except (WebhookBlockedError, OSError) as exc:
            logger.warning("webhook blocked tenant=%s: %s", tenant.tenant_id, exc)
            return DeliveryResult(ok=False, attempts=0, error=f"blocked: {exc}")

        body = json.dumps(event, separators=(",", ":"), sort_keys=True, default=str).encode()
        key = idempotency_key or str(uuid.uuid4())
        last = DeliveryResult(ok=False, attempts=0)
        for attempt in range(1, self.max_attempts + 1):
            timestamp = str(int(time.time()))
            headers = {
                "Content-Type": "application/json",
                SIGNATURE_HEADER: sign(tenant.webhook_secret.get_secret_value(), timestamp, body),
                TIMESTAMP_HEADER: timestamp,
                IDEMPOTENCY_HEADER: key,  # same key on every retry so receivers can dedupe
                TENANT_HEADER: tenant.tenant_id,
            }
            try:
                resp = self._client.post(tenant.webhook_url, content=body, headers=headers)
            except httpx.HTTPError as exc:
                last = DeliveryResult(ok=False, attempts=attempt, error=f"{type(exc).__name__}: {exc}")
            else:
                if 200 <= resp.status_code < 300:
                    return DeliveryResult(ok=True, attempts=attempt, status_code=resp.status_code)
                last = DeliveryResult(ok=False, attempts=attempt, status_code=resp.status_code, error="non-2xx")
                if resp.status_code < 500 and resp.status_code != 429:
                    break  # client errors won't fix themselves
            if attempt < self.max_attempts:
                self._sleep(self.backoff_seconds * (2 ** (attempt - 1)))
        logger.error("webhook failed tenant=%s attempts=%s error=%s", tenant.tenant_id, last.attempts, last.error)
        return last

    def close(self) -> None:
        self._client.close()
