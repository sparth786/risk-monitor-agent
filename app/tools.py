"""The `notify_risk_team` tool the LLM can call.

The tool is created per request and closes over that request's tenant. The LLM only
chooses *which* transactions and *how severe*; it can never choose the destination URL
or the signing secret, and it cannot reference transactions outside the current batch.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime

from strands import tool

from app.models import NotificationRecord, Severity, Transaction
from app.tenants import TenantConfig
from app.webhook import WebhookClient

logger = logging.getLogger(__name__)


class NotificationSink:
    """Per-request state: delivers webhooks for one tenant and records what was sent."""

    def __init__(
        self,
        *,
        tenant: TenantConfig,
        webhook: WebhookClient,
        transactions: list[Transaction],
        request_id: str,
        agent_version: str,
        prompt_version: str,
        dry_run: bool = False,
    ):
        self.tenant = tenant
        self.webhook = webhook
        self.request_id = request_id
        self.agent_version = agent_version
        self.prompt_version = prompt_version
        self.dry_run = dry_run
        self._txns = {t.transaction_id: t for t in transactions}
        self._notified: set[str] = set()
        self._lock = threading.Lock()
        self.records: list[NotificationRecord] = []

    @property
    def notified_ids(self) -> set[str]:
        return set(self._notified)

    def notify(self, transaction_ids: list[str], severity: str | Severity, reason: str, source: str) -> dict:
        try:
            sev = Severity(severity.lower() if isinstance(severity, str) else severity)
        except ValueError:
            return {"status": "error", "error": f"invalid severity '{severity}'"}

        unknown = [t for t in transaction_ids if t not in self._txns]
        with self._lock:
            fresh = [t for t in dict.fromkeys(transaction_ids) if t in self._txns and t not in self._notified]
            if not fresh:
                return {"status": "skipped", "reason": "already notified or no valid ids", "unknown_ids": unknown}
            self._notified.update(fresh)

        event = {
            "event_type": "risk.detected",
            "tenant_id": self.tenant.tenant_id,
            "request_id": self.request_id,
            "severity": sev.value,
            "reason": reason[:1000],
            "transactions": [self._txns[t].model_dump(mode="json") for t in fresh],
            "agent_version": self.agent_version,
            "prompt_version": self.prompt_version,
            "detected_at": datetime.now(UTC).isoformat(),
        }
        idempotency_key = f"{self.request_id}:{','.join(sorted(fresh))}"

        if self.dry_run:
            record = NotificationRecord(transaction_ids=fresh, severity=sev, source=source, status="dry_run")
        else:
            result = self.webhook.send(self.tenant, event, idempotency_key=idempotency_key)
            record = NotificationRecord(
                transaction_ids=fresh,
                severity=sev,
                source=source,
                status="sent" if result.ok else "failed",
                attempts=result.attempts,
                http_status=result.status_code,
                error=result.error,
            )
        with self._lock:
            self.records.append(record)
        logger.info(
            "notify tenant=%s request=%s source=%s status=%s ids=%s",
            self.tenant.tenant_id,
            self.request_id,
            source,
            record.status,
            fresh,
        )
        return {"status": record.status, "notified_ids": fresh, "unknown_ids": unknown}


def make_notify_tool(sink: NotificationSink):
    """Build a Strands tool bound to this request's sink (and therefore tenant)."""

    @tool
    def notify_risk_team(transaction_ids: list[str], severity: str, reason: str) -> dict:
        """Send an alert to the risk team's webhook about suspicious transactions.

        Call this once per group of related suspicious transactions whose severity is at or
        above the tenant's notification threshold.

        Args:
            transaction_ids: IDs of the suspicious transactions (must come from the input batch).
            severity: One of "low", "medium", "high", "critical".
            reason: One sentence explaining why these transactions are suspicious.
        """
        return sink.notify(transaction_ids, severity, reason, source="agent_tool")

    return notify_risk_team
