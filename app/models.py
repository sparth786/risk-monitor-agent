"""Request/response schemas for the Risk Monitor agent."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_TRANSACTIONS_PER_REQUEST = 500


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def at_least(self, other: Severity) -> bool:
        return self.rank >= other.rank


_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


class Transaction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transaction_id: str | None = Field(default=None, max_length=128)
    amount: float = Field(gt=0, le=1_000_000_000)
    merchant: str = Field(min_length=1, max_length=256)
    timestamp: datetime
    customer_id: str = Field(min_length=1, max_length=128)
    currency: str = Field(default="USD", min_length=3, max_length=3)

    @field_validator("timestamp")
    @classmethod
    def _normalise_tz(cls, value: datetime) -> datetime:
        # Naive timestamps are treated as UTC so comparisons are always well defined.
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str | None = Field(default=None, max_length=64)
    transactions: list[Transaction] = Field(min_length=1, max_length=MAX_TRANSACTIONS_PER_REQUEST)
    prompt_version: str | None = Field(default=None, description="Optional override; must be allowed for the tenant")
    dry_run: bool = Field(default=False, description="Analyse without calling the webhook")

    @model_validator(mode="after")
    def _assign_ids(self) -> AnalyzeRequest:
        seen: set[str] = set()
        for index, txn in enumerate(self.transactions):
            if not txn.transaction_id:
                txn.transaction_id = f"txn-{index + 1}"
            if txn.transaction_id in seen:
                raise ValueError(f"duplicate transaction_id: {txn.transaction_id}")
            seen.add(txn.transaction_id)
        return self


class Finding(BaseModel):
    """One suspicious transaction, as judged by the LLM."""

    transaction_id: str
    customer_id: str | None = None
    risk_score: int = Field(ge=0, le=100, description="0 = clearly fine, 100 = almost certainly fraud")
    severity: Severity
    reasons: list[str] = Field(default_factory=list, description="Short, concrete reasons")


class RiskAssessment(BaseModel):
    """Structured output the LLM must return."""

    findings: list[Finding] = Field(default_factory=list, description="Only suspicious transactions")
    summary: str = Field(description="2-4 sentence summary for the risk team")


class NotificationRecord(BaseModel):
    transaction_ids: list[str]
    severity: Severity
    source: str  # "agent_tool" | "fallback"
    status: str  # "sent" | "failed" | "dry_run"
    attempts: int = 0
    http_status: int | None = None
    error: str | None = None


class AnalyzeResponse(BaseModel):
    request_id: str
    tenant_id: str
    agent_version: str
    prompt_version: str
    model_id: str
    analysis_mode: str  # "llm" | "rules_fallback" | "mock"
    transactions_analyzed: int
    flagged_count: int
    findings: list[Finding]
    notifications: list[NotificationRecord]
    summary: str
