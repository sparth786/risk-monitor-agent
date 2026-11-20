"""Risk Monitor orchestration: signals -> LLM agent (Strands + Bedrock) -> guaranteed alerting."""

from __future__ import annotations

import json
import logging
from typing import Protocol

from app.models import AnalyzeRequest, AnalyzeResponse, Finding, RiskAssessment, Severity, Transaction
from app.prompts import get_prompt, prompt_fingerprint
from app.signals import Signal, compute_signals, rules_assessment
from app.tenants import TenantConfig
from app.tools import NotificationSink, make_notify_tool
from app.webhook import WebhookClient

logger = logging.getLogger(__name__)


class PromptVersionNotAllowedError(PermissionError):
    pass


class Analyzer(Protocol):
    """Anything that turns a prompt + tools into a RiskAssessment."""

    mode: str
    model_id: str

    def assess(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        tools: list,
        transactions: list[Transaction],
        signals: dict[str, list[Signal]],
    ) -> RiskAssessment: ...


class StrandsBedrockAnalyzer:
    """Real LLM path: a Strands agent on Amazon Bedrock with the notify tool attached."""

    mode = "llm"

    def __init__(self, model_id: str, region: str, max_tokens: int = 4096, model=None, temperature: float | None = None):
        self.model_id = model_id
        self.region = region
        self.max_tokens = max_tokens
        self.temperature = temperature
        self._model = model  # injectable (tests pass a scripted fake Strands model)

    def _build_model(self):
        if self._model is not None:
            return self._model
        from strands.models.bedrock import BedrockModel

        # Temperature is only sent when configured: Nova recommends 0 (greedy) for tool use,
        # while current Claude models on Bedrock reject sampling params entirely.
        extra = {"temperature": self.temperature} if self.temperature is not None else {}
        return BedrockModel(model_id=self.model_id, region_name=self.region, max_tokens=self.max_tokens, **extra)

    def assess(self, *, system_prompt, user_prompt, tools, transactions, signals) -> RiskAssessment:
        from strands import Agent

        # A fresh Agent per request: no conversation history is shared across tenants/requests.
        agent = Agent(
            model=self._build_model(),
            system_prompt=system_prompt,
            tools=tools,
            callback_handler=None,
        )
        result = agent(user_prompt, structured_output_model=RiskAssessment)
        if result.structured_output is None:
            raise RuntimeError("model returned no structured output")
        return result.structured_output


class MockAnalyzer:
    """Offline analyzer (no AWS): uses rule signals and calls the tool like the LLM would."""

    mode = "mock"
    model_id = "mock-rules"

    def __init__(self, notify_min_severity: Severity | None = None):
        self.notify_min_severity = notify_min_severity

    def assess(self, *, system_prompt, user_prompt, tools, transactions, signals) -> RiskAssessment:
        assessment = rules_assessment(transactions, signals)
        threshold = Severity(json.loads(user_prompt)["policy"]["notify_min_severity"])
        notify = next(t for t in tools if getattr(t, "tool_name", "") == "notify_risk_team")
        urgent = [f for f in assessment.findings if f.severity.at_least(threshold)]
        if urgent:
            top = max((f.severity for f in urgent), key=lambda s: s.rank)
            notify(
                transaction_ids=[f.transaction_id for f in urgent],
                severity=top.value,
                reason="Rules screen: " + "; ".join(urgent[0].reasons[:2]),
            )
        return assessment


def build_user_prompt(tenant: TenantConfig, transactions: list[Transaction], signals: dict[str, list[Signal]]) -> str:
    payload = {
        "policy": {
            "notify_min_severity": tenant.notify_min_severity.value,
            "high_amount_threshold": tenant.high_amount_threshold,
        },
        "transactions": [
            {
                **t.model_dump(mode="json"),
                "signals": [f"{s.name}: {s.detail}" for s in signals.get(t.transaction_id, [])],
            }
            for t in transactions
        ],
    }
    # JSON keeps the data clearly separated from instructions (prompt-injection hygiene).
    return json.dumps(payload, indent=1)


class RiskMonitor:
    def __init__(
        self,
        analyzer: Analyzer,
        webhook: WebhookClient,
        *,
        agent_version: str,
        default_prompt_version: str,
        rules_fallback_on_error: bool = True,
    ):
        self.analyzer = analyzer
        self.webhook = webhook
        self.agent_version = agent_version
        self.default_prompt_version = default_prompt_version
        self.rules_fallback_on_error = rules_fallback_on_error

    def resolve_prompt_version(self, tenant: TenantConfig, requested: str | None) -> str:
        if requested is None:
            return tenant.prompt_version or self.default_prompt_version
        if requested not in tenant.prompt_versions():
            raise PromptVersionNotAllowedError(f"prompt_version '{requested}' is not enabled for this tenant")
        return requested

    def run(self, request: AnalyzeRequest, tenant: TenantConfig, request_id: str) -> AnalyzeResponse:
        prompt_version = self.resolve_prompt_version(tenant, request.prompt_version)
        system_prompt = get_prompt(prompt_version)
        txns = request.transactions
        signals = compute_signals(txns, tenant.high_amount_threshold)

        sink = NotificationSink(
            tenant=tenant,
            webhook=self.webhook,
            transactions=txns,
            request_id=request_id,
            agent_version=self.agent_version,
            prompt_version=prompt_version,
            dry_run=request.dry_run,
        )
        tools = [make_notify_tool(sink)]
        mode, model_id = self.analyzer.mode, self.analyzer.model_id
        logger.info(
            "analyze tenant=%s request=%s txns=%d prompt=%s@%s mode=%s",
            tenant.tenant_id,
            request_id,
            len(txns),
            prompt_version,
            prompt_fingerprint(prompt_version),
            mode,
        )
        try:
            assessment = self.analyzer.assess(
                system_prompt=system_prompt,
                user_prompt=build_user_prompt(tenant, txns, signals),
                tools=tools,
                transactions=txns,
                signals=signals,
            )
        except Exception:
            if not self.rules_fallback_on_error:
                raise
            logger.exception("LLM analysis failed; degrading to rules tenant=%s request=%s", tenant.tenant_id, request_id)
            assessment = rules_assessment(txns, signals)
            mode, model_id = "rules_fallback", "rules"

        findings = self._sanitize(assessment.findings, txns)
        self._ensure_alerts(findings, tenant, sink)
        return AnalyzeResponse(
            request_id=request_id,
            tenant_id=tenant.tenant_id,
            agent_version=self.agent_version,
            prompt_version=prompt_version,
            model_id=model_id,
            analysis_mode=mode,
            transactions_analyzed=len(txns),
            flagged_count=len(findings),
            findings=findings,
            notifications=sink.records,
            summary=assessment.summary,
        )

    @staticmethod
    def _sanitize(findings: list[Finding], txns: list[Transaction]) -> list[Finding]:
        """Drop hallucinated/duplicate IDs and fill customer_id from the source data."""
        by_id = {t.transaction_id: t for t in txns}
        clean: dict[str, Finding] = {}
        for f in findings:
            txn = by_id.get(f.transaction_id)
            if txn is None:
                logger.warning("dropping finding for unknown transaction_id=%s", f.transaction_id)
                continue
            if f.transaction_id in clean and clean[f.transaction_id].risk_score >= f.risk_score:
                continue
            clean[f.transaction_id] = f.model_copy(update={"customer_id": txn.customer_id})
        return sorted(clean.values(), key=lambda f: f.risk_score, reverse=True)

    @staticmethod
    def _ensure_alerts(findings: list[Finding], tenant: TenantConfig, sink: NotificationSink) -> None:
        """Safety net: if the LLM flagged something severe but forgot to call the tool, alert anyway."""
        missed = [
            f
            for f in findings
            if f.severity.at_least(tenant.notify_min_severity) and f.transaction_id not in sink.notified_ids
        ]
        if missed:
            top = max((f.severity for f in missed), key=lambda s: s.rank)
            reason = "; ".join(dict.fromkeys(r for f in missed for r in f.reasons[:1])) or "flagged by risk monitor"
            sink.notify([f.transaction_id for f in missed], top, reason, source="fallback")
