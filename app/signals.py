"""Deterministic pre-screening signals.

These are cheap, explainable features computed before the LLM runs. They are passed to
the LLM as hints, and they power the rules-only fallback when Bedrock is unavailable
(and the offline ``mock`` provider used in docker-compose / CI).
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from app.models import Finding, RiskAssessment, Severity, Transaction

RISKY_MERCHANT_KEYWORDS = ("crypto", "gift card", "giftcard", "wire", "casino", "bet", "moneygram", "western union")
VELOCITY_WINDOW = timedelta(minutes=10)
VELOCITY_COUNT = 4
DUPLICATE_WINDOW = timedelta(minutes=5)
OUTLIER_MULTIPLIER = 5.0


@dataclass(frozen=True)
class Signal:
    name: str
    detail: str
    weight: int


def compute_signals(transactions: list[Transaction], high_amount_threshold: float = 5000.0) -> dict[str, list[Signal]]:
    """Return {transaction_id: [signals]} for every transaction (possibly empty lists)."""
    signals: dict[str, list[Signal]] = {t.transaction_id: [] for t in transactions}
    by_customer: dict[str, list[Transaction]] = defaultdict(list)
    for txn in transactions:
        by_customer[txn.customer_id].append(txn)

    for txn in transactions:
        out = signals[txn.transaction_id]
        if txn.amount >= high_amount_threshold:
            out.append(Signal("high_amount", f"{txn.amount:.2f} >= threshold {high_amount_threshold:.0f}", 25))
        if txn.timestamp.hour < 5:
            out.append(Signal("odd_hour", f"at {txn.timestamp:%H:%M} UTC", 10))
        if txn.amount >= 1000 and txn.amount % 500 == 0:
            out.append(Signal("round_amount", f"round amount {txn.amount:.0f}", 5))
        merchant = txn.merchant.lower()
        hit = next((k for k in RISKY_MERCHANT_KEYWORDS if k in merchant), None)
        if hit:
            out.append(Signal("risky_merchant", f"merchant matches '{hit}'", 20))

    for customer_txns in by_customer.values():
        ordered = sorted(customer_txns, key=lambda t: t.timestamp)
        # Amount outlier vs. the customer's own median (needs some history in the batch).
        if len(ordered) >= 3:
            for txn in ordered:
                others = [t.amount for t in ordered if t is not txn]
                median = statistics.median(others)
                if median > 0 and txn.amount >= OUTLIER_MULTIPLIER * median:
                    signals[txn.transaction_id].append(
                        Signal("amount_outlier", f"{txn.amount / median:.1f}x customer median {median:.2f}", 30)
                    )
        # Velocity: many charges inside a short window (card testing / account takeover).
        for i, txn in enumerate(ordered):
            window = [t for t in ordered[i:] if t.timestamp - txn.timestamp <= VELOCITY_WINDOW]
            if len(window) >= VELOCITY_COUNT:
                for t in window:
                    names = {s.name for s in signals[t.transaction_id]}
                    if "velocity" not in names:
                        signals[t.transaction_id].append(
                            Signal("velocity", f"{len(window)} charges within {VELOCITY_WINDOW}", 30)
                        )
        # Duplicates: same merchant + amount within a few minutes.
        for i, a in enumerate(ordered):
            for b in ordered[i + 1 :]:
                if b.timestamp - a.timestamp > DUPLICATE_WINDOW:
                    break
                if a.merchant.lower() == b.merchant.lower() and a.amount == b.amount:
                    signals[b.transaction_id].append(Signal("duplicate", f"same merchant/amount as {a.transaction_id}", 20))
    return signals


def score(signals: list[Signal]) -> int:
    return min(100, sum(s.weight for s in signals))


def severity_for_score(value: int) -> Severity:
    if value >= 75:
        return Severity.CRITICAL
    if value >= 50:
        return Severity.HIGH
    if value >= 30:
        return Severity.MEDIUM
    return Severity.LOW


def rules_assessment(transactions: list[Transaction], signals: dict[str, list[Signal]]) -> RiskAssessment:
    """Deterministic assessment used for the offline/mock provider and as LLM-failure fallback."""
    findings = []
    for txn in transactions:
        txn_signals = signals.get(txn.transaction_id, [])
        value = score(txn_signals)
        if value >= 30:
            findings.append(
                Finding(
                    transaction_id=txn.transaction_id,
                    customer_id=txn.customer_id,
                    risk_score=value,
                    severity=severity_for_score(value),
                    reasons=[f"{s.name}: {s.detail}" for s in txn_signals],
                )
            )
    summary = (
        f"Rules-based screen flagged {len(findings)} of {len(transactions)} transactions."
        if findings
        else f"Rules-based screen found no suspicious activity in {len(transactions)} transactions."
    )
    return RiskAssessment(findings=findings, summary=summary)
