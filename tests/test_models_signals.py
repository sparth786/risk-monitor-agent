from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.models import AnalyzeRequest, Severity, Transaction
from app.signals import compute_signals, rules_assessment, severity_for_score


def txn(i, amount, minutes=0, customer="c1", merchant="Shop", hour=12):
    ts = datetime(2026, 11, 20, hour, 0, tzinfo=UTC) + timedelta(minutes=minutes)
    return Transaction(transaction_id=f"t{i}", amount=amount, merchant=merchant, timestamp=ts, customer_id=customer)


def names(signals, tid):
    return {s.name for s in signals[tid]}


def test_request_assigns_ids_and_rejects_duplicates():
    base = {"amount": 1, "merchant": "m", "timestamp": "2026-01-01T00:00:00", "customer_id": "c"}
    req = AnalyzeRequest(transactions=[base, base])
    assert [t.transaction_id for t in req.transactions] == ["txn-1", "txn-2"]
    assert req.transactions[0].timestamp.tzinfo is not None  # naive -> UTC
    with pytest.raises(ValidationError):
        AnalyzeRequest(transactions=[{**base, "transaction_id": "x"}, {**base, "transaction_id": "x"}])


@pytest.mark.parametrize(
    "bad",
    [
        {"amount": -5},
        {"amount": 0},
        {"merchant": ""},
        {"timestamp": "not-a-date"},
        {"surprise": "field"},
    ],
)
def test_transaction_validation(bad):
    base = {"amount": 10, "merchant": "m", "timestamp": "2026-01-01T00:00:00Z", "customer_id": "c"}
    with pytest.raises(ValidationError):
        Transaction.model_validate({**base, **bad})


def test_request_requires_transactions():
    with pytest.raises(ValidationError):
        AnalyzeRequest(transactions=[])


def test_severity_ordering():
    assert Severity.CRITICAL.at_least(Severity.HIGH)
    assert not Severity.MEDIUM.at_least(Severity.HIGH)


def test_signals_detect_outlier_odd_hour_and_risky_merchant():
    txns = [txn(1, 40), txn(2, 50, 60), txn(3, 45, 120), txn(4, 9500, 0, merchant="CryptoXchange", hour=3)]
    sig = compute_signals(txns, high_amount_threshold=5000)
    assert {"high_amount", "amount_outlier", "risky_merchant", "odd_hour"} <= names(sig, "t4")
    assert names(sig, "t1") == set()


def test_signals_velocity_and_duplicates():
    txns = [txn(i, 1.0, minutes=i, merchant="Gift Card Store") for i in range(5)]
    sig = compute_signals(txns)
    assert all("velocity" in names(sig, f"t{i}") for i in range(5))
    assert "duplicate" in names(sig, "t1")
    assert "duplicate" not in names(sig, "t0")


def test_signals_are_per_customer():
    # Same pattern split across customers must not trigger velocity.
    txns = [txn(i, 1.0, minutes=i, customer=f"c{i}") for i in range(5)]
    sig = compute_signals(txns)
    assert not any("velocity" in names(sig, f"t{i}") for i in range(5))


def test_rules_assessment_and_severity_mapping():
    assert severity_for_score(80) is Severity.CRITICAL
    assert severity_for_score(10) is Severity.LOW
    txns = [txn(1, 40), txn(2, 50, 60), txn(3, 45, 120), txn(4, 9500, 0, merchant="CryptoXchange", hour=3)]
    result = rules_assessment(txns, compute_signals(txns))
    assert [f.transaction_id for f in result.findings] == ["t4"]
    assert result.findings[0].severity is Severity.CRITICAL
