"""Runs the REAL Strands agent loop with a scripted model: tool call -> structured output."""

from app.agent import RiskMonitor, StrandsBedrockAnalyzer
from app.webhook import verify
from tests.fakes import STRUCTURED, ScriptedModel

ASSESSMENT = {
    "findings": [
        {
            "transaction_id": "t-004",
            "risk_score": 92,
            "severity": "critical",
            "reasons": ["9500 at crypto exchange, ~200x customer median, 03:14 UTC"],
        },
        {
            "transaction_id": "t-008",
            "risk_score": 70,
            "severity": "high",
            "reasons": ["card testing: three $1 charges then $499.99"],
        },
    ],
    "summary": "Two suspicious patterns: a crypto cash-out and card testing on gift cards.",
}


def make_monitor(model, webhook):
    analyzer = StrandsBedrockAnalyzer("scripted-fake", "us-east-1", model=model)
    return RiskMonitor(analyzer, webhook, agent_version="test-sha", default_prompt_version="v1")


def test_agent_calls_tool_then_returns_structured_output(sample_request, acme, webhook, recorder):
    model = ScriptedModel(
        [
            [("notify_risk_team", {"transaction_ids": ["t-004"], "severity": "critical", "reason": "crypto cash-out"})],
            [(STRUCTURED, ASSESSMENT)],
        ]
    )
    resp = make_monitor(model, webhook).run(sample_request, acme, "req-1")

    # Model saw our tool and the versioned system prompt.
    assert "notify_risk_team" in model.calls[0]["tool_names"]
    assert "Risk Monitor" in model.calls[0]["system"]

    assert resp.analysis_mode == "llm"
    assert [f.transaction_id for f in resp.findings] == ["t-004", "t-008"]
    assert resp.findings[0].customer_id == "cust-17"  # filled from source data

    # t-004 alerted by the agent's tool call; t-008 (high, missed by the LLM) by the safety net.
    sources = {r.source: r.transaction_ids for r in resp.notifications}
    assert sources == {"agent_tool": ["t-004"], "fallback": ["t-008"]}
    assert len(recorder.requests) == 2
    req = recorder.requests[0]
    assert str(req.url) == acme.webhook_url
    assert verify(
        acme.webhook_secret.get_secret_value(), req.headers["X-Risk-Timestamp"], req.content, req.headers["X-Risk-Signature"]
    )


def test_agent_tool_rejects_hallucinated_ids(sample_request, acme, webhook, recorder):
    model = ScriptedModel(
        [
            [("notify_risk_team", {"transaction_ids": ["t-999"], "severity": "high", "reason": "made up"})],
            [
                (
                    STRUCTURED,
                    {"findings": [{"transaction_id": "t-999", "risk_score": 80, "severity": "high"}], "summary": "x"},
                )
            ],
        ]
    )
    resp = make_monitor(model, webhook).run(sample_request, acme, "req-2")
    assert resp.findings == []
    assert recorder.requests == []
