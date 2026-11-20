"""Test doubles: a scripted Strands model (drives the real Strands agent loop offline)."""

from __future__ import annotations

import json
from typing import Any

from strands.models import Model

STRUCTURED = "__structured_output__"  # placeholder: resolved to the structured-output tool name


class ScriptedModel(Model):
    """Each call to `stream` plays the next scripted turn: a list of (tool_name, input) calls.

    Use STRUCTURED as tool_name to return the final structured output; it resolves to whichever
    tool spec Strands registered for the output model.
    """

    def __init__(self, turns: list[list[tuple[str, dict]]]):
        self.turns = list(turns)
        self.calls: list[dict[str, Any]] = []
        self.config = {"model_id": "scripted-fake"}

    def update_config(self, **model_config):
        self.config.update(model_config)

    def get_config(self):
        return self.config

    async def structured_output(self, output_model, prompt, system_prompt=None, **kwargs):
        raise NotImplementedError
        yield  # pragma: no cover

    async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs):
        specs = tool_specs or []
        self.calls.append({"messages": messages, "tool_names": [s["name"] for s in specs], "system": system_prompt})
        turn = self.turns.pop(0) if self.turns else []
        yield {"messageStart": {"role": "assistant"}}
        for i, (name, tool_input) in enumerate(turn):
            if name == STRUCTURED:
                name = next(s["name"] for s in specs if s["name"] != "notify_risk_team")
            yield {"contentBlockStart": {"start": {"toolUse": {"toolUseId": f"tu-{len(self.calls)}-{i}", "name": name}}}}
            yield {"contentBlockDelta": {"delta": {"toolUse": {"input": json.dumps(tool_input)}}}}
            yield {"contentBlockStop": {}}
        if not turn:
            yield {"contentBlockDelta": {"delta": {"text": "done"}}}
            yield {"contentBlockStop": {}}
        yield {"messageStop": {"stopReason": "tool_use" if turn else "end_turn"}}
        yield {"metadata": {"usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2}, "metrics": {"latencyMs": 1}}}


class FailingAnalyzer:
    mode = "llm"
    model_id = "broken"

    def assess(self, **kwargs):
        raise RuntimeError("bedrock throttled")


class StaticAnalyzer:
    """Returns a fixed assessment; optionally calls the notify tool first."""

    mode = "llm"
    model_id = "static"

    def __init__(self, assessment, tool_calls: list[dict] | None = None):
        self.assessment = assessment
        self.tool_calls = tool_calls or []
        self.seen: dict = {}

    def assess(self, *, system_prompt, user_prompt, tools, transactions, signals):
        self.seen = {"system_prompt": system_prompt, "user_prompt": user_prompt, "tools": tools}
        for call in self.tool_calls:
            tools[0](**call)
        return self.assessment
