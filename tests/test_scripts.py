"""Deployment tooling tests (fake AgentCore control-plane client) + golden eval in mock mode."""

from types import SimpleNamespace

import pytest

from scripts import agentcore_deploy as dep
from scripts import evaluate


class NotFound(Exception):
    pass


class FakeControl:
    """Minimal in-memory stand-in for boto3 'bedrock-agentcore-control'."""

    exceptions = SimpleNamespace(ResourceNotFoundException=NotFound)

    def __init__(self):
        self.runtime = None  # dict
        self.versions: dict[str, dict] = {}
        self.endpoints: dict[str, dict] = {}
        self.calls: list[tuple[str, dict]] = []

    def _new_version(self, kw):
        v = str(len(self.versions) + 1)
        self.versions[v] = kw
        self.runtime["agentRuntimeVersion"] = v
        return {
            "agentRuntimeId": "rt-1",
            "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:1:runtime/rt-1",
            "agentRuntimeVersion": v,
            "status": "CREATING",
        }

    def list_agent_runtimes(self, **kw):
        return {"agentRuntimes": [self.runtime] if self.runtime else []}

    def create_agent_runtime(self, **kw):
        self.calls.append(("create_agent_runtime", kw))
        self.runtime = {
            "agentRuntimeName": kw["agentRuntimeName"],
            "agentRuntimeId": "rt-1",
            "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:1:runtime/rt-1",
        }
        return self._new_version(kw)

    def update_agent_runtime(self, **kw):
        self.calls.append(("update_agent_runtime", kw))
        return self._new_version(kw)

    def get_agent_runtime(self, **kw):
        return {"status": "READY"}

    def get_agent_runtime_endpoint(self, agentRuntimeId, endpointName):
        if endpointName not in self.endpoints:
            raise NotFound(endpointName)
        return {**self.endpoints[endpointName], "status": "READY"}

    def create_agent_runtime_endpoint(self, agentRuntimeId, name, agentRuntimeVersion, description=None):
        self.endpoints[name] = {"liveVersion": agentRuntimeVersion, "description": description}

    def update_agent_runtime_endpoint(self, agentRuntimeId, endpointName, agentRuntimeVersion, description=None):
        self.endpoints[endpointName] = {"liveVersion": agentRuntimeVersion, "description": description}

    def list_agent_runtime_endpoints(self, agentRuntimeId):
        return {"runtimeEndpoints": [{"name": n, **e} for n, e in self.endpoints.items()]}


def run(client, *argv):
    args = dep.build_parser().parse_args(list(argv))
    return dep.COMMANDS[args.command](client, args, sleep=lambda s: None)


DEPLOY = ["deploy", "--runtime-name", "risk_monitor", "--role-arn", "arn:aws:iam::1:role/exec", "--endpoint", "staging"]


def test_deploy_promote_rollback_flow():
    c = FakeControl()
    out1 = run(c, *DEPLOY, "--image-uri", "repo:sha1", "--env", "AGENT_VERSION=sha1")
    assert out1["runtime_version"] == "1" and c.calls[0][0] == "create_agent_runtime"
    spec = c.calls[0][1]
    assert spec["agentRuntimeArtifact"]["containerConfiguration"]["containerUri"] == "repo:sha1"
    assert spec["environmentVariables"] == {"AGENT_VERSION": "sha1"}
    assert spec["requestHeaderConfiguration"]["requestHeaderAllowlist"] == ["Authorization"]

    run(c, "promote", "--runtime-name", "risk_monitor", "--endpoint", "prod", "--version", "1")
    # A prompt/config change = new image or env -> new immutable version, staging moves, prod doesn't.
    out2 = run(c, *DEPLOY, "--image-uri", "repo:sha2", "--env", "AGENT_VERSION=sha2")
    assert out2["runtime_version"] == "2" and c.calls[-1][0] == "update_agent_runtime"
    assert c.endpoints["staging"]["liveVersion"] == "2" and c.endpoints["prod"]["liveVersion"] == "1"

    promoted = run(c, "promote", "--runtime-name", "risk_monitor", "--endpoint", "prod", "--version", "2")
    assert promoted["previous_version"] == "1"
    assert "previous=1" in c.endpoints["prod"]["description"]

    rb = run(c, "rollback", "--runtime-name", "risk_monitor", "--endpoint", "prod")
    assert rb["runtime_version"] == "1" and rb["rolled_back_from"] == "2"
    assert c.endpoints["prod"]["liveVersion"] == "1"


def test_rollback_explicit_version_and_missing_history():
    c = FakeControl()
    run(c, *DEPLOY, "--image-uri", "repo:a")
    run(c, *DEPLOY, "--image-uri", "repo:b")
    run(c, "promote", "--runtime-name", "risk_monitor", "--endpoint", "prod", "--version", "2")
    with pytest.raises(SystemExit):
        run(c, "rollback", "--runtime-name", "risk_monitor", "--endpoint", "prod")
    assert (
        run(c, "rollback", "--runtime-name", "risk_monitor", "--endpoint", "prod", "--to-version", "1")["runtime_version"]
        == "1"
    )


def test_jwt_authorizer_config():
    args = dep.build_parser().parse_args(
        [
            *DEPLOY,
            "--image-uri",
            "x",
            "--jwt-discovery-url",
            "https://cognito/.well-known/openid-configuration",
            "--jwt-client-id",
            "client-a",
        ]
    )
    spec = dep.runtime_spec(args)
    assert spec["authorizerConfiguration"]["customJWTAuthorizer"]["allowedClients"] == ["client-a"]


def test_failed_status_aborts():
    with pytest.raises(SystemExit):
        dep.wait_for(lambda: {"status": "UPDATE_FAILED", "failureReason": "bad image"}, "rt", sleep=lambda s: None)


def test_bad_env_pair():
    with pytest.raises(SystemExit):
        dep.parse_env(["NOEQUALS"])


def test_golden_eval_passes_in_mock_mode(monkeypatch):
    from app import main

    monkeypatch.setenv("LLM_PROVIDER", "mock")
    main.set_service(None)
    try:
        metrics, results = evaluate.run("inprocess", evaluate.DEFAULT_DATASET)
    finally:
        main.set_service(None)
    assert metrics["precision"] == 1.0 and metrics["recall"] == 1.0, metrics
    assert all(n["status"] == "dry_run" for r in results for n in r["notifications"])


def test_eval_scoring_counts_false_positives():
    cases = [{"name": "x", "expected_flagged": ["a"], "must_not_flag": ["b", "c"]}]
    results = [{"findings": [{"transaction_id": "a"}, {"transaction_id": "b"}]}]
    m = evaluate.score(cases, results)
    assert m["fp"] == 1 and m["precision"] == 0.5 and m["recall"] == 1.0
    assert m["failures"][0]["false_positives"] == ["b"]


def test_require_mode_rejects_rules_fallback(monkeypatch):
    """A gate meant for the LLM must not go green just because the rules fallback scored well."""
    from app import main

    monkeypatch.setenv("LLM_PROVIDER", "mock")
    main.set_service(None)
    try:
        assert evaluate.main(["--target", "inprocess"]) == 0  # mock mode, no mode requirement
        assert evaluate.main(["--target", "inprocess", "--require-mode", "llm"]) == 1
    finally:
        main.set_service(None)
