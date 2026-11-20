#!/usr/bin/env python3
"""Golden-set evaluation / smoke test for the Risk Monitor.

Runs labelled cases against a target and gates on precision/recall, so a prompt or model
change that starts producing false positives fails the pipeline BEFORE it reaches prod.
Cases always run with dry_run=true, so evaluations never page the real risk team.

Targets:
  inprocess                    - call app.main.handle directly (CI; LLM_PROVIDER decides mock/bedrock)
  http://localhost:8080        - a running container (docker-compose)
  arn:aws:bedrock-agentcore:...- a deployed AgentCore runtime (use --qualifier staging|prod)
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET = ROOT / "evals" / "golden.json"


def invoke_inprocess(payload: dict) -> dict:
    sys.path.insert(0, str(ROOT))
    from app.main import handle

    result = handle(payload)
    if not isinstance(result, dict):  # error JSONResponse
        raise RuntimeError(f"HTTP {result.status_code}: {result.body.decode()}")
    return result


def invoke_http(url: str, payload: dict, token: str | None = None) -> dict:
    headers = {"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})}
    req = urllib.request.Request(url.rstrip("/") + "/invocations", data=json.dumps(payload).encode(), headers=headers)  # noqa: S310
    with urllib.request.urlopen(req, timeout=300) as resp:  # noqa: S310 - operator-supplied URL
        return json.loads(resp.read())


def invoke_agentcore(arn: str, qualifier: str, payload: dict, region: str | None = None) -> dict:
    import boto3
    from botocore.config import Config

    client = boto3.client("bedrock-agentcore", region_name=region or arn.split(":")[3], config=Config(read_timeout=300))
    resp = client.invoke_agent_runtime(
        agentRuntimeArn=arn,
        qualifier=qualifier,
        runtimeSessionId=f"eval-{uuid.uuid4()}",  # >= 33 chars; one isolated session per case
        contentType="application/json",
        accept="application/json",
        payload=json.dumps(payload).encode(),
    )
    return json.loads(resp["response"].read())


def score(cases: list[dict], results: list[dict]) -> dict:
    tp = fp = fn = 0
    failures = []
    for case, result in zip(cases, results, strict=False):
        flagged = {f["transaction_id"] for f in result.get("findings", [])}
        expected = set(case.get("expected_flagged", []))
        forbidden = set(case.get("must_not_flag", []))
        tp += len(flagged & expected)
        fn += len(expected - flagged)
        fp += len(flagged & forbidden)
        if expected - flagged or flagged & forbidden:
            failures.append(
                {"case": case["name"], "missed": sorted(expected - flagged), "false_positives": sorted(flagged & forbidden)}
            )
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return {"precision": round(precision, 3), "recall": round(recall, 3), "tp": tp, "fp": fp, "fn": fn, "failures": failures}


def run(target: str, dataset: Path, qualifier: str = "DEFAULT", token: str | None = None) -> tuple[dict, list]:
    data = json.loads(Path(dataset).read_text())
    cases, results = data["cases"], []
    for case in cases:
        payload = {**case["payload"], "dry_run": True}
        if target == "inprocess":
            result = invoke_inprocess(payload)
        elif target.startswith("http"):
            result = invoke_http(target, payload, token)
        elif target.startswith("arn:"):
            result = invoke_agentcore(target, qualifier, payload)
        else:
            raise SystemExit(f"unknown target {target}")
        for key in ("request_id", "findings", "summary", "prompt_version", "agent_version"):
            if key not in result:
                raise SystemExit(f"case {case['name']}: response missing '{key}': {result}")
        results.append(result)
        print(
            f"  {case['name']}: flagged={sorted(f['transaction_id'] for f in result['findings'])} "
            f"mode={result.get('analysis_mode')} prompt={result['prompt_version']}",
            file=sys.stderr,
        )
    return score(cases, results), results


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", default="inprocess")
    p.add_argument("--qualifier", default="DEFAULT", help="AgentCore endpoint name (staging/prod)")
    p.add_argument("--dataset", default=str(DEFAULT_DATASET))
    p.add_argument("--min-precision", type=float, default=0.9)
    p.add_argument("--min-recall", type=float, default=0.9)
    p.add_argument("--token", help="bearer token (when the runtime uses JWT auth)")
    args = p.parse_args(argv)

    metrics, _ = run(args.target, Path(args.dataset), args.qualifier, args.token)
    print(json.dumps(metrics, indent=2))
    ok = metrics["precision"] >= args.min_precision and metrics["recall"] >= args.min_recall
    print("EVAL PASSED" if ok else "EVAL FAILED", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
