#!/usr/bin/env python3
"""Deploy / promote / roll back the Risk Monitor on Amazon Bedrock AgentCore Runtime.

Model:
  * One AgentCore *runtime*. Every `deploy` (new image OR new config/env vars) creates a new,
    immutable runtime *version* (1, 2, 3, ...).
  * Named *endpoints* are movable pointers to a version, like aliases:
      staging -> newest version (auto-updated by CI)
      prod    -> the version that passed staging checks and manual approval
  * `promote` moves an endpoint to a version and remembers the previous one in the endpoint
    description, so `rollback` is a single pointer flip (seconds, no rebuild).

Usage:
  deploy   --runtime-name risk_monitor --image-uri <ecr-uri> --role-arn <exec-role> --endpoint staging \
           --env AGENT_VERSION=<sha> --env BEDROCK_MODEL_ID=... [--jwt-discovery-url ... --jwt-client-id ...]
  promote  --runtime-name risk_monitor --endpoint prod --version 7 [--note sha=abc123]
  rollback --runtime-name risk_monitor --endpoint prod [--to-version 6]
  status   --runtime-name risk_monitor
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time

TERMINAL_OK = {"READY"}
TERMINAL_BAD = {"CREATE_FAILED", "UPDATE_FAILED", "DELETE_FAILED"}
_PREV_RE = re.compile(r"previous=(\d+)")


def control_client(region: str | None):
    import boto3

    return boto3.client("bedrock-agentcore-control", region_name=region)


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def write_outputs(outputs: dict) -> None:
    """Print JSON and, inside GitHub Actions, export step outputs."""
    print(json.dumps(outputs, default=str))
    gh = os.getenv("GITHUB_OUTPUT")
    if gh:
        with open(gh, "a", encoding="utf-8") as fh:
            for key, value in outputs.items():
                fh.write(f"{key}={value}\n")


def find_runtime(client, name: str) -> dict | None:
    token = None
    while True:
        kwargs = {"maxResults": 100, **({"nextToken": token} if token else {})}
        page = client.list_agent_runtimes(**kwargs)
        for rt in page.get("agentRuntimes", []):
            if rt["agentRuntimeName"] == name:
                return rt
        token = page.get("nextToken")
        if not token:
            return None


def require_runtime(client, name: str) -> dict:
    rt = find_runtime(client, name)
    if rt is None:
        raise SystemExit(f"runtime '{name}' not found")
    return rt


def wait_for(fetch, what: str, timeout: float = 900, interval: float = 10, sleep=time.sleep) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        state = fetch()
        status = state.get("status")
        log(f"  {what}: {status}")
        if status in TERMINAL_OK:
            return state
        if status in TERMINAL_BAD:
            raise SystemExit(f"{what} failed: {state.get('failureReason', status)}")
        if time.monotonic() > deadline:
            raise SystemExit(f"timed out waiting for {what}")
        sleep(interval)


def parse_env(pairs: list[str]) -> dict[str, str]:
    env = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise SystemExit(f"--env expects KEY=VALUE, got '{pair}'")
        env[key] = value
    return env


def runtime_spec(args) -> dict:
    spec = {
        "agentRuntimeArtifact": {"containerConfiguration": {"containerUri": args.image_uri}},
        "roleArn": args.role_arn,
        "networkConfiguration": {"networkMode": "PUBLIC"},
        "protocolConfiguration": {"serverProtocol": "HTTP"},
        "environmentVariables": parse_env(args.env),
        # Forward the bearer token to the container so it can read the tenant claim.
        "requestHeaderConfiguration": {"requestHeaderAllowlist": ["Authorization"]},
    }
    if args.jwt_discovery_url:
        jwt = {"discoveryUrl": args.jwt_discovery_url}
        if args.jwt_client_id:
            jwt["allowedClients"] = args.jwt_client_id
        if args.jwt_audience:
            jwt["allowedAudience"] = args.jwt_audience
        spec["authorizerConfiguration"] = {"customJWTAuthorizer": jwt}
    return spec


def get_endpoint(client, runtime_id: str, endpoint: str) -> dict | None:
    try:
        return client.get_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=endpoint)
    except client.exceptions.ResourceNotFoundException:
        return None


def point_endpoint(client, runtime_id: str, endpoint: str, version: str, note: str = "", sleep=time.sleep) -> dict:
    """Create or move `endpoint` to `version`, recording the version it replaced."""
    current = get_endpoint(client, runtime_id, endpoint)
    previous = (current or {}).get("liveVersion")
    description = f"previous={previous} {note}".strip() if previous and previous != version else note or None
    kwargs = {"description": description[:256]} if description else {}
    if current is None:
        log(f"creating endpoint '{endpoint}' -> v{version}")
        client.create_agent_runtime_endpoint(agentRuntimeId=runtime_id, name=endpoint, agentRuntimeVersion=version, **kwargs)
    else:
        log(f"moving endpoint '{endpoint}' v{previous} -> v{version}")
        client.update_agent_runtime_endpoint(
            agentRuntimeId=runtime_id, endpointName=endpoint, agentRuntimeVersion=version, **kwargs
        )
    state = wait_for(
        lambda: client.get_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=endpoint),
        f"endpoint {endpoint}",
        sleep=sleep,
    )
    return {"endpoint": endpoint, "version": state.get("liveVersion", version), "previous_version": previous or ""}


def cmd_deploy(client, args, sleep=time.sleep) -> dict:
    spec = runtime_spec(args)
    existing = find_runtime(client, args.runtime_name)
    if existing is None:
        log(f"creating runtime '{args.runtime_name}'")
        resp = client.create_agent_runtime(agentRuntimeName=args.runtime_name, **spec)
    else:
        log(f"updating runtime '{args.runtime_name}' ({existing['agentRuntimeId']}) -> new version")
        resp = client.update_agent_runtime(agentRuntimeId=existing["agentRuntimeId"], **spec)
    runtime_id, version = resp["agentRuntimeId"], str(resp["agentRuntimeVersion"])
    wait_for(
        lambda: client.get_agent_runtime(agentRuntimeId=runtime_id, agentRuntimeVersion=version),
        f"runtime v{version}",
        sleep=sleep,
    )
    out = {"runtime_id": runtime_id, "runtime_arn": resp["agentRuntimeArn"], "runtime_version": version}
    if args.endpoint:
        moved = point_endpoint(client, runtime_id, args.endpoint, version, args.note, sleep=sleep)
        out["endpoint"], out["previous_version"] = moved["endpoint"], moved["previous_version"]
    return out


def cmd_promote(client, args, sleep=time.sleep) -> dict:
    rt = require_runtime(client, args.runtime_name)
    moved = point_endpoint(client, rt["agentRuntimeId"], args.endpoint, str(args.version), args.note, sleep=sleep)
    return {
        "runtime_arn": rt["agentRuntimeArn"],
        "runtime_version": moved["version"],
        "endpoint": args.endpoint,
        "previous_version": moved["previous_version"],
    }


def cmd_rollback(client, args, sleep=time.sleep) -> dict:
    rt = require_runtime(client, args.runtime_name)
    current = get_endpoint(client, rt["agentRuntimeId"], args.endpoint)
    if current is None:
        raise SystemExit(f"endpoint '{args.endpoint}' does not exist")
    target = args.to_version
    if not target:
        match = _PREV_RE.search(current.get("description") or "")
        if not match:
            raise SystemExit("no previous version recorded on the endpoint; pass --to-version")
        target = match.group(1)
    log(f"ROLLBACK {args.endpoint}: v{current.get('liveVersion')} -> v{target}")
    moved = point_endpoint(client, rt["agentRuntimeId"], args.endpoint, str(target), "rollback", sleep=sleep)
    return {
        "runtime_arn": rt["agentRuntimeArn"],
        "endpoint": args.endpoint,
        "runtime_version": moved["version"],
        "rolled_back_from": current.get("liveVersion"),
    }


def cmd_status(client, args, sleep=time.sleep) -> dict:
    rt = require_runtime(client, args.runtime_name)
    eps = client.list_agent_runtime_endpoints(agentRuntimeId=rt["agentRuntimeId"]).get("runtimeEndpoints", [])
    return {
        "runtime_arn": rt["agentRuntimeArn"],
        "latest_version": rt["agentRuntimeVersion"],
        "endpoints": json.dumps({e["name"]: e.get("liveVersion") for e in eps}),
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--region", default=os.getenv("AWS_REGION"))
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("deploy")
    d.add_argument("--runtime-name", required=True)
    d.add_argument("--image-uri", required=True)
    d.add_argument("--role-arn", required=True, help="AgentCore execution role (Bedrock, ECR, logs, secrets)")
    d.add_argument("--endpoint", help="endpoint to point at the new version, e.g. staging")
    d.add_argument("--env", action="append", default=[], metavar="KEY=VALUE")
    d.add_argument("--note", default="", help="recorded in endpoint description, e.g. sha=abc123")
    d.add_argument("--jwt-discovery-url")
    d.add_argument("--jwt-client-id", action="append")
    d.add_argument("--jwt-audience", action="append")

    pr = sub.add_parser("promote")
    pr.add_argument("--runtime-name", required=True)
    pr.add_argument("--endpoint", required=True)
    pr.add_argument("--version", required=True)
    pr.add_argument("--note", default="")

    rb = sub.add_parser("rollback")
    rb.add_argument("--runtime-name", required=True)
    rb.add_argument("--endpoint", required=True)
    rb.add_argument("--to-version")

    st = sub.add_parser("status")
    st.add_argument("--runtime-name", required=True)
    return p


COMMANDS = {"deploy": cmd_deploy, "promote": cmd_promote, "rollback": cmd_rollback, "status": cmd_status}


def main(argv: list[str] | None = None, client=None) -> dict:
    args = build_parser().parse_args(argv)
    client = client or control_client(args.region)
    out = COMMANDS[args.command](client, args)
    write_outputs(out)
    return out


if __name__ == "__main__":
    main()
