"""Small, explicit AWS orchestration facade for the Terraform smoke module.

This module deliberately has no AMI/snapshot or account-wide cleanup paths.
Every destructive action is scoped by the experiment tag and requires an
explicit run id confirmation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODULE = ROOT / "deployment" / "terraform" / "aws-smoke"


def _terraform(module: Path, args: Iterable[str], *, state_dir: Path | None = None) -> int:
    command = ["terraform", f"-chdir={module}"]
    command.extend(args)
    if state_dir is not None:
        state_dir.mkdir(parents=True, exist_ok=True)
        command.append(f"-state={state_dir / 'terraform.tfstate'}")
    return subprocess.call(command)


def terraform_action(module: Path, action: str, var_file: Path | None, state_dir: Path | None) -> int:
    if action not in {"plan", "apply"}:
        raise ValueError(f"unsupported terraform action: {action}")
    args = [action, "-input=false"]
    if action == "apply":
        args.append("-auto-approve")
    if var_file is not None:
        args.append(f"-var-file={var_file}")
    return _terraform(module, args, state_dir=state_dir)


def _boto3(region: str):
    try:
        import boto3  # type: ignore
    except ImportError as exc:
        raise RuntimeError("boto3 is required for AWS instance operations") from exc
    profile = os.environ.get("AWS_PROFILE", "")
    session = boto3.Session(profile_name=profile or None, region_name=region)
    return session.client("ec2"), session.client("ssm")


def instances(region: str, experiment_group: str) -> list[dict[str, Any]]:
    ec2, _ = _boto3(region)
    response = ec2.describe_instances(
        Filters=[
            {"Name": "tag:ExperimentGroup", "Values": [experiment_group]},
            {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]},
        ]
    )
    result = []
    for reservation in response.get("Reservations", []):
        for item in reservation.get("Instances", []):
            result.append(
                {
                    "instance_id": item.get("InstanceId", ""),
                    "state": item.get("State", {}).get("Name", ""),
                    "private_ip": item.get("PrivateIpAddress", ""),
                    "public_ip": item.get("PublicIpAddress", ""),
                    "spot": bool(item.get("InstanceLifecycle") == "spot"),
                }
            )
    return sorted(result, key=lambda value: value["instance_id"])


def ssm_run(region: str, instance_ids: list[str], command: str, timeout: int = 180) -> dict[str, Any]:
    if not instance_ids:
        raise ValueError("no instance ids supplied")
    if timeout <= 0 or timeout > 3600:
        raise ValueError("timeout must be between 1 and 3600 seconds")
    _, ssm = _boto3(region)
    sent = ssm.send_command(
        InstanceIds=instance_ids,
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": ["set -e", command]},
        TimeoutSeconds=timeout,
    )
    command_id = sent["Command"]["CommandId"]
    return {"command_id": command_id, "instance_ids": instance_ids, "timeout": timeout}


def wait_ssm(region: str, command_id: str, instance_ids: list[str], timeout: int) -> dict[str, Any]:
    _, ssm = _boto3(region)
    deadline = time.monotonic() + timeout
    result: dict[str, Any] = {}
    while time.monotonic() < deadline:
        pending = False
        for instance_id in instance_ids:
            item = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
            status = item.get("Status", "Unknown")
            if status in {"Pending", "InProgress", "Delayed"}:
                pending = True
            result[instance_id] = {
                "status": status,
                "stdout": item.get("StandardOutputContent", ""),
                "stderr": item.get("StandardErrorContent", ""),
            }
        if not pending:
            return {"command_id": command_id, "results": result}
        time.sleep(2)
    raise TimeoutError(f"SSM command {command_id} did not finish within {timeout}s")


def collect_summary(
    region: str, instance_ids: list[str], project: str, run_id: str, timeout: int = 180
) -> dict[str, Any]:
    if not project or not run_id or not re.fullmatch(r"[A-Za-z0-9_.-]+", project) or not re.fullmatch(r"[A-Za-z0-9_.-]+", run_id):
        raise ValueError("project and run_id are required")
    artifact = f"/var/lib/rladkr/artifacts/{project}"
    command = (
        "set -e; "
        f"printf 'RLADKR_FILE_BEGIN:bench\\n'; if sudo test -f {artifact}.bench.{run_id}.txt; "
        f"then sudo cat {artifact}.bench.{run_id}.txt; fi; printf '\\nRLADKR_FILE_END:bench\\n'; "
        f"printf 'RLADKR_FILE_BEGIN:status\\n'; if sudo test -f {artifact}.status.{run_id}; "
        f"then sudo cat {artifact}.status.{run_id}; fi; printf '\\nRLADKR_FILE_END:status\\n'"
    )
    sent = ssm_run(region, instance_ids, command, timeout)
    return wait_ssm(region, sent["command_id"], instance_ids, timeout)


def stop_instances(region: str, experiment_group: str) -> dict[str, Any]:
    ec2, _ = _boto3(region)
    items = instances(region, experiment_group)
    ids = [item["instance_id"] for item in items if item["state"] in {"pending", "running"}]
    if ids:
        ec2.stop_instances(InstanceIds=ids)
    return {"stopped": ids, "experiment_group": experiment_group}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    parser.add_argument("--experiment-group", required=True)
    parser.add_argument("--module", type=Path, default=DEFAULT_MODULE)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--var-file", type=Path)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("plan", "apply"):
        sub.add_parser(action)
    sub.add_parser("status")
    command = sub.add_parser("ssm")
    command.add_argument("--instance-id", action="append", required=True)
    command.add_argument("--command", required=True)
    command.add_argument("--timeout", type=int, default=180)
    collect = sub.add_parser("collect")
    collect.add_argument("--instance-id", action="append", required=True)
    collect.add_argument("--project", required=True)
    collect.add_argument("--run-id", required=True)
    collect.add_argument("--timeout", type=int, default=180)
    cleanup = sub.add_parser("cleanup")
    cleanup.add_argument("--confirm-run-id", required=True)
    cleanup.add_argument("--stop", action="store_true", help="stop matching running instances")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.action in {"plan", "apply"}:
        return terraform_action(args.module.resolve(), args.action, args.var_file, args.state_dir)
    if args.action == "status":
        print(json.dumps(instances(args.region, args.experiment_group), indent=2, sort_keys=True))
        return 0
    if args.action == "ssm":
        sent = ssm_run(args.region, args.instance_id, args.command, args.timeout)
        print(json.dumps(wait_ssm(args.region, sent["command_id"], args.instance_id, args.timeout), sort_keys=True))
        return 0
    if args.action == "collect":
        print(json.dumps(collect_summary(args.region, args.instance_id, args.project, args.run_id, args.timeout), sort_keys=True))
        return 0
    if args.confirm_run_id != args.experiment_group:
        raise SystemExit("cleanup confirmation must exactly match --experiment-group")
    # Cleanup intentionally stops at inventory. Resource destruction remains a
    # separate, reviewed Terraform command and is never implicit here.
    result: dict[str, Any] = {"cleanup": "inventory-only", "experiment_group": args.experiment_group}
    if args.stop:
        result = stop_instances(args.region, args.experiment_group)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
