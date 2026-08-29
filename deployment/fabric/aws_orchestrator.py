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
            try:
                item = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
            except Exception as exc:
                code = str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))
                if code == "InvocationDoesNotExist":
                    pending = True
                    continue
                raise
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


def collect_summary_when_success(
    region: str, instance_ids: list[str], project: str, run_id: str, quorum: int,
    timeout: int = 180, poll_interval: int = 2,
) -> dict[str, Any]:
    """Collect independently and stop once a quorum of successful nodes exists."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", project) or not re.fullmatch(r"[A-Za-z0-9_.-]+", run_id):
        raise ValueError("project and run_id must contain only safe filename characters")
    if not instance_ids or not 1 <= quorum <= len(instance_ids):
        raise ValueError("quorum must be between 1 and the number of instances")
    if timeout <= 0 or poll_interval <= 0:
        raise ValueError("timeout and poll_interval must be positive")
    artifact = f"/var/lib/rladkr/artifacts/{project}"
    status = f"{artifact}.status.{run_id}"
    bench = f"{artifact}.bench.{run_id}.txt"
    command = (
        f"deadline=$((SECONDS+{int(timeout)})); "
        f"while [ ! -f {status} ] || [ \"$(sudo tail -n 1 {status} 2>/dev/null || true)\" != success ]; do "
        f"[ $SECONDS -ge $deadline ] && exit 124; sleep {int(poll_interval)}; done; "
        f"printf 'RLADKR_FILE_BEGIN:bench\\n'; sudo cat {bench} 2>/dev/null || true; "
        f"printf '\\nRLADKR_FILE_END:bench\\n'; printf 'RLADKR_FILE_BEGIN:status\\n'; "
        f"sudo tail -n 1 {status}; printf '\\nRLADKR_FILE_END:status\\n'"
    )
    # A single multi-instance command cannot return early: SSM waits for every
    # invocation.  Send one command per node so slow or dead outliers can be
    # cancelled after quorum is reached.
    _, ssm = _boto3(region)
    commands = {
        instance_id: ssm_run(region, [instance_id], command, min(timeout, 3600))["command_id"]
        for instance_id in instance_ids
    }
    deadline = time.monotonic() + timeout
    results: dict[str, Any] = {}
    terminal = {"Success", "Cancelled", "TimedOut", "Failed", "Cancelling", "Undeliverable", "Terminated"}
    while time.monotonic() < deadline:
        successful = 0
        pending_ids: list[str] = []
        for instance_id, command_id in commands.items():
            if instance_id in results and results[instance_id]["status"] in terminal:
                if results[instance_id]["status"] == "Success":
                    status_text = _file_content(results[instance_id]["stdout"], "status")
                    successful += status_text.splitlines()[-1:] == ["success"]
                continue
            try:
                item = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
            except Exception as exc:
                code = str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))
                if code == "InvocationDoesNotExist":
                    pending_ids.append(instance_id)
                    continue
                raise
            status_value = item.get("Status", "Unknown")
            results[instance_id] = {
                "status": status_value,
                "stdout": item.get("StandardOutputContent", ""),
                "stderr": item.get("StandardErrorContent", ""),
            }
            if status_value == "Success":
                status_text = _file_content(results[instance_id]["stdout"], "status")
                successful += status_text.splitlines()[-1:] == ["success"]
            elif status_value not in terminal:
                pending_ids.append(instance_id)
        if successful >= quorum:
            for instance_id, command_id in commands.items():
                if instance_id not in results or results[instance_id]["status"] not in terminal:
                    try:
                        ssm.cancel_command(CommandId=command_id)
                    except Exception:
                        pass
            return {"commands": commands, "results": results, "quorum": quorum}
        # If all remaining invocations failed, waiting cannot reach quorum.
        failed = sum(
            1 for value in results.values()
            if value.get("status") in terminal and value.get("status") != "Success"
        )
        if len(instance_ids) - failed < quorum:
            break
        time.sleep(poll_interval)
    for instance_id, command_id in commands.items():
        if instance_id not in results or results[instance_id].get("status") not in terminal:
            try:
                ssm.cancel_command(CommandId=command_id)
            except Exception:
                pass
            results.setdefault(instance_id, {"status": "TimedOut", "stdout": "", "stderr": ""})
    return {"commands": commands, "results": results, "quorum": quorum}


def _file_content(output: str, name: str) -> str:
    match = re.search(
        rf"RLADKR_FILE_BEGIN:{re.escape(name)}\n(.*?)\nRLADKR_FILE_END:{re.escape(name)}",
        output,
        re.S,
    )
    return match.group(1).strip() if match else ""


def run_series(
    region: str,
    instance_ids: list[str],
    project: str,
    run_id_prefix: str,
    epochs: int,
    quorum: int,
    command_template: str,
    cleanup_template: str = "",
    timeout: int = 600,
    start_delay: int = 5,
    poll_interval: int = 2,
    stop_on_failure: bool = True,
) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", run_id_prefix):
        raise ValueError("run_id_prefix must contain only letters, digits, dot, underscore, or dash")
    if epochs <= 0 or not 1 <= quorum <= len(instance_ids):
        raise ValueError("epochs and quorum must be positive and quorum cannot exceed target count")
    if timeout <= 0 or start_delay < 0 or poll_interval <= 0:
        raise ValueError("invalid series timing")
    if not command_template.strip():
        raise ValueError("command_template is required")

    series: list[dict[str, Any]] = []
    for epoch in range(1, epochs + 1):
        run_id = f"{run_id_prefix}-epoch-{epoch:06d}"
        values = {"run_id": run_id, "epoch": epoch, "start_at": int(time.time()) + start_delay}
        launch_command = command_template.format(**values)
        launched = ssm_run(region, instance_ids, launch_command, min(timeout, 3600))
        launch_result = wait_ssm(
            region, launched["command_id"], instance_ids, min(timeout, 3600)
        )
        launch_ok = sorted(
            instance_id
            for instance_id, result in launch_result["results"].items()
            if result["status"] == "Success"
        )
        record: dict[str, Any] = {
            "epoch": epoch,
            "run_id": run_id,
            "start_at": values["start_at"],
            "launched": launch_ok,
            "successful": [],
            "quorum_success": False,
        }
        if len(launch_ok) >= quorum:
            collected = collect_summary_when_success(
                region, launch_ok, project, run_id, quorum, timeout, poll_interval
            )
            successful = []
            bench: dict[str, str] = {}
            for instance_id, result in collected["results"].items():
                if result["status"] != "Success":
                    continue
                status = _file_content(result["stdout"], "status")
                if status.splitlines()[-1:] != ["success"]:
                    continue
                successful.append(instance_id)
                bench[instance_id] = _file_content(result["stdout"], "bench")
            if len(successful) >= quorum:
                successful.sort()
                selected = successful[:quorum]
                record["successful"] = selected
                record["bench"] = {instance_id: bench[instance_id] for instance_id in selected}
                record["quorum_success"] = True
        if cleanup_template.strip():
            cleanup = ssm_run(
                region,
                launch_ok or instance_ids,
                cleanup_template.format(**values),
                min(timeout, 3600),
            )
            wait_ssm(region, cleanup["command_id"], launch_ok or instance_ids, min(timeout, 3600))
        series.append(record)
        if not record["quorum_success"] and stop_on_failure:
            break
    return {
        "project": project,
        "requested_epochs": epochs,
        "attempted_epochs": len(series),
        "successful_epochs": sum(bool(item["quorum_success"]) for item in series),
        "epochs": series,
    }


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
    series = sub.add_parser("series")
    series.add_argument("--instance-id", action="append", required=True)
    series.add_argument("--project", required=True)
    series.add_argument("--run-id-prefix", required=True)
    series.add_argument("--epochs", type=int, required=True)
    series.add_argument("--quorum", type=int, required=True)
    series.add_argument("--command-template", required=True)
    series.add_argument("--cleanup-template", default="")
    series.add_argument("--timeout", type=int, default=600)
    series.add_argument("--start-delay", type=int, default=5)
    series.add_argument("--poll-interval", type=int, default=2)
    series.add_argument("--continue-on-failure", action="store_true")
    series.add_argument("--out", type=Path)
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
    if args.action == "series":
        result = run_series(
            args.region,
            args.instance_id,
            args.project,
            args.run_id_prefix,
            args.epochs,
            args.quorum,
            args.command_template,
            args.cleanup_template,
            args.timeout,
            args.start_delay,
            args.poll_interval,
            not args.continue_on_failure,
        )
        payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(payload, encoding="utf-8")
        print(payload, end="")
        return 0 if result["successful_epochs"] == result["requested_epochs"] else 1
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
