# ARL-ADKR and PracticalADKR

Go implementations and benchmark runners for ARL-ADKR and PracticalADKR.

## Prerequisites

- Go 1.26+, Bash, GNU `timeout`, and `awk`
- A sibling `dumbomvba-go` checkout referenced by `go.mod`
- AWS benchmarks: Terraform, Python 3 with `boto3`, AWS CLI v2, and an authenticated profile

## Running and benchmarking locally

Run from this directory. Use a new, empty output directory for each run.

ARL-ADKR, one epoch:

```sh
RLADKR_CV_FAILURE_TARGET=original \
  scripts/run_cv_cluster.sh 16 5 /tmp/arladkr-run 22000
```

ARL-ADKR, serial epochs:

```sh
RLADKR_CV_FAILURE_TARGET=high-assurance \
  scripts/run_cv_epoch_series.sh 16 5 10 /tmp/arladkr-series 22000
```

PracticalADKR, one epoch:

```sh
PRACTICAL_MP_N=16 PRACTICAL_MP_F=5 PRACTICAL_MP_PORT_BASE=23000 \
PRACTICAL_MP_RUN_DIR=/tmp/practical-run \
  experiments/practical-adkr/scripts/run_practical_multiprocess_n7.sh
```

PracticalADKR, serial epochs:

```sh
experiments/practical-adkr/scripts/run_practical_epoch_series.sh \
  16 5 10 /tmp/practical-series 23000
```

Arguments are `n`, `f`, epoch count (series only), output directory, and base
TCP port. Results include quorum status, latency, consensus hash, and protocol
sent bytes per node.

## Running and benchmarking on AWS

The Terraform module is `deployment/terraform/aws-smoke`; it provisions Spot
instances and optional private SSM/S3 endpoints. Keep tfvars, state, keys, and
artifacts outside version control.

```sh
export AWS_PROFILE=<profile>
aws sso login --profile "$AWS_PROFILE"
terraform -chdir=deployment/terraform/aws-smoke init
terraform -chdir=deployment/terraform/aws-smoke validate
python3 -m deployment.fabric.aws_orchestrator \
  --experiment-group <run-tag> --var-file /path/to/run.tfvars \
  --state-dir "$PWD/deployment/aws-state/<run-tag>" plan
python3 -m deployment.fabric.aws_orchestrator \
  --experiment-group <run-tag> --var-file /path/to/run.tfvars \
  --state-dir "$PWD/deployment/aws-state/<run-tag>" apply
```

Use the Fabric facade for tagged status, explicit SSM commands, quorum-based
collection, serial epochs, and cleanup:

```sh
python3 -m deployment.fabric.aws_orchestrator --region <region> \
  --experiment-group <run-tag> status
python3 -m deployment.fabric.aws_orchestrator --region <region> \
  --experiment-group <run-tag> series \
  --instance-id i-EXAMPLE --project <project> --run-id-prefix <prefix> \
  --epochs 5 --quorum <n-f> \
  --command-template 'sudo /opt/runner/run-epoch --run-id {run_id} --epoch {epoch}' \
  --cleanup-template 'sudo /opt/runner/cleanup-epoch --run-id {run_id}' \
  --out /tmp/series.json
python3 -m deployment.fabric.aws_orchestrator --region <region> \
  --experiment-group <run-tag> cleanup --confirm-run-id <run-tag> --stop
```

Repeat `--instance-id` for all targets. Collection returns the first
deterministic quorum and cancels late SSM requests; full-fleet completion is not
required. Destroy Terraform resources separately after reviewing the state.
