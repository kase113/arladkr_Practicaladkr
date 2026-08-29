#!/usr/bin/env bash
set -euo pipefail

n="${1:-16}"
f="${2:-5}"
epoch_count="${3:-3}"
if (( $# >= 4 )); then
  series_root="$4"
else
  series_root="$(mktemp -d "/tmp/arladkr-cv-series-n${n}.XXXXXX")"
fi
base_port="${5:-22000}"
port_stride="${RLADKR_CV_SERIES_PORT_STRIDE:-$((2*n + 256))}"

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cluster_runner="${RLADKR_CV_CLUSTER_RUNNER:-$repo_dir/scripts/run_cv_cluster.sh}"
failure_target="${RLADKR_CV_FAILURE_TARGET:-original}"
keep_artifacts="${RLADKR_CV_SERIES_KEEP_ARTIFACTS:-false}"
keep_failed_artifacts="${RLADKR_CV_SERIES_KEEP_FAILED_ARTIFACTS:-true}"
stop_on_failure="${RLADKR_CV_SERIES_STOP_ON_FAILURE:-true}"

validate_bool() {
  case "$1" in
    true|false) ;;
    *) printf 'expected true or false, got %s\n' "$1" >&2; exit 2 ;;
  esac
}

validate_bool "$keep_artifacts"
validate_bool "$keep_failed_artifacts"
validate_bool "$stop_on_failure"
if (( n <= 0 || f < 0 || n < 3 * f + 1 || epoch_count <= 0 || base_port <= 0 || port_stride <= 0 )); then
  printf 'invalid series parameters: n=%s f=%s epochs=%s base_port=%s\n' \
    "$n" "$f" "$epoch_count" "$base_port" >&2
  exit 2
fi
if [[ ! -x "$cluster_runner" ]]; then
  printf 'cluster runner is not executable: %s\n' "$cluster_runner" >&2
  exit 2
fi
if [[ -d "$series_root" && -n "$(find "$series_root" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
  printf 'series directory must be empty: %s\n' "$series_root" >&2
  exit 2
fi

mkdir -p "$series_root/logs" "$series_root/runs"
results_file="$series_root/epoch-results.log"
: >"$results_file"

attempted=0
successful=0
series_status=0
for ((epoch=1; epoch<=epoch_count; epoch++)); do
  attempted=$((attempted + 1))
  epoch_name="epoch-$(printf '%06d' "$epoch")"
  run_dir="$series_root/runs/$epoch_name"
  epoch_log="$series_root/logs/$epoch_name.log"
  epoch_port=$((base_port + (epoch - 1) * port_stride))
  printf 'ARLADKR_EPOCH_SERIES_START epoch=%s/%s base_port=%s run_dir=%s\n' "$epoch" "$epoch_count" "$epoch_port" "$run_dir"

  set +e
  RLADKR_CV_EPOCH_ID="$epoch" RLADKR_CV_FAILURE_TARGET="$failure_target" \
    "$cluster_runner" "$n" "$f" "$run_dir" "$epoch_port" 2>&1 | tee "$epoch_log"
  epoch_status=${PIPESTATUS[0]}
  set -e

  summary="$(rg '^CLUSTER_BENCH_RESULT ' "$epoch_log" | tail -n 1 || true)"
  if (( epoch_status == 0 )) && [[ "$summary" == *" quorum_success=1 "* ]]; then
    successful=$((successful + 1))
    printf 'SERIES_EPOCH_RESULT epoch=%s status=success %s\n' "$epoch" "$summary" >>"$results_file"
  else
    series_status=1
    printf 'SERIES_EPOCH_RESULT epoch=%s status=failed runner_status=%s %s\n' \
      "$epoch" "$epoch_status" "$summary" >>"$results_file"
  fi

  if [[ "$keep_artifacts" == false ]] &&
    { (( epoch_status == 0 )) || [[ "$keep_failed_artifacts" == false ]]; }; then
    rm -rf "$run_dir"
  fi
  if (( epoch_status != 0 )) && [[ "$stop_on_failure" == true ]]; then
    break
  fi
done

awk -v requested="$epoch_count" -v attempted="$attempted" '
  function field(name,    i, pair) {
    for (i = 1; i <= NF; i++) {
      split($i, pair, "=")
      if (pair[1] == name) return pair[2]
    }
    return 0
  }
  /^SERIES_EPOCH_RESULT / {
    if (field("status") != "success") next
    success++
    latency += field("quorum_latency_ms")
    online += field("quorum_online_latency_ms")
    sent += field("quorum_mean_sent_bytes_per_node")
  }
  END {
    if (success > 0) {
      latency /= success
      online /= success
      sent /= success
    }
    printf "ARLADKR_EPOCH_SERIES_RESULT requested_epochs=%d attempted_epochs=%d successful_epochs=%d success_rate=%.4f mean_quorum_latency_ms=%.2f mean_quorum_online_latency_ms=%.2f mean_quorum_sent_bytes_per_node=%.0f\n", requested, attempted, success, success/requested, latency, online, sent
  }
' "$results_file"
printf 'ARLADKR_EPOCH_SERIES_DIR=%s\n' "$series_root"

if (( successful != epoch_count )); then
  series_status=1
fi
exit "$series_status"
