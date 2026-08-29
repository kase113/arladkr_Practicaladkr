#!/usr/bin/env bash
set -euo pipefail

# Run fresh strict-TCP PracticalADKR epochs serially. Each epoch gets a new
# process, setup directory, local state directory and port namespace.
n="${1:-16}"
f="${2:-5}"
epoch_count="${3:-3}"
series_root="${4:-$(mktemp -d "/tmp/practical-adkr-series-n${n}.XXXXXX")}" 
base_port="${5:-23000}"
port_stride="${PRACTICAL_SERIES_PORT_STRIDE:-$((2*n + 256))}"
runner="${PRACTICAL_SERIES_RUNNER:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/run_practical_multiprocess_n7.sh}"
keep_artifacts="${PRACTICAL_SERIES_KEEP_ARTIFACTS:-false}"
keep_failed="${PRACTICAL_SERIES_KEEP_FAILED_ARTIFACTS:-true}"
stop_on_failure="${PRACTICAL_SERIES_STOP_ON_FAILURE:-true}"

for value in "$keep_artifacts" "$keep_failed" "$stop_on_failure"; do
  case "$value" in true|false) ;; *) echo "series artifact controls must be true or false" >&2; exit 2 ;; esac
done
if (( n <= 0 || f < 0 || n < 3*f+1 || epoch_count <= 0 || base_port <= 0 || port_stride <= 0 )); then
  echo "invalid series parameters" >&2; exit 2
fi
if [[ ! -x "$runner" ]]; then
  echo "Practical multiprocess runner is not executable: $runner" >&2; exit 2
fi
if [[ -d "$series_root" && -n "$(find "$series_root" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
  echo "series directory must be empty: $series_root" >&2; exit 2
fi
mkdir -p "$series_root/logs" "$series_root/runs"
results="$series_root/epoch-results.log"
: > "$results"

attempted=0
successful=0
status=0
for ((epoch=1; epoch<=epoch_count; epoch++)); do
  attempted=$((attempted+1))
  name="epoch-$(printf '%06d' "$epoch")"
  run_dir="$series_root/runs/$name"
  log="$series_root/logs/$name.log"
  port=$((base_port + (epoch-1)*port_stride))
  echo "PRACTICAL_EPOCH_SERIES_START epoch=$epoch/$epoch_count base_port=$port run_dir=$run_dir"
  set +e
  PRACTICAL_EPOCH_BASE="$epoch" PRACTICAL_MP_N="$n" PRACTICAL_MP_F="$f" \
    PRACTICAL_MP_PORT_BASE="$port" PRACTICAL_MP_RUNS=1 \
    PRACTICAL_MP_RUN_DIR="$run_dir" "$runner" > >(tee "$log") 2>&1
  runner_status=$?
  set -e
  summary="$(rg '^CLUSTER_BENCH_RESULT |^E2E_BENCH_RESULT ' "$log" | tail -n 1 || true)"
  if (( runner_status == 0 )); then
    successful=$((successful+1))
    printf 'SERIES_EPOCH_RESULT epoch=%d status=success %s\n' "$epoch" "$summary" >> "$results"
  else
    status=1
    printf 'SERIES_EPOCH_RESULT epoch=%d status=failed runner_status=%d %s\n' "$epoch" "$runner_status" "$summary" >> "$results"
  fi
  if [[ "$keep_artifacts" == false ]] && { (( runner_status == 0 )) || [[ "$keep_failed" == false ]]; }; then
    rm -rf -- "$run_dir"
  fi
  if (( runner_status != 0 )) && [[ "$stop_on_failure" == true ]]; then break; fi
done

rate="$(awk -v a="$successful" -v b="$epoch_count" 'BEGIN{print a/b}')"
printf 'PRACTICAL_EPOCH_SERIES_RESULT requested_epochs=%d attempted_epochs=%d successful_epochs=%d success_rate=%.4f\n' \
  "$epoch_count" "$attempted" "$successful" "$rate"
printf 'PRACTICAL_EPOCH_SERIES_DIR=%s\n' "$series_root"
(( successful == epoch_count )) || status=1
exit "$status"
