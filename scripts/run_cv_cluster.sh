#!/usr/bin/env bash
set -euo pipefail

n="${1:-4}"
f="${2:-1}"
if (( $# >= 3 )); then
  root="$3"
else
  root="$(mktemp -d "/tmp/arladkr-cv-n${n}.XXXXXX")"
fi
base_port="${4:-20000}"
epoch_timeout="${RLADKR_CV_EPOCH_TIMEOUT:-90s}"
runner_timeout="${RLADKR_CV_RUNNER_TIMEOUT:-$epoch_timeout}"
runner_timeout_explicit="${RLADKR_CV_RUNNER_TIMEOUT:-}"
wait_spbc_timeout="${RLADKR_CV_WAIT_SPBC_TIMEOUT:-}"
# The shared-host harness can finish honest nodes several seconds apart under
# CPU contention. A one-second route timeout selects the existing ten-second
# holder-service grace; reported latency already excludes that grace.
route_send_timeout="${RLADKR_CV_ROUTE_SEND_TIMEOUT:-1s}"
apvss_mode="${RLADKR_APVSS_MODE:-ack-fallback}"
apvss_full_proof_profile="${RLADKR_APVSS_FULL_PROOF_PROFILE:-exact}"
apvss_fallback_profile="${RLADKR_APVSS_FALLBACK_PROFILE:-feldman-batch-v1}"
allow_experimental_apvss="${RLADKR_ALLOW_EXPERIMENTAL_APVSS:-false}"
apvss_forced_fallback_count="${RLADKR_APVSS_FORCED_FALLBACK_COUNT:-0}"
apvss_wait_all_acks="${RLADKR_APVSS_WAIT_ALL_ACKS:-false}"
epochs="${RLADKR_CV_EPOCHS:-1}"
epoch_id="${RLADKR_CV_EPOCH_ID:-1}"
# Formal paper runs must pass an explicit sampling target; smoke keeps the
# historical flow-verification default.
cv_failure_target="${RLADKR_CV_FAILURE_TARGET:-smoke}"
runs="${RLADKR_CV_RUNS:-1}"
# All n node processes share one host in this harness. Keep the default at one
# crypto worker per process so the benchmark does not oversubscribe the host;
# callers can still set RLADKR_CRYPTO_WORKERS explicitly.
crypto_workers="${RLADKR_CRYPTO_WORKERS:-1}"
# ACK decryption has its own bounded queue. Two workers per process use the
# 32 logical CPUs of the n=16 local harness without widening proof workers.
lane_workers="${RLADKR_LANE_WORKERS:-2}"
# The local harness starts every logical node and collects every artifact.
# Let the independent MVBA listeners rendezvous as a full local fleet before
# starting agreement; this is a harness synchronization rule, not a protocol
# quorum change. AWS runners keep their existing n-f readiness behavior.
mvba_peer_wait_target="${RLADKR_MVBA_PEER_WAIT_TARGET:-all}"
mvba_peer_wait_ms="${RLADKR_MVBA_PEER_WAIT_MS:-5000}"
setup_batch_size="${RLADKR_CV_SETUP_BATCH_SIZE:-16}"
setup_ready_timeout="${RLADKR_CV_SETUP_READY_TIMEOUT:-900s}"
# Divide a shared host's logical CPUs across its n node processes. The n=16
# harness benefits measurably from its second SMT worker for curve-heavy leaf
# verification. On a real one-process-per-host deployment the runtime default
# instead reserves one scheduler slot and caps leaf verification at four.
host_cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')"
if [[ -n "${RLADKR_LEAF_VERIFY_WORKERS:-}" ]]; then
  leaf_verify_workers="$RLADKR_LEAF_VERIFY_WORKERS"
else
  leaf_verify_workers=$((host_cpus / n))
  (( leaf_verify_workers < 1 )) && leaf_verify_workers=1
  (( leaf_verify_workers > 4 )) && leaf_verify_workers=4
fi
# Partition the shared host scheduler budget across logical node processes.
# Without this, every process sees the full machine and local n=10 runs can
# create hundreds of runnable Go threads, which obscures protocol latency.
if [[ -n "${RLADKR_CV_GOMAXPROCS:-}" ]]; then
  node_gomaxprocs="$RLADKR_CV_GOMAXPROCS"
else
  node_gomaxprocs=$((host_cpus / n))
  (( node_gomaxprocs < 1 )) && node_gomaxprocs=1
fi
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="$repo_dir/bin/rladkrbench"
summary_awk="$repo_dir/scripts/summarize_cluster_bench.awk"
public_dir="$root/keys/public"
generated_secret_dir="$root/keys/generated-private"
log_dir="$root/logs"
results_file="$root/cluster-results.log"

if (( n <= 0 || f < 0 || n < 3 * f + 1 || epochs <= 0 || epoch_id <= 0 || runs <= 0 || setup_batch_size <= 0 )); then
  printf 'invalid committee parameters: n=%s f=%s\n' "$n" "$f" >&2
  exit 2
fi
required_nodes=$((n - f))
# This harness launches every node on one host and expects to collect every
# artifact. Wait for all listener processes by default so CPU startup skew
# cannot make a late node miss one-shot protocol messages. Protocol success
# and the final cluster summary still require only n-f completed nodes.
listener_ready_count="${RLADKR_CV_LISTENER_READY_COUNT:-$n}"
if (( listener_ready_count < required_nodes || listener_ready_count > n )); then
  printf 'invalid listener-ready count: got=%s require=%s..%s\n' \
    "$listener_ready_count" "$required_nodes" "$n" >&2
  exit 2
fi
if ! command -v timeout >/dev/null 2>&1; then
  printf 'cluster runner requires the timeout command for child-process cleanup\n' >&2
  exit 2
fi
if (( epochs != 1 || runs != 1 )); then
  printf 'CV V2 cluster experiment supports exactly one fresh run and one epoch; key rotation and incomplete-epoch resume are unsupported\n' >&2
  exit 2
fi
component_last_port=$((base_port + 2 * n - 1))
mvba_base_port=$((base_port + 2 * n + 100))
mvba_last_port=$((mvba_base_port + n - 1))
if (( base_port <= 0 || mvba_last_port > 65535 )); then
  printf 'invalid cluster port ranges: component=%s-%s mvba=%s-%s\n' \
    "$base_port" "$component_last_port" "$mvba_base_port" "$mvba_last_port" >&2
  exit 2
fi
read -r ephemeral_low ephemeral_high < /proc/sys/net/ipv4/ip_local_port_range
if (( (base_port <= ephemeral_high && component_last_port >= ephemeral_low) ||
      (mvba_base_port <= ephemeral_high && mvba_last_port >= ephemeral_low) )); then
  printf 'cluster listener range overlaps ephemeral ports %s-%s: component=%s-%s mvba=%s-%s\n' \
    "$ephemeral_low" "$ephemeral_high" "$base_port" "$component_last_port" \
    "$mvba_base_port" "$mvba_last_port" >&2
  exit 2
fi
if [[ -d "$root" && -n "$(find "$root" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
  printf 'run directory must be empty to avoid stale keys, readiness markers, and shards: %s\n' "$root" >&2
  exit 2
fi

mkdir -p "$repo_dir/bin" "$public_dir" "$generated_secret_dir" "$root/ready" "$root/setup-ready" "$log_dir"
mkdir -p "$root/epoch-barrier"
touch "$results_file"
bench_timeout_args=()
if [[ -n "$wait_spbc_timeout" ]]; then
  bench_timeout_args+=( -wait-spbc-timeout "$wait_spbc_timeout" )
fi
if [[ -n "$route_send_timeout" ]]; then
  bench_timeout_args+=( -route-send-timeout "$route_send_timeout" )
fi
(cd "$repo_dir" && go build -buildvcs=false -o "$binary" ./cmd/rladkrbench)
"$binary" -n "$n" -f "$f" -runs 1 -epoch "$epoch_id" -cv-keygen-only \
  -cv-public-key-dir "$public_dir" -cv-local-secret-dir "$generated_secret_dir"

for ((i=0; i<n; i++)); do
  node_secret_dir="$root/node-$i/private"
  mkdir -p "$node_secret_dir"
  chmod 700 "$node_secret_dir"
  mv "$generated_secret_dir/old-node-$i-validator.scalar" "$node_secret_dir/"
  mv "$generated_secret_dir/old-node-$i-v2-apdb.scalar" "$node_secret_dir/"
  mv "$generated_secret_dir/old-node-$i-v2-control.scalar" "$node_secret_dir/"
  mv "$generated_secret_dir/old-node-$i-v2-coin.scalar" "$node_secret_dir/"
  mv "$generated_secret_dir/receiver-$((n+i))-elgamal.scalar" "$node_secret_dir/"
  mv "$generated_secret_dir/receiver-$((n+i))-identity.ed25519" "$node_secret_dir/"
done
rmdir "$generated_secret_dir"

node_addrs=""
mvba_addrs=""
for ((i=0; i<n; i++)); do
  [[ -z "$node_addrs" ]] || node_addrs+=","
  [[ -z "$mvba_addrs" ]] || mvba_addrs+=","
  node_addrs+="$i=127.0.0.1:$((base_port+i))"
  mvba_addrs+="$i=127.0.0.1:$((mvba_base_port+i))"
done

printf 'ARLADKR_CV_PORTS component=%s-%s mvba=%s-%s ephemeral=%s-%s\n' \
  "$base_port" "$component_last_port" "$mvba_base_port" "$mvba_last_port" \
  "$ephemeral_low" "$ephemeral_high"

# Give larger setup batches time to finish before the synchronized protocol start.
start_delay=30
if (( n >= 96 )); then
  start_delay=120
  if [[ -z "$runner_timeout_explicit" ]]; then
    runner_timeout=1200s
  fi
fi
start_at="$(( $(date +%s) + start_delay ))"
pids=()
terminate_tree() {
  local pid="$1"
  local child
  while read -r child; do
    [[ -n "$child" ]] || continue
    terminate_tree "$child"
  done < <(pgrep -P "$pid" 2>/dev/null || true)
  kill "$pid" 2>/dev/null || true
}
cleanup_children() {
  for pid in "${pids[@]:-}"; do
    if kill -0 "$pid" 2>/dev/null; then
      terminate_tree "$pid"
    fi
  done
}
handle_signal() {
  cleanup_children
  exit 130
}
trap handle_signal INT TERM
trap cleanup_children EXIT
for ((i=0; i<n; i++)); do
  mkdir -p "$root/node-$i/store"
  node_secret_dir="$root/node-$i/private"
  log="$log_dir/node-$i.log"
  (
    export RLADKR_LOCAL_NODE_IDS="$i"
    export RLADKR_LOCAL_RECEIVER_IDS="$((n+i))"
    export RLADKR_NODE_ADDRS="$node_addrs"
    export RLADKR_MVBA_NODE_ADDRS="$mvba_addrs"
    export RLADKR_ARTIFACT_CACHE_DIR="$root/node-$i/store"
    export RLADKR_LISTENER_READY_DIR="$root/ready"
    export RLADKR_LISTENER_READY_NODE_COUNT="$listener_ready_count"
    export RLADKR_EPOCH_BARRIER_DIR="$root/epoch-barrier"
    export RLADKR_SETUP_READY_DIR="$root/setup-ready"
    export RLADKR_CV_DEBUG="${RLADKR_CV_DEBUG:-1}"
    export RLADKR_CV_PERF_COUNTERS="${RLADKR_CV_PERF_COUNTERS:-1}"
    export RLADKR_CRYPTO_WORKERS="$crypto_workers"
    export RLADKR_LANE_WORKERS="$lane_workers"
    export RLADKR_LEAF_VERIFY_WORKERS="$leaf_verify_workers"
    export GOMAXPROCS="$node_gomaxprocs"
    export RLADKR_MVBA_PEER_WAIT_TARGET="$mvba_peer_wait_target"
    export RLADKR_MVBA_PEER_WAIT_MS="$mvba_peer_wait_ms"
    if timeout --foreground --kill-after=5s "$runner_timeout" "$binary" -n "$n" -f "$f" -runs "$runs" -epochs "$epochs" -epoch "$epoch_id" \
      -transport tcp-distributed -cv-failure-target "$cv_failure_target" \
      -bind-host 127.0.0.1 -base-port "$base_port" -start-at "$start_at" -timeout "$epoch_timeout" \
			"${bench_timeout_args[@]}" \
		-apvss-mode "$apvss_mode" \
      -apvss-full-proof-profile "$apvss_full_proof_profile" \
      -apvss-fallback-profile "$apvss_fallback_profile" \
      -allow-experimental-apvss="$allow_experimental_apvss" \
      -apvss-forced-fallback-count "$apvss_forced_fallback_count" \
      -apvss-wait-all-acks="$apvss_wait_all_acks" \
      -comm-metrics=true -strict-network=true \
      -cv-public-key-dir "$public_dir" -cv-local-secret-dir "$node_secret_dir" \
      -cv-local-receiver-ids "$((n+i))"; then
      child_status=0
    else
      child_status=$?
    fi
    result="$(rg '^E2E_BENCH_RESULT ' "$log" | tail -n 1 || true)"
    if (( child_status != 0 )); then
      printf 'NODE_%s_RUNNER_ERROR status=%s\n' "$i" "$child_status" >&2
      exit "$child_status"
    fi
    if [[ "$result" != *"success_runs=1"* ]]; then
      printf 'NODE_%s_RUNNER_ERROR missing successful benchmark result\n' "$i" >&2
      exit 1
    fi
  ) >"$log" 2>&1 &
  pids+=("$!")
  if (( (i + 1) % setup_batch_size == 0 || i + 1 == n )); then
    batch_start=$((i + 1 - (i % setup_batch_size)))
    deadline=$(( $(date +%s) + ${setup_ready_timeout%s} ))
    for ((j=batch_start; j<=i; j++)); do
      marker="$root/setup-ready/node-$(printf '%06d' "$j").ready"
      while [[ ! -f "$marker" ]]; do
        if (( $(date +%s) >= deadline )); then
          printf 'SETUP_READY_TIMEOUT batch=%s-%s node=%s\n' "$batch_start" "$i" "$j" >&2
          exit 1
        fi
        sleep 1
      done
    done
  fi
done

status=0
successful_children=0
remaining=("${pids[@]}")
while ((${#remaining[@]} > 0)); do
  finished_pid=""
  if wait -n -p finished_pid "${remaining[@]}"; then
    child_status=0
  else
    child_status=$?
  fi
  next=()
  for pid in "${remaining[@]}"; do
    [[ "$pid" == "$finished_pid" ]] || next+=("$pid")
  done
  remaining=("${next[@]}")

  if (( child_status == 0 )); then
    successful_children=$((successful_children + 1))
  fi
  if (( successful_children >= required_nodes )); then
    # A successful benchmark result is emitted only after the node has
    # completed its protocol run. Once n-f such results exist, quorum is
    # satisfied and waiting for additional nodes would skew collection time
    # without changing the success decision.
    cleanup_children
    for pid in "${remaining[@]}"; do
      wait "$pid" 2>/dev/null || true
    done
    remaining=()
    status=0
    break
  fi
done
pids=()

if (( successful_children < required_nodes )); then
  status=1
fi

printf 'ARLADKR_CV_RUN_DIR=%s\n' "$root"
printf 'ARLADKR_CV_LOG_DIR=%s\n' "$log_dir"
for ((i=0; i<n; i++)); do
  log="$log_dir/node-$i.log"
  result="$(rg '^E2E_BENCH_RESULT ' "$log" | tail -n 1 || true)"
  if [[ -n "$result" ]]; then
    printf '%s\n' "$result" >>"$results_file"
    printf 'NODE_%s %s\n' "$i" "$result"
  else
    printf 'NODE_%s NO_RESULT\n' "$i"
    tail -n 12 "$log" >&2 || true
  fi
done
awk -v protocol=ARLADKR-GO -v expected_nodes="$n" -v faults="$f" \
  -f "$summary_awk" "$results_file"
exit "$status"
