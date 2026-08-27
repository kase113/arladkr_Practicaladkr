#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
summary_awk="$repo_dir/scripts/summarize_cluster_bench.awk"
fixture="$(mktemp /tmp/arladkr-cluster-summary.XXXXXX)"
trap 'rm -f "$fixture"' EXIT

printf '%s\n' \
  'E2E_BENCH_RESULT runs=1 success_runs=1 mean_latency_ms=100 mean_all_latency_ms=100 mean_setup_ms=10 mean_total_sent_bytes=1000 mean_total_recv_bytes=2000 mean_arc_share_sent_bytes=10 consensus_hash=abc' \
  'E2E_BENCH_RESULT runs=1 success_runs=1 mean_latency_ms=120 mean_all_latency_ms=120 mean_setup_ms=20 mean_total_sent_bytes=1200 mean_total_recv_bytes=2200 mean_arc_share_sent_bytes=20 consensus_hash=abc' \
  'E2E_BENCH_RESULT runs=1 success_runs=1 mean_latency_ms=110 mean_all_latency_ms=110 mean_setup_ms=30 mean_total_sent_bytes=1400 mean_total_recv_bytes=2400 mean_arc_share_sent_bytes=30 consensus_hash=abc' \
  'E2E_BENCH_RESULT runs=1 success_runs=0 mean_latency_ms=0 mean_all_latency_ms=900 mean_setup_ms=0 mean_total_sent_bytes=0 mean_total_recv_bytes=0 consensus_hash=none' \
  >"$fixture"

result="$(awk -v protocol=TEST -v expected_nodes=4 -v faults=1 -f "$summary_awk" "$fixture")"
for token in \
  'result_nodes=4' \
  'successful_nodes=3' \
  'quorum=3' \
  'quorum_success=1' \
  'all_success=0' \
  'quorum_latency_ms=120.00' \
  'quorum_online_latency_ms=100.00' \
  'all_nodes_latency_ms=-1.00' \
  'mean_node_latency_ms=110.00' \
  'max_attempt_latency_ms=900.00' \
  'mean_setup_ms=20.00' \
  'mean_sent_bytes_per_node=1200' \
  'mean_recv_bytes_per_node=2200' \
  'quorum_mean_sent_bytes_per_node=1200' \
  'quorum_mean_recv_bytes_per_node=2200' \
  'total_protocol_sent_bytes=3600' \
  'total_arc_share_sent_bytes=60' \
  'quorum_protocol_sent_bytes=3600' \
  'quorum_arc_share_sent_bytes=60' \
  'arc_communication_nodes=3' \
  'arc_communication_share_valid=1' \
  'arc_communication_share_pct=1.666667' \
  'consensus_hashes=1'; do
  if [[ "$result" != *"$token"* ]]; then
    printf 'missing %s in summary:\n%s\n' "$token" "$result" >&2
    exit 1
  fi
done

printf 'cluster summary regression test passed\n'

outlier_fixture="$(mktemp /tmp/arladkr-cluster-summary-outlier.XXXXXX)"
trap 'rm -f "$fixture" "$outlier_fixture"' EXIT
printf '%s\n' \
  'E2E_BENCH_RESULT runs=1 success_runs=1 mean_latency_ms=100 mean_setup_ms=10 mean_total_sent_bytes=1000 mean_total_recv_bytes=2000 mean_arc_share_sent_bytes=10 consensus_hash=abc' \
  'E2E_BENCH_RESULT runs=1 success_runs=1 mean_latency_ms=120 mean_setup_ms=20 mean_total_sent_bytes=1200 mean_total_recv_bytes=2200 mean_arc_share_sent_bytes=20 consensus_hash=abc' \
  'E2E_BENCH_RESULT runs=1 success_runs=1 mean_latency_ms=110 mean_setup_ms=30 mean_total_sent_bytes=1400 mean_total_recv_bytes=2400 mean_arc_share_sent_bytes=30 consensus_hash=abc' \
  'E2E_BENCH_RESULT runs=1 success_runs=1 mean_latency_ms=1000 mean_setup_ms=40 mean_total_sent_bytes=9000 mean_total_recv_bytes=10000 mean_arc_share_sent_bytes=40 consensus_hash=abc' \
  >"$outlier_fixture"
outlier_result="$(awk -v protocol=TEST -v expected_nodes=4 -v faults=1 -f "$summary_awk" "$outlier_fixture")"
for token in \
  'quorum_mean_sent_bytes_per_node=1200' \
  'mean_sent_bytes_all_success=3150' \
  'quorum_protocol_sent_bytes=3600' \
  'arc_communication_share_pct=1.666667'; do
  if [[ "$outlier_result" != *"$token"* ]]; then
    printf 'missing quorum outlier token %s in summary:\n%s\n' "$token" "$outlier_result" >&2
    exit 1
  fi
done
printf 'cluster quorum summary regression test passed\n'
