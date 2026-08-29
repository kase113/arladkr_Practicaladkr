#!/usr/bin/env bash
set -euo pipefail

# Run one strict-TCP PracticalADKR process per old-committee node.
# Trusted setup is generated once before timing. Each process receives the
# common public bundle and only its own signing, decryption, and coin shares.

# Override these values for a matched committee experiment, e.g. n=16/f=5/kappa=6.
N="${PRACTICAL_MP_N:-7}"
F="${PRACTICAL_MP_F:-2}"
KAPPA="${PRACTICAL_MP_KAPPA:-3}"
PORT_BASE="${PRACTICAL_MP_PORT_BASE:-23000}"
MVBA_PORT_BASE="${PRACTICAL_MP_MVBA_PORT_BASE:-${PORT_BASE}}"
PROTO_PORT_BASE="${PRACTICAL_MP_PROTO_PORT_BASE:-$((PORT_BASE + 1000))}"
COIN_PORT_BASE="${PRACTICAL_MP_COIN_PORT_BASE:-$((PORT_BASE - 5000))}"
COMP_PORT_BASE="${PRACTICAL_MP_COMP_PORT_BASE:-$((PORT_BASE - 12000))}"
PARTIAL_PORT_BASE="${PRACTICAL_MP_PARTIAL_PORT_BASE:-$((PORT_BASE - 9000))}"
if (( MVBA_PORT_BASE <= 0 || PROTO_PORT_BASE <= 0 || COIN_PORT_BASE <= 0 || COMP_PORT_BASE <= 0 || PARTIAL_PORT_BASE <= 0 )); then
  printf 'invalid port base configuration\n' >&2
  exit 2
fi
if (( N <= 0 || F < 0 || KAPPA <= 0 || KAPPA > 2 * F + 1 || N < 3 * F + 1 )); then
  printf 'invalid committee parameters: n=%s f=%s kappa=%s\n' "${N}" "${F}" "${KAPPA}" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_dir_template="/tmp/practical-adkr-mp-n${N}.XXXXXX"
RUN_DIR="${PRACTICAL_MP_RUN_DIR:-$(mktemp -d "${run_dir_template}")}"
SETUP_DIR="${RUN_DIR}/setup"
LOG_DIR="${RUN_DIR}/logs"
BIN="${ROOT_DIR}/bin/bench_latency"
SUMMARY_AWK="${ROOT_DIR}/../../scripts/summarize_cluster_bench.awk"
if [[ ! -f "${SUMMARY_AWK}" ]]; then
  SUMMARY_AWK="$(cd "${ROOT_DIR}/../../../scripts" && pwd)/summarize_cluster_bench.awk"
fi
RESULTS_FILE="${RUN_DIR}/cluster-results.log"
if [[ -d "${RUN_DIR}" && -n "$(find "${RUN_DIR}" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
  printf 'run directory must be empty to avoid stale benchmark artifacts: %s\n' "${RUN_DIR}" >&2
  exit 2
fi
mkdir -p "${LOG_DIR}"
touch "${RESULTS_FILE}"

epoch_barrier_env=()
if (( ${PRACTICAL_MP_RUNS:-1} > 1 )); then
  mkdir -p "${RUN_DIR}/epoch-barrier"
  epoch_barrier_env+=("PRACTICAL_EPOCH_BARRIER_DIR=${RUN_DIR}/epoch-barrier")
fi

cleanup() {
  status=$?
  if [[ "${KEEP_PRACTICAL_MP_RUN:-0}" != "1" && "${RUN_DIR}" == "/tmp/practical-adkr-mp-n${N}."* ]]; then
    rm -rf -- "${RUN_DIR}"
  else
    printf 'PRACTICAL_MP_RUN_DIR=%s\n' "${RUN_DIR}" >&2
  fi
  exit "${status}"
}
trap cleanup EXIT INT TERM

if [[ ! -x "${BIN}" || "${REBUILD_PRACTICAL_MP:-1}" == "1" ]]; then
  (cd "${ROOT_DIR}" && go build -o "${BIN}" ./cmd/bench_latency)
fi

"${BIN}" -n "${N}" -f "${F}" -kappa "${KAPPA}" -runs 1 \
  -paillier-bits "${PRACTICAL_MP_PAILLIER_BITS:-3072}" \
  -setup-keygen-only -setup-output-dir "${SETUP_DIR}"

mvba_addrs=""
proto_addrs=""
coin_addrs=""
comp_addrs=""
partial_addrs=""
for id in $(seq 0 $((N - 1))); do
  [[ -z "${mvba_addrs}" ]] || mvba_addrs+=","
  mvba_addrs+="${id}=127.0.0.1:$((MVBA_PORT_BASE + id))"
  [[ -z "${proto_addrs}" ]] || proto_addrs+=","
	proto_addrs+="${id}=127.0.0.1:$((PROTO_PORT_BASE + id))"
	[[ -z "${coin_addrs}" ]] || coin_addrs+=","
	coin_addrs+="${id}=127.0.0.1:$((COIN_PORT_BASE + id))"
done
for id in $(seq 0 $((N - 1))); do
	new_id=$((N + id))
	proto_addrs+=",${new_id}=127.0.0.1:$((PROTO_PORT_BASE + new_id))"
	[[ -z "${comp_addrs}" ]] || comp_addrs+=","
	comp_addrs+="${new_id}=127.0.0.1:$((COMP_PORT_BASE + new_id))"
	[[ -z "${partial_addrs}" ]] || partial_addrs+=","
	partial_addrs+="${new_id}=127.0.0.1:$((PARTIAL_PORT_BASE + new_id))"
done

# Hold every node at one wall-clock start so spawn skew does not compress the
# slowest nodes' readiness windows on a shared host. Unset the variable to keep
# immediate start.
PRACTICAL_START_AT_UNIX="${PRACTICAL_START_AT_UNIX:-$(( $(date +%s) + 8 ))}"
export PRACTICAL_START_AT_UNIX
PRACTICAL_RECAST_PORT_OFFSET="${PRACTICAL_RECAST_PORT_OFFSET:-3000}"
export PRACTICAL_RECAST_PORT_OFFSET

pids=()
for id in $(seq 0 $((N - 1))); do
  log="${LOG_DIR}/node-${id}.log"
  env PRACTICAL_ARTIFACT_CACHE_DIR="${SETUP_DIR}/node-$(printf '%06d' "${id}")" \
  PRACTICAL_SETUP_READ_ONLY=1 \
  PRACTICAL_LOCAL_STATE_DIR="${RUN_DIR}/local/node-${id}" \
  "${epoch_barrier_env[@]}" \
  PRACTICAL_STRICT_NETWORK=1 \
  "${BIN}" \
    -n "${N}" -f "${F}" -kappa "${KAPPA}" -runs "${PRACTICAL_MP_RUNS:-1}" \
    -timeout "${PRACTICAL_MP_TIMEOUT:-120s}" \
    -paillier-bits "${PRACTICAL_MP_PAILLIER_BITS:-3072}" \
    -mvba-network tcp \
    -mvba-addrs "${mvba_addrs}" -mvba-local-ids "${id}" \
	-proto-addrs "${proto_addrs}" -proto-local-ids "${id},$((N + id))" \
	-coin-addrs "${coin_addrs}" \
	-comp-addrs "${comp_addrs}" -partial-verify-addrs "${partial_addrs}" \
	-comm-metrics=true \
    >"${log}" 2>&1 &
  pids+=("$!")
done

status=0
for i in $(seq 0 $((N - 1))); do
  if ! wait "${pids[$i]}"; then
    status=1
  fi
done

printf 'PRACTICAL_MP_RUN_DIR=%s\n' "${RUN_DIR}"
printf 'PRACTICAL_MP_LOG_DIR=%s\n' "${LOG_DIR}"
for id in $(seq 0 $((N - 1))); do
  log="${LOG_DIR}/node-${id}.log"
  result=$(rg '^E2E_BENCH_RESULT ' "${log}" | tail -n 1 || true)
  if [[ -n "${result}" ]]; then
    printf '%s\n' "${result}" >>"${RESULTS_FILE}"
    printf 'NODE_%s %s\n' "${id}" "${result}"
  else
    printf 'NODE_%s NO_RESULT\n' "${id}"
    tail -n 8 "${log}" >&2 || true
  fi
done
awk -v protocol=PRACTICAL-ADKR -v expected_nodes="${N}" -v faults="${F}" \
  -f "${SUMMARY_AWK}" "${RESULTS_FILE}"
successful_nodes=$(rg -c ' success_runs=1 ' "${RESULTS_FILE}" || true)
if (( successful_nodes >= N - F )); then
  exit 0
fi
exit "${status}"
