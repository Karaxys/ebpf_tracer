#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KAFKA_CONTAINER="${KAFKA_CONTAINER:-raven-kafka}"
AGENT_HEALTH_URL="${AGENT_HEALTH_URL:-http://127.0.0.1:7071}"
SPOOL_FILE="${KARAXYS_AGENT_SPOOL_FILE:-${ROOT_DIR}/logs/agent-spool.jsonl}"
SMOKE_CMD="${SMOKE_CMD:-bash ${ROOT_DIR}/scripts/smoke-vampi-traffic.sh}"
kafka_stopped=0

cleanup() {
  if [[ "${kafka_stopped}" -eq 1 ]]; then
    docker start "${KAFKA_CONTAINER}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_for_ready() {
  for _ in $(seq 1 90); do
    if curl -fsS "${AGENT_HEALTH_URL}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "[karaxys] agent health endpoint not reachable: ${AGENT_HEALTH_URL}" >&2
  return 1
}

spool_bytes() {
  if [[ ! -f "${SPOOL_FILE}" ]]; then
    printf '0'
    return
  fi
  wc -c <"${SPOOL_FILE}" | tr -d ' '
}

metric_value() {
  local name="$1"
  curl -fsS "${AGENT_HEALTH_URL}/metrics" 2>/dev/null | awk -v metric="${name}" '$1 == metric { print $2; found=1; exit } END { if (!found) print "0" }'
}

wait_for_metric_at_least() {
  local name="$1"
  local minimum="$2"
  local timeout="$3"
  local deadline=$((SECONDS + timeout))
  local value
  while (( SECONDS <= deadline )); do
    value="$(metric_value "${name}")"
    if [[ "${value}" =~ ^[0-9]+$ ]] && (( value >= minimum )); then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_spool_or_circuit() {
  local start_spool_bytes="$1"
  local start_circuit_spool="$2"
  local timeout="$3"
  local deadline=$((SECONDS + timeout))
  local current_bytes
  local current_circuit_spool
  while (( SECONDS <= deadline )); do
    current_bytes="$(spool_bytes)"
    current_circuit_spool="$(metric_value ebpf_tracer_broker_circuit_spool)"
    if (( current_bytes > start_spool_bytes )); then
      return 0
    fi
    if [[ "${current_circuit_spool}" =~ ^[0-9]+$ ]] && (( current_circuit_spool > start_circuit_spool )); then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_recovery() {
  local timeout="$1"
  local deadline=$((SECONDS + timeout))
  local current_bytes
  local broker_unavailable
  while (( SECONDS <= deadline )); do
    current_bytes="$(spool_bytes)"
    broker_unavailable="$(metric_value ebpf_tracer_broker_unavailable)"
    if [[ "${broker_unavailable}" == "0" ]] && (( current_bytes == 0 )); then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_ready

echo "[karaxys] stopping Kafka container ${KAFKA_CONTAINER}"
docker stop "${KAFKA_CONTAINER}" >/dev/null
kafka_stopped=1

echo "[karaxys] waiting for agent Kafka circuit breaker"
if ! wait_for_metric_at_least ebpf_tracer_broker_unavailable 1 30; then
  echo "[karaxys] broker circuit did not open passively; sending traffic to force producer errors"
  set +e
  bash -lc "${SMOKE_CMD}"
  smoke_status="$?"
  set -e
  if [[ "${smoke_status}" -ne 0 ]]; then
    echo "[karaxys] smoke command exited ${smoke_status}; continuing because target/API errors are acceptable during outage drill"
  fi
  if ! wait_for_metric_at_least ebpf_tracer_broker_unavailable 1 30; then
    echo "[karaxys] expected ebpf_tracer_broker_unavailable=1 after Kafka stopped" >&2
    exit 1
  fi
fi

before_spool_bytes="$(spool_bytes)"
before_circuit_spool="$(metric_value ebpf_tracer_broker_circuit_spool)"

echo "[karaxys] generating traffic while Kafka is unavailable"
set +e
bash -lc "${SMOKE_CMD}"
smoke_status="$?"
set -e
if [[ "${smoke_status}" -ne 0 ]]; then
  echo "[karaxys] smoke command exited ${smoke_status}; continuing because target/API errors are acceptable during outage drill"
fi

if ! wait_for_spool_or_circuit "${before_spool_bytes}" "${before_circuit_spool}" 30; then
  current_bytes="$(spool_bytes)"
  current_circuit_spool="$(metric_value ebpf_tracer_broker_circuit_spool)"
  echo "[karaxys] expected broker-circuit spooling while Kafka is down; spool_bytes=${current_bytes} broker_circuit_spool=${current_circuit_spool}" >&2
  exit 1
fi
before_recovery_bytes="$(spool_bytes)"
echo "[karaxys] broker-circuit spooling observed during outage: spool_bytes=${before_recovery_bytes} broker_circuit_spool=$(metric_value ebpf_tracer_broker_circuit_spool)"

echo "[karaxys] restarting Kafka container ${KAFKA_CONTAINER}"
docker start "${KAFKA_CONTAINER}" >/dev/null
kafka_stopped=0
for _ in $(seq 1 90); do
  if docker exec "${KAFKA_CONTAINER}" kafka-topics.sh --bootstrap-server localhost:9092 --list >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "[karaxys] waiting for periodic spool replay"
if ! wait_for_recovery 90; then
  after_recovery_bytes="$(spool_bytes)"
  broker_unavailable="$(metric_value ebpf_tracer_broker_unavailable)"
  echo "[karaxys] agent did not recover cleanly after Kafka restart: spool_bytes=${after_recovery_bytes} broker_unavailable=${broker_unavailable}" >&2
  exit 1
fi

after_recovery_bytes="$(spool_bytes)"
echo "[karaxys] Kafka outage drill passed: before=${before_recovery_bytes} after=${after_recovery_bytes}"
