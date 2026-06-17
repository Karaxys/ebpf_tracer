#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${ROOT_DIR}/bin"
LOG_DIR="${ROOT_DIR}/logs"
KAFKA_BOOTSTRAP="${KAFKA_BOOTSTRAP:-localhost:9092}"
KAFKA_TOPIC="${KAFKA_TOPIC:-raw-network-traffic}"
VAMPI_CONTAINER="${VAMPI_CONTAINER:-vampi-test}"
VAMPI_IMAGE="${VAMPI_IMAGE:-erev0s/vampi:latest}"
VAMPI_HOST_PORT="${VAMPI_HOST_PORT:-3000}"
VAMPI_CONTAINER_PORT="${VAMPI_CONTAINER_PORT:-5000}"
AGENT_ID="${KARAXYS_AGENT_ID:-local-ebpf-agent}"
WORKER_GROUP_ID="${WORKER_GROUP_ID:-karaxys-worker-$(date +%s)}"

mkdir -p "${BIN_DIR}" "${LOG_DIR}"

echo "[karaxys] building eBPF agent and worker"
go build -o "${BIN_DIR}/agent" ./cmd/agent
go build -o "${BIN_DIR}/worker" ./cmd/worker

echo "[karaxys] starting Kafka"
docker compose -f "${ROOT_DIR}/docker-compose.yml" up -d kafka

echo "[karaxys] waiting for Kafka"
for _ in $(seq 1 60); do
  if docker exec raven-kafka kafka-topics.sh --bootstrap-server localhost:9092 --list >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

docker exec raven-kafka kafka-topics.sh \
  --bootstrap-server localhost:9092 \
  --create \
  --if-not-exists \
  --topic "${KAFKA_TOPIC}" \
  --partitions 3 \
  --replication-factor 1 >/dev/null

if docker ps -a --format '{{.Names}}' | grep -qx "${VAMPI_CONTAINER}"; then
  echo "[karaxys] starting existing ${VAMPI_CONTAINER}"
  docker start "${VAMPI_CONTAINER}" >/dev/null
else
  echo "[karaxys] starting ${VAMPI_CONTAINER}"
  docker run -d \
    --name "${VAMPI_CONTAINER}" \
    -p "${VAMPI_HOST_PORT}:${VAMPI_CONTAINER_PORT}" \
    "${VAMPI_IMAGE}" >/dev/null
fi

echo "[karaxys] waiting for VAmPI on http://127.0.0.1:${VAMPI_HOST_PORT}"
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${VAMPI_HOST_PORT}/" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

WORKER_ARGS=(
  -kafka-bootstrap "${KAFKA_BOOTSTRAP}"
  -topic "${KAFKA_TOPIC}"
  -group-id "${WORKER_GROUP_ID}"
  -offset-reset earliest
  -output-contract normalized
  -agent-id "${AGENT_ID}"
)

if [[ -n "${KARAXYS_BACKEND_URL:-}" && -n "${KARAXYS_AGENT_TOKEN:-}" ]]; then
  echo "[karaxys] worker sink: backend ${KARAXYS_BACKEND_URL}"
  WORKER_ARGS+=(
    -output-sink http
    -backend-url "${KARAXYS_BACKEND_URL}"
    -agent-token "${KARAXYS_AGENT_TOKEN}"
    -dead-letter-file "${LOG_DIR}/worker-deadletters.jsonl"
    -pretty=false
  )
else
  echo "[karaxys] worker sink: stdout. Set KARAXYS_BACKEND_URL and KARAXYS_AGENT_TOKEN to ingest into backend."
  WORKER_ARGS+=(-output-sink stdout -pretty=true)
fi

WORKER_LOG="${LOG_DIR}/worker.log"
echo "[karaxys] starting worker. log=${WORKER_LOG}"
"${BIN_DIR}/worker" "${WORKER_ARGS[@]}" >"${WORKER_LOG}" 2>&1 &
WORKER_PID="$!"

cleanup() {
  if kill -0 "${WORKER_PID}" >/dev/null 2>&1; then
    kill "${WORKER_PID}" >/dev/null 2>&1 || true
    wait "${WORKER_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

echo "[karaxys] eBPF agent will run in foreground. Press Ctrl-C to stop."
echo "[karaxys] generate traffic with: bash ${ROOT_DIR}/scripts/smoke-vampi-traffic.sh"

sudo -E "${BIN_DIR}/agent" \
  -target-mode container \
  -container "${VAMPI_CONTAINER}" \
  -kafka-bootstrap "${KAFKA_BOOTSTRAP}" \
  -topic "${KAFKA_TOPIC}" \
  -target-ports "${VAMPI_CONTAINER_PORT}" \
  -stats-interval 5s
