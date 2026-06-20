#!/usr/bin/env bash
set -euo pipefail

TARGET_URL="${LOAD_TARGET_URL:-http://127.0.0.1:3000/users/v1/login}"
REQUESTS="${LOAD_REQUESTS:-100}"
CONCURRENCY="${LOAD_CONCURRENCY:-10}"
METHOD="${LOAD_METHOD:-POST}"
CONTENT_TYPE="${LOAD_CONTENT_TYPE:-application/json}"
BODY="${LOAD_BODY:-{\"username\":\"tracer\",\"password\":\"password123\"}}"

if (( REQUESTS <= 0 || CONCURRENCY <= 0 )); then
  echo "[karaxys] LOAD_REQUESTS and LOAD_CONCURRENCY must be positive integers" >&2
  exit 1
fi

echo "[karaxys] load start method=${METHOD} url=${TARGET_URL} requests=${REQUESTS} concurrency=${CONCURRENCY}"

running=0
completed=0
failed=0

run_one() {
  local status
  if [[ "${METHOD}" == "GET" ]]; then
    status="$(curl -sS -o /dev/null -w "%{http_code}" "${TARGET_URL}" || true)"
  else
    status="$(curl -sS -o /dev/null -w "%{http_code}" \
      -X "${METHOD}" \
      -H "Content-Type: ${CONTENT_TYPE}" \
      --data "${BODY}" \
      "${TARGET_URL}" || true)"
  fi
  [[ "${status}" =~ ^(2|3) ]]
}

for _ in $(seq 1 "${REQUESTS}"); do
  (
    run_one
  ) &
  running=$((running + 1))

  if (( running >= CONCURRENCY )); then
    if wait -n; then
      completed=$((completed + 1))
    else
      failed=$((failed + 1))
    fi
    running=$((running - 1))
  fi
done

while (( running > 0 )); do
  if wait -n; then
    completed=$((completed + 1))
  else
    failed=$((failed + 1))
  fi
  running=$((running - 1))
done

echo "[karaxys] load complete completed=${completed} failed=${failed}"
if (( failed > 0 )); then
  exit 1
fi
