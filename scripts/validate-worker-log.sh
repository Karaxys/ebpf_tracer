#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="${1:-logs/worker.log}"
TIMEOUT_SECONDS="${VALIDATION_TIMEOUT_SECONDS:-30}"
INTERVAL_SECONDS="${VALIDATION_INTERVAL_SECONDS:-2}"

if [[ ! -f "${LOG_FILE}" ]]; then
  echo "[karaxys] worker log not found: ${LOG_FILE}" >&2
  exit 1
fi

value_for() {
  local key="$1"
  printf '%s\n' "${latest_stats}" | sed -n "s/.*${key}=\([0-9][0-9]*\).*/\1/p"
}

stats_passes() {
  received="$(value_for received)"
  parsed="$(value_for parsed)"
  routed_req="$(value_for routedReq)"
  routed_resp="$(value_for routedResp)"
  req_parsed="$(value_for reqParsed)"
  resp_parsed="$(value_for respParsed)"

  for value in "${received}" "${parsed}" "${routed_req}" "${routed_resp}" "${req_parsed}" "${resp_parsed}"; do
    if [[ -z "${value}" ]]; then
      return 2
    fi
  done

  (( received > 0 && parsed > 0 && routed_req > 0 && routed_resp > 0 && req_parsed > 0 && resp_parsed > 0 ))
}

deadline=$((SECONDS + TIMEOUT_SECONDS))
latest_stats=""
while (( SECONDS <= deadline )); do
  latest_stats="$(grep 'stats\[periodic\]\|stats\[shutdown\]' "${LOG_FILE}" | tail -n 1 || true)"
  if [[ -n "${latest_stats}" ]]; then
    if stats_passes; then
      echo "[karaxys] worker conversation validation passed"
      echo "${latest_stats}"
      exit 0
    fi
  fi
  sleep "${INTERVAL_SECONDS}"
done

if [[ -z "${latest_stats}" ]]; then
  echo "[karaxys] no worker stats line found in ${LOG_FILE}" >&2
else
  echo "[karaxys] worker did not parse complete conversations within ${TIMEOUT_SECONDS}s:" >&2
  echo "${latest_stats}" >&2
fi
exit 1
