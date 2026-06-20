#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${HTTPBIN_BASE_URL:-http://127.0.0.1:3001}"

echo "[karaxys] GET /get"
curl -fsS -i "${BASE_URL}/get?trace_id=karaxys-ebpf"
echo

echo "[karaxys] POST /anything JSON"
curl -fsS -i \
  -H 'Content-Type: application/json' \
  -d '{"username":"tracer","role":"tester","active":true}' \
  "${BASE_URL}/anything"
echo

echo "[karaxys] POST /anything large JSON"
{
  printf '{"payload":"'
  head -c 9000 </dev/zero | tr '\0' 'A'
  printf '"}'
} | curl -fsS -i \
  -H 'Content-Type: application/json' \
  --data-binary @- \
  "${BASE_URL}/anything"
echo
