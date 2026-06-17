#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${VAMPI_BASE_URL:-http://127.0.0.1:3000}"

echo "[karaxys] GET /createdb"
curl -fsS -i "${BASE_URL}/createdb"
echo

echo "[karaxys] POST /users/v1/register"
curl -fsS -i \
  -H 'Content-Type: application/json' \
  -d '{"username":"tracer","email":"tracer@123","password":"password123"}' \
  "${BASE_URL}/users/v1/register" || true
echo

echo "[karaxys] POST /users/v1/login"
curl -fsS -i \
  -H 'Content-Type: application/json' \
  -d '{"username":"tracer","password":"password123"}' \
  "${BASE_URL}/users/v1/login"
echo
