#!/usr/bin/env bash
set -euo pipefail

base_url="${1:-http://127.0.0.1:8000}"

echo "[smoke] checking /health"
health_payload="$(curl -fsS "${base_url}/health")"
echo "${health_payload}" | grep -q '"status":"ok"'
echo "${health_payload}" | grep -q '"auth_mode":"oauth2-remote"'

echo "[smoke] checking /.well-known/oauth-authorization-server"
well_known_payload="$(curl -fsS "${base_url}/.well-known/oauth-authorization-server")"
echo "${well_known_payload}" | grep -q '"authorization_endpoint"'
echo "${well_known_payload}" | grep -q '"token_endpoint"'
echo "${well_known_payload}" | grep -q '"registration_endpoint"'

echo "[smoke] checking /register"
register_payload="$(curl -fsS -X POST "${base_url}/register" \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"smoke-test","redirect_uris":["http://localhost:1234/callback"]}')"
client_id="$(echo "${register_payload}" | sed -n 's/.*"client_id":"\([^"]*\)".*/\1/p')"
if [[ -z "${client_id}" ]]; then
  echo "failed to parse client_id from /register response"
  exit 1
fi

echo "[smoke] checking /authorize redirect"
authorize_headers="$(curl -fsS -D - -o /dev/null \
  "${base_url}/authorize?response_type=code&client_id=${client_id}&redirect_uri=http://localhost:1234/callback&state=smoke-state&code_challenge=smoke-challenge&code_challenge_method=S256")"
echo "${authorize_headers}" | grep -q "HTTP/1.1 302"
echo "${authorize_headers}" | grep -q "^location: https://x.com/i/oauth2/authorize?"

echo "[smoke] oauth2-remote checks passed"
