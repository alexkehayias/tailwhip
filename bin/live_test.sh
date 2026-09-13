#!/usr/bin/env bash
#
# live_test.sh — send a signed test webhook to the deployed tailwhip endpoint
# and print the response. Exercises the default "/" HMAC path.
#
# Run with AWS credentials in the environment, e.g.:
#   aws-vault exec hq -- ./bin/live_test.sh
#
# Requires: aws, tofu, openssl, curl.
set -euo pipefail

# Run from the repo root so `tofu output` finds the local state.
cd "$(dirname "$0")/.."

SECRET=$(aws ssm get-parameter \
  --name /tailwhip/default_webhook_secret \
  --with-decryption --query Parameter.Value --output text)

BODY='{"event":"test","data":"hello"}'
TS=$(date +%s)
SIG="sha256=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $NF}')"

URL=$(tofu output -raw function_url)
echo "POST $URL"
curl -i -X POST "$URL" \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Timestamp: $TS" \
  -H "X-Webhook-Signature: $SIG" \
  -d "$BODY"
