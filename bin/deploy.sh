#!/usr/bin/env bash
#
# deploy.sh — build the Lambda and apply it with OpenTofu.
#
# Runs the Go checks, rebuilds lambda/bootstrap, then `tofu apply`. All
# arguments are forwarded to `tofu apply`, so pass your variables here:
#
#   ./bin/deploy.sh -var region=us-east-1 -var target_url=http://100.x.y.z:1234/webhook
#
# (Variables can also come from TF_VAR_* env vars or a *.tfvars file.) Run
# `tofu init` first if the working directory isn't initialized yet.
#
# Set SKIP_TESTS=1 to skip gofmt/vet/test (not recommended).
#
# Requires: go, tofu.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -z "${SKIP_TESTS:-}" ]]; then
  echo "==> gofmt / vet / test"
  (
    cd lambda
    unformatted=$(gofmt -l .)
    if [[ -n "$unformatted" ]]; then
      echo "gofmt: unformatted files:" >&2
      echo "$unformatted" >&2
      exit 1
    fi
    go vet ./...
    go test ./...
  )
fi

echo "==> building lambda/bootstrap"
(cd lambda && ./build.sh)

echo "==> tofu apply $*"
tofu apply "$@"
