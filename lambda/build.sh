#!/usr/bin/env bash
# Cross-compile the Lambda handler for AWS (Amazon Linux 2023, x86_64).
# CGO disabled so the binary is fully static — runs on any glibc.
#
# Produces ./bootstrap in this directory. The Terraform archive_file data
# source zips it into the Lambda package at `tofu apply` time, so re-running
# this script before each deploy ensures the deployed code matches main.go.
set -euo pipefail

cd "$(dirname "$0")"

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bootstrap .

if [[ -f bootstrap ]]; then
    echo "Built ./bootstrap ($(du -h bootstrap | cut -f1))"
else
    echo "Build failed" >&2
    exit 1
fi