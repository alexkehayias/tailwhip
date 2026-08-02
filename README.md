# tailwhip

An AWS Lambda that acts as a public webhook ingress for an upstream server running on a Tailscale tailnet.

The Lambda verifies an HMAC-SHA256 signature on every request (shared secret from SSM). For valid signatures, it joins the tailnet via [`tsnet`](https://pkg.go.dev/tailscale.com/tsnet) and forwards the request to the upstream server's Tailscale address. Without a valid signature, anyone who found the URL could proxy arbitrary traffic into your private network — so signature verification is mandatory, not optional.

```
[webhook sender] --HTTPS--> [Lambda Function URL]
                                |
                             verify HMAC-SHA256
                              (shared secret from SSM)
                                |  valid
                             tsnet.Dial(ctx, "tcp", <upstream-tailscale-ip>:1234)
                                |
                             [server on Tailnet]  POST /api/webhook
```

## Prerequisites

- **AWS account** with credentials configured locally (`aws sso login` or `~/.aws/credentials`). The Lambda needs an IAM role (Terraform creates it) but you need creds to run `tofu apply`.
- **OpenTofu** ≥ 1.6 ([install](https://opentofu.org/docs/intro/install/)) — `brew install opentofu` on macOS.
- **Go** ≥ 1.26 — for building the Lambda binary (`tailscale.com/tsnet` requires a recent Go).
- **Tailscale admin access** — to generate an auth key for the Lambda.

## Tailscale setup (one-time)

The Lambda joins your tailnet as an ephemeral node so it auto-cleans when the execution environment is recycled (no stale nodes piling up in your admin console).

1. **Generate a Tailscale auth key** at https://login.tailscale.com/admin/settings/keys:
   - Check **Reusable** (so the same key works across cold starts — without this you'd need a new one each time).
   - Check **Ephemeral** (so the node auto-deletes when Lambda recycles).
2. **Generate an HMAC shared secret** for webhook signatures:
   ```bash
   openssl rand -hex 32
   ```
   This is what your webhook sender (GitHub, Stripe, custom script) will use to sign request bodies. Keep it secret.
3. **Store both in SSM** as SecureString parameters — don't put secrets in Terraform state:
   ```bash
   aws ssm put-parameter \
     --name /tailwhip/ts_authkey \
     --value "tskey-..." \
     --type SecureString

   aws ssm put-parameter \
     --name /tailwhip/webhook_secret \
     --value "<openssl rand -hex 32 output>" \
     --type SecureString
   ```
4. **Tailscale ACLs**: for a personal tailnet with default `* -> *` ACLs, no changes. If your tailnet has restrictive ACLs, allow the Lambda's node (or a `tag:lambda` if you tag it) to reach the upstream server's Tailscale IP address.

## Deploy

```bash
# 1. Build the Go binary (cross-compile for Amazon Linux 2023, x86_64)
cd lambda && ./build.sh
# → produces lambda/bootstrap (28MB, ~10s build)

# 2. Deploy — pass your upstream server's Tailscale address
cd ..
tofu init
tofu apply -var target_url="http://<your-tailscale-ip>:1234/webhook"

# 3. Read the output
tofu output function_url
```

The upstream server **must be listening on a Tailnet-reachable address** — not `127.0.0.1`. Use your Tailscale IPv4 (`tailscale ip -4` to find it) or bind `0.0.0.0`. If the server binds to `127.0.0.1`, the Lambda can't reach it.

The `target_url` should include the full path (e.g., `/api/webhook`). The Lambda forwards verbatim — method, path, headers, body — so any upstream route works.

## Sending a webhook

Sign `timestamp + "." + body` with HMAC-SHA256 using the secret from SSM, and send both `X-Webhook-Timestamp` and `X-Webhook-Signature` headers. The Lambda rejects requests where the timestamp is more than ±5 minutes from now (replay protection) or if the signature is missing/invalid.

```bash
SECRET=$(aws ssm get-parameter \
  --name /tailwhip/webhook_secret \
  --with-decryption --query Parameter.Value --output text)

BODY='{"event":"test","data":"hello"}'
TS=$(date +%s)
SIG="sha256=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $NF}')"

curl -X POST "$(tofu output -raw function_url)" \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Timestamp: $TS" \
  -H "X-Webhook-Signature: $SIG" \
  -d "$BODY"
# → 200, upstream server logs the request
```

Missing/stale timestamp or bad signature → `401` (Lambda rejects before dialing Tailscale). Upstream server down → `502`. Successful forward returns the upstream response verbatim.

## Verification

### Cold start

First request after ~15min idle pays tsnet bootstrap (2–5s). Subsequent requests in the same warm execution environment are <100ms. Check CloudWatch:

```bash
aws logs tail /aws/lambda/tailwhip --follow
# Look for: "initialized: target=..." on cold start, HMAC failures (WARN), forwards (INFO)
```

`Init Duration` in CloudWatch metrics should be under 10s. If it's higher, the tsnet auth may be failing — check that the SSM parameter value is a valid reusable + ephemeral key.

### Tailscale admin

Confirm the `tailwhip` node appears in https://login.tailscale.com/admin/machines when the Lambda runs. Ephemeral nodes disappear after idle — that's expected, not a bug.

## Files

| File | Purpose |
|------|---------|
| `lambda/main.go` | Go handler: SSM fetch, tsnet start, HMAC verify, reverse proxy forward. |
| `lambda/build.sh` | Cross-compile to `bootstrap` (linux/amd64, CGO disabled). |
| `main.tf` | AWS + archive providers, region config. |
| `variables.tf` | Input vars: `target_url`, `region`, `tailscale_hostname`. |
| `lambda.tf` | Lambda function, IAM role (scoped SSM read), Function URL, log group. |
| `outputs.tf` | `function_url`, `log_group_name`. |

Secrets (`ts_authkey`, `webhook_secret`) live in SSM Parameter Store, **not** in this directory. The IAM role grants `ssm:GetParameters` on `/tailwhip/*` — the Go code fetches them at cold start.
