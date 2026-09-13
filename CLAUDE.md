# tailwhip — extending the Lambda to a new webhook provider

This project is an AWS Lambda that acts as a public webhook ingress for a private
server on a Tailscale tailnet. The Lambda verifies an inbound webhook signature,
then forwards the request over Tailscale to a single upstream `TARGET_URL`.

Routing is by URL path:
- The root `/` (and any non-reserved path) uses a generic HMAC scheme
  (`X-Webhook-Signature` over `timestamp.body` + `X-Webhook-Timestamp` replay
  check) — handled by `handleDefault` in `lambda/main.go`.
- Reserved paths (e.g. `/github`) use that provider's **native** signature
  verification — handled by a per-provider `verify` function.

`lambda/` is its own Go module. Always run Go commands from inside it:
`cd lambda && go test ./...` and `cd lambda && ./build.sh`.

## How a provider is wired up

There are exactly four touch points in code, plus docs:

1. An SSM path constant in `lambda/main.go`.
2. That path added to the fail-fast fetch loop in `initialize()`.
3. A `provider` entry in the `providers` map in `lambda/providers.go`.
4. A `verify` function for it in `lambda/providers.go`.

The `provider` struct (`lambda/providers.go`):

```go
type provider struct {
	name       string
	secretPath string
	secret     string // populated at init from SSM
	header     string // signature header name
	verify     func(p *provider, req *events.APIGatewayV2HTTPRequest, body []byte) error
}
```

The `providers` map is keyed by the exact, case-sensitive reserved path. The
`secret` field is populated at cold start; the `verify` func reads it via `p`.

## Step 1 — add the secret path + fail-fast fetch (`lambda/main.go`)

Add a constant alongside the existing ones:

```go
const (
	ssmAuthKeyPath        = "/tailwhip/ts_authkey"
	ssmDefaultSecretPath  = "/tailwhip/default_webhook_secret"
	ssmGithubSecretPath   = "/tailwhip/github_webhook_secret"
	// NEW:
	ssmStripeSecretPath   = "/tailwhip/stripe_webhook_secret"
	...
)
```

In `initialize()` there is a fail-fast loop — **every** secret is required at
cold start and the Lambda refuses to start if any is missing. Add the new path
to the list, and assign the value to the provider:

```go
for _, path := range []string{ssmAuthKeyPath, ssmDefaultSecretPath, ssmGithubSecretPath, ssmStripeSecretPath} {
	if values[path] == "" {
		log.Fatalf("missing SSM parameter %s", path)
	}
}
secret = values[ssmDefaultSecretPath]
providers["/github"].secret = values[ssmGithubSecretPath]
providers["/stripe"].secret = values[ssmStripeSecretPath]
```

**Consequence:** because secrets fail fast, the Lambda will not start until the
new SSM parameter exists. Create it before deploying (see Deploy below), and
note this in the PR/commit — an existing deployment that applies the new code
without the SSM parameter will stop serving.

## Step 2 — register the provider (`lambda/providers.go`)

Add a map entry with the header name and verifier:

```go
var providers = map[string]*provider{
	"/github": { ... },
	"/stripe": {
		name:       "stripe",
		secretPath: ssmStripeSecretPath,
		header:     "Stripe-Signature",
		verify:     verifyStripe,
	},
}
```

## Step 3 — write the `verify` function

Signature and rules that MUST be followed:

```go
func verifyStripe(p *provider, req *events.APIGatewayV2HTTPRequest, body []byte) error {
	sig := headerGet(*req, p.header)   // req is a pointer here
	...
}
```

- **`req` is a pointer**, but `headerGet` takes a value — call `headerGet(*req, p.header)`. API Gateway lowercases header keys, and `headerGet` handles that, so pass the provider's header name as-is.
- **`body` is the raw, base64-decoded request body** (already decoded by `handler`). Compute the HMAC over exactly what the sender signed — for most providers that is the raw body; for some (e.g. Twilio) it is a constructed string like the URL plus sorted form params. Never sign `req.Body` (which may be base64).
- **Always compare in constant time.** For lowercase hex use the existing `constantTimeHexEqual(a, b string) bool`. For base64 or binary signatures decode to bytes and compare with `crypto/subtle.ConstantTimeCompare`. Never use `==` on attacker-controlled signature bytes.
- **Return descriptive errors** (e.g. `errors.New("stripe signature mismatch")`). `handler` logs them as `WARN` and converts any error to a `401 invalid signature` — it does not leak the message to the caller.
- **Replay protection is per-provider.** Only enforce a timestamp window if the provider actually includes one (e.g. Stripe embeds `t=` inside its signature; Slack uses a separate `X-Slack-Request-Timestamp` header). GitHub/Twilio send none — do not require a timestamp, replay safety relies on the secret staying secret. The default `/` handler is the only place `replayWindow` is used.
- Reuse the existing helpers (`hmacSHA256Hex`, `constantTimeHexEqual`) where they fit; add a new helper only if the provider's format genuinely needs one (e.g. base64, SHA1, or a multi-part signed string).

## Step 4 — add tests (`lambda/providers_test.go`)

Add a `TestVerify<Provider>` following the GitHub test. Compute the expected
signature **independently** with the stdlib (`crypto/hmac`) using the provider's
documented format, then assert: valid signature accepted; tampered body,
wrong secret, missing header, and malformed-format each rejected. Also test any
new helper and the `rawPath` cases if routing is involved.

## Step 5 — update docs

- `README.md`: add the row to the Providers table and a short subsection (how to
  configure the provider's dashboard to post to `<function_url>/<path>` and the
  SSM secret it needs).
- `outputs.tf`: update the `function_url` output description only if the wording
  stops being accurate.

## Build, test, deploy

```bash
cd lambda && gofmt -l . && go vet ./... && go test ./...   # all must pass
cd lambda && ./build.sh                                     # regenerates bootstrap

# Deploy (from repo root)
tofu apply -var target_url="http://<tailscale-ip>:1234/webhook"
```

Before `tofu apply`, create the new SSM parameter or the Lambda won't start:

```bash
aws ssm put-parameter \
  --name /tailwhip/stripe_webhook_secret \
  --value "<secret from the provider's dashboard>" \
  --type SecureString
```

`tofu apply` zips `lambda/bootstrap` (rebuilt by `./build.sh`) and redeploys;
`source_code_hash` triggers the update when the binary changes.

## Gotchas

- **Don't break the default path.** Any path not in `providers` falls through to
  `handleDefault`. Keep reserved paths specific and documented.
- **Paths are exact and case-sensitive** (`rawPath` returns the raw path;
  `/Stripe` ≠ `/stripe`).
- **Never add the signature verification as a no-op "stub".** Verification is
  the project's core security guarantee — the README stresses it is mandatory.
- **`lambda/` is a separate Go module** — run tests/build from inside it, not
  from the repo root.
