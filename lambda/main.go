// Package main implements an AWS Lambda function that verifies HMAC-SHA256
// signatures on incoming webhooks and, for valid requests, forwards them to an
// upstream server running on a Tailscale tailnet. tsnet (Tailscale's in-process
// library) joins the tailnet from within the Lambda execution environment so
// the outbound request flows over Tailscale to the upstream server's private
// address.
//
// Secrets (Tailscale auth key + HMAC shared secret) live in SSM Parameter
// Store as SecureString parameters under /tailwhip/*. The Lambda's IAM role
// grants ssm:GetParameters on that path — secrets never appear in Lambda
// environment variables or Terraform state.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"tailscale.com/tsnet"
)

// Package-level state — initialized once per Lambda execution environment
// (cold start) and reused across warm invocations. tsnet's tailnet connection
// persists for the lifetime of the execution environment.
var (
	tsServer   *tsnet.Server
	targetURL  *url.URL
	secret     string
	sigHeader  string
	httpClient *http.Client
)

const (
	ssmAuthKeyPath  = "/tailwhip/ts_authkey"
	ssmSecretPath   = "/tailwhip/webhook_secret"
	replayWindow    = 5 * time.Minute
	upstreamTimeout = 10 * time.Second
)

func init() {
	ctx := context.Background()

	// AWS config — Lambda's IAM role provides credentials via env.
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("loading AWS config: %v", err)
	}

	// Fetch both secrets in one GetParameters call (single round-trip).
	ssmClient := ssm.NewFromConfig(cfg)
	resp, err := ssmClient.GetParameters(ctx, &ssm.GetParametersInput{
		Names:          []string{ssmAuthKeyPath, ssmSecretPath},
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		log.Fatalf("fetching SSM parameters: %v", err)
	}
	if len(resp.InvalidParameters) > 0 {
		log.Printf("WARN: SSM invalid parameters: %v", resp.InvalidParameters)
	}

	var authKey, webhookSecret string
	for _, p := range resp.Parameters {
		if p.Name == nil || p.Value == nil {
			continue
		}
		switch *p.Name {
		case ssmAuthKeyPath:
			authKey = *p.Value
		case ssmSecretPath:
			webhookSecret = *p.Value
		}
	}
	if authKey == "" || webhookSecret == "" {
		log.Fatalf("missing SSM parameters (authkey set: %v, secret set: %v)", authKey != "", webhookSecret != "")
	}
	secret = webhookSecret

	// Start tsnet — joins the tailnet as an ephemeral node so it auto-cleans
	// when the Lambda execution environment is recycled (no stale nodes).
	hostname := os.Getenv("TAILSCALE_HOSTNAME")
	if hostname == "" {
		hostname = "tailwhip"
	}
	tsServer = &tsnet.Server{
		AuthKey:   authKey,
		Hostname:  hostname,
		Ephemeral: true,
	}
	if err := tsServer.Start(); err != nil {
		log.Fatalf("starting tsnet: %v", err)
	}

	// Parse target URL once.
	targetStr := os.Getenv("TARGET_URL")
	if targetStr == "" {
		log.Fatal("TARGET_URL env var not set")
	}
	targetURL, err = url.Parse(targetStr)
	if err != nil {
		log.Fatalf("parsing TARGET_URL %q: %v", targetStr, err)
	}

	// HTTP client with a Tailscale-backed dial — outbound requests flow over
	// the tailnet to the upstream server's private address. The addr arg from
	// http.Transport is ignored; we always dial targetURL.Host.
	httpClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return tsServer.Dial(ctx, "tcp", targetURL.Host)
			},
		},
		Timeout: upstreamTimeout,
	}

	sigHeader = os.Getenv("SIG_HEADER")
	if sigHeader == "" {
		sigHeader = "X-Webhook-Signature"
	}

	log.Printf("initialized: target=%s, hostname=%s", targetURL.String(), hostname)
}

// handler verifies the HMAC-SHA256 signature on every request. For valid
// signatures, it forwards the request to the upstream server over Tailscale and
// returns the response verbatim. Invalid signatures or stale/missing timestamps
// get a 401 (no forwarding).
func handler(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// API Gateway may base64-encode non-UTF8 request bodies — decode first so
	// the HMAC is computed against exactly what the sender signed.
	body := []byte(req.Body)
	if req.IsBase64Encoded {
		decoded, err := base64.StdEncoding.DecodeString(req.Body)
		if err != nil {
			return errorResp(400, "invalid base64 body"), nil
		}
		body = decoded
	}

	// Require X-Webhook-Timestamp for replay protection (±5min window).
	ts := headerGet(req, "X-Webhook-Timestamp")
	if ts == "" {
		log.Println("WARN: missing X-Webhook-Timestamp header")
		return errorResp(401, "missing timestamp"), nil
	}
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		log.Printf("WARN: invalid timestamp %q: %v", ts, err)
		return errorResp(401, "invalid timestamp"), nil
	}
	skew := time.Since(time.Unix(tsInt, 0))
	if skew > replayWindow || skew < -replayWindow {
		log.Printf("WARN: timestamp skew too large (%v)", skew)
		return errorResp(401, "stale request"), nil
	}

	// Verify HMAC-SHA256 signature over timestamp.body. hmac.Equal is constant-time.
	sig := headerGet(req, sigHeader)
	if sig == "" {
		log.Println("WARN: missing signature header")
		return errorResp(401, "missing signature"), nil
	}
	expected := computeHMAC(secret, []byte(ts+"."+string(body)))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		log.Printf("WARN: HMAC mismatch (got %q)", sig)
		return errorResp(401, "invalid signature"), nil
	}

	// Forward to upstream over Tailscale.
	method := req.RequestContext.HTTP.Method
	if method == "" {
		method = "POST"
	}
	forwardReq, err := http.NewRequestWithContext(ctx, method, targetURL.String(), bytes.NewReader(body))
	if err != nil {
		return errorResp(500, "internal error"), nil
	}
	// Copy headers through; skip hop-by-hop and Lambda-internal ones. The Host
	// header is set by http.NewRequest from targetURL — don't copy the original.
	for k, v := range req.Headers {
		if strings.EqualFold(k, "host") ||
			strings.EqualFold(k, "x-forwarded-for") ||
			strings.EqualFold(k, "x-forwarded-proto") {
			continue
		}
		forwardReq.Header.Set(k, v)
	}

	resp, err := httpClient.Do(forwardReq)
	if err != nil {
		log.Printf("ERROR: upstream request failed: %v", err)
		return errorResp(502, "upstream unavailable"), nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR: reading upstream response: %v", err)
		return errorResp(502, "reading upstream response"), nil
	}

	respHeaders := map[string]string{}
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[k] = v[0]
		}
	}

	log.Printf("INFO: forwarded %s → %d (%d bytes)", method, resp.StatusCode, len(respBody))

	return events.APIGatewayV2HTTPResponse{
		StatusCode:      resp.StatusCode,
		Headers:         respHeaders,
		Body:            string(respBody),
		IsBase64Encoded: false,
	}, nil
}

// computeHMAC returns "sha256=<hex>" — the format callers send in the signature
// header. The full string (including "sha256=" prefix) is compared via hmac.Equal
// so an attacker can't shorten-prefix-match a truncated hash.
func computeHMAC(secret string, payload []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

// headerGet returns a header value from an API Gateway V2 request. API Gateway
// lowercases all header keys, so the lookup is case-insensitive against whatever
// SIG_HEADER was configured as.
func headerGet(req events.APIGatewayV2HTTPRequest, name string) string {
	return req.Headers[strings.ToLower(name)]
}

// errorResp builds a JSON error response.
func errorResp(code int, msg string) events.APIGatewayV2HTTPResponse {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return events.APIGatewayV2HTTPResponse{
		StatusCode: code,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(b),
	}
}

func main() {
	lambda.Start(handler)
}
