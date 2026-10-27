// Provider-specific webhook verification. Each provider signs requests with a
// different header, format, and payload construction. The provider map is
// keyed by the reserved URL path that sender posts to; anything not in the map
// falls through to the default HMAC scheme handled in main.go.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
)

// provider describes one webhook sender's verification scheme.
type provider struct {
	name        string
	secretPath  string
	secret      string // populated at init; only when the provider is enabled
	header      string
	verify      func(p *provider, req *events.APIGatewayV2HTTPRequest, body []byte) error
	upstreamEnv string   // env var holding this provider's upstream URL; "" = disabled
	upstream    *url.URL // parsed at init from upstreamEnv; nil = disabled
}

// providers maps each reserved path to its verifier. A provider is enabled iff
// its upstreamEnv variable is set; a disabled provider's path returns 404.
var providers = map[string]*provider{
	"/github": {
		name:        "github",
		secretPath:  ssmGithubSecretPath,
		header:      "X-Hub-Signature-256",
		verify:      verifyGitHub,
		upstreamEnv: "GITHUB_UPSTREAM_URL",
	},
	"/tailscale": {
		name:        "tailscale",
		secretPath:  ssmTailscaleSecretPath,
		header:      "Tailscale-Webhook-Signature",
		verify:      verifyTailscale,
		upstreamEnv: "TAILSCALE_UPSTREAM_URL",
	},
}

// verifyGitHub checks the X-Hub-Signature-256 header: "sha256=<hex>" HMAC over
// the raw request body. GitHub sends no timestamp, so replay safety relies on
// the signing secret staying secret.
func verifyGitHub(p *provider, req *events.APIGatewayV2HTTPRequest, body []byte) error {
	sig := headerGet(*req, p.header)
	if sig == "" {
		return errors.New("missing X-Hub-Signature-256 header")
	}
	if !strings.HasPrefix(sig, "sha256=") {
		return errors.New("github signature missing sha256= prefix")
	}
	expected := hmacSHA256Hex(p.secret, body)
	if !constantTimeHexEqual(strings.TrimPrefix(sig, "sha256="), expected) {
		return errors.New("github signature mismatch")
	}
	return nil
}

// tailscaleSigVersion is the signature scheme version Tailscale currently
// sends in the Tailscale-Webhook-Signature header.
const tailscaleSigVersion = "v1"

// verifyTailscale checks the Tailscale-Webhook-Signature header. Its format is
// a comma-separated list of "t=<unix>" and "v1=<hex>" pairs, e.g.
// "t=1700000000,v1=<hex>". The signed payload is "<unix>.<raw body>" and the
// MAC is HMAC-SHA256 hex. Tailscale may include more than one v1 signature
// (e.g. during secret rotation); any match is accepted. The timestamp is
// checked against replayWindow because Tailscale embeds one.
func verifyTailscale(p *provider, req *events.APIGatewayV2HTTPRequest, body []byte) error {
	header := headerGet(*req, p.header)
	if header == "" {
		return errors.New("missing Tailscale-Webhook-Signature header")
	}
	ts, sigs, err := parseTailscaleSignature(header)
	if err != nil {
		return err
	}
	skew := time.Since(ts)
	if skew > replayWindow || skew < -replayWindow {
		return fmt.Errorf("tailscale timestamp skew too large (%v)", skew)
	}

	payload := strconv.AppendInt(nil, ts.Unix(), 10)
	payload = append(payload, '.')
	payload = append(payload, body...)
	expected := hmacSHA256Hex(p.secret, payload)

	// Compare every candidate in constant time and OR the results, so the
	// accepted position doesn't short-circuit the loop.
	var match int
	for _, sig := range sigs {
		match |= subtle.ConstantTimeCompare([]byte(sig), []byte(expected))
	}
	if match != 1 {
		return errors.New("tailscale signature mismatch")
	}
	return nil
}

// parseTailscaleSignature splits a Tailscale-Webhook-Signature header into its
// timestamp and v1 signatures. Unknown keys are ignored, matching Tailscale's
// example verifier, so future header additions don't break verification.
func parseTailscaleSignature(header string) (time.Time, []string, error) {
	var (
		ts     time.Time
		haveTS bool
		sigs   []string
	)
	for _, pair := range strings.Split(header, ",") {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			return time.Time{}, nil, errors.New("malformed Tailscale-Webhook-Signature header")
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "t":
			sec, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return time.Time{}, nil, fmt.Errorf("invalid tailscale timestamp %q", value)
			}
			ts = time.Unix(sec, 0)
			haveTS = true
		case tailscaleSigVersion:
			if value == "" {
				return time.Time{}, nil, errors.New("empty tailscale v1 signature")
			}
			sigs = append(sigs, value)
		}
	}
	if !haveTS {
		return time.Time{}, nil, errors.New("missing tailscale timestamp")
	}
	if len(sigs) == 0 {
		return time.Time{}, nil, errors.New("missing tailscale v1 signature")
	}
	return ts, sigs, nil
}

// hmacSHA256Hex returns the bare lowercase hex HMAC-SHA256 of payload.
func hmacSHA256Hex(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// constantTimeHexEqual compares two lowercase hex strings in constant time.
func constantTimeHexEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
