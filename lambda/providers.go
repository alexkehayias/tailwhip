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
	"strings"

	"github.com/aws/aws-lambda-go/events"
)

// provider describes one webhook sender's verification scheme.
type provider struct {
	name       string
	secretPath string
	secret     string // populated at init
	header     string
	verify     func(p *provider, req *events.APIGatewayV2HTTPRequest, body []byte) error
}

// providers maps each reserved path to its verifier.
var providers = map[string]*provider{
	"/github": {
		name:       "github",
		secretPath: ssmGithubSecretPath,
		header:     "X-Hub-Signature-256",
		verify:     verifyGitHub,
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
