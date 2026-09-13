package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

// githubSig builds a valid X-Hub-Signature-256 value using the documented
// format (HMAC-SHA256 over the raw body), computed independently of the
// package's hmacSHA256Hex helper.
func githubSig(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyGitHub(t *testing.T) {
	const secret = "test-secret"
	p := &provider{name: "github", header: "X-Hub-Signature-256", secret: secret}
	body := []byte(`{"action":"opened","issue":42}`)

	valid := func() *events.APIGatewayV2HTTPRequest {
		return &events.APIGatewayV2HTTPRequest{
			Headers: map[string]string{"x-hub-signature-256": githubSig(secret, body)},
		}
	}

	if err := verifyGitHub(p, valid(), body); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	req := valid()
	if err := verifyGitHub(p, req, []byte(`{"action":"deleted"}`)); err == nil {
		t.Fatal("tampered body accepted")
	}

	req = valid()
	req.Headers["x-hub-signature-256"] = githubSig("wrong-secret", body)
	if err := verifyGitHub(p, req, body); err == nil {
		t.Fatal("wrong secret accepted")
	}

	req = &events.APIGatewayV2HTTPRequest{Headers: map[string]string{}}
	if err := verifyGitHub(p, req, body); err == nil {
		t.Fatal("missing header accepted")
	}

	req = valid()
	req.Headers["x-hub-signature-256"] = githubSig(secret, body)[len("sha256="):] // strip prefix
	if err := verifyGitHub(p, req, body); err == nil {
		t.Fatal("signature without sha256= prefix accepted")
	}
}

func TestRawPath(t *testing.T) {
	httpCtx := func(path string) events.APIGatewayV2HTTPRequestContext {
		return events.APIGatewayV2HTTPRequestContext{
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{Path: path},
		}
	}
	cases := []struct {
		name string
		req  *events.APIGatewayV2HTTPRequest
		want string
	}{
		{"raw path preferred", &events.APIGatewayV2HTTPRequest{RawPath: "/github", RequestContext: httpCtx("/github")}, "/github"},
		{"http path fallback", &events.APIGatewayV2HTTPRequest{RequestContext: httpCtx("/foo")}, "/foo"},
		{"empty defaults to root", &events.APIGatewayV2HTTPRequest{}, "/"},
	}
	for _, c := range cases {
		if got := rawPath(c.req); got != c.want {
			t.Errorf("%s: rawPath = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestParseUpstream(t *testing.T) {
	const env = "TEST_UPSTREAM_URL"
	t.Setenv(env, "")
	if u, err := parseUpstream(env); err != nil || u != nil {
		t.Fatalf("empty env: got (%v, %v), want (nil, nil)", u, err)
	}

	t.Setenv(env, "http://100.64.0.5:1234/github-webhook")
	u, err := parseUpstream(env)
	if err != nil {
		t.Fatalf("valid env: unexpected error: %v", err)
	}
	if u == nil || u.String() != "http://100.64.0.5:1234/github-webhook" {
		t.Fatalf("valid env: got %v, want parsed URL", u)
	}

	t.Setenv(env, "://bad url")
	if u, err := parseUpstream(env); err == nil {
		t.Fatalf("malformed env: got (%v, nil), want error", u)
	}
}
