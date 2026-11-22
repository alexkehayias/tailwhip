package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
)

// TestHandlerForwardsLmProxy exercises the full /lm-proxy path: reserved-path
// routing (including slash-normalized variants), HMAC verification, and
// forwarding to the provider upstream.
func TestHandlerForwardsLmProxy(t *testing.T) {
	for _, path := range []string{"/lm-proxy", "/lm-proxy/", "//lm-proxy"} {
		t.Run(path, func(t *testing.T) {
			var (
				gotBody []byte
				gotSig  string
				gotTS   string
			)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotBody, _ = io.ReadAll(r.Body)
				gotSig = r.Header.Get("X-Webhook-Signature")
				gotTS = r.Header.Get("X-Webhook-Timestamp")
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			u, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}

			p := providers["/lm-proxy"]
			oldUpstream, oldClient, oldSecret := p.upstream, httpClient, p.secret
			p.upstream = u
			httpClient = upstream.Client()
			p.secret = "test-secret"
			defer func() {
				p.upstream, httpClient, p.secret = oldUpstream, oldClient, oldSecret
			}()

			body := []byte(`{"input":10,"output":42,"cache_read":5,"cache_write":0}`)
			now := time.Now()
			req := events.APIGatewayV2HTTPRequest{
				RawPath: path,
				Headers: map[string]string{
					"x-webhook-timestamp": strconv.FormatInt(now.Unix(), 10),
					"x-webhook-signature": hmacTimestampSig(p.secret, now, body),
				},
				Body: string(body),
				RequestContext: events.APIGatewayV2HTTPRequestContext{
					HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
						Method: "POST",
						Path:   path,
					},
				},
			}

			resp, err := handler(context.Background(), req)
			if err != nil {
				t.Fatalf("handler error: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, body = %s", resp.StatusCode, resp.Body)
			}
			if string(gotBody) != string(body) {
				t.Errorf("upstream body = %q, want %q", gotBody, body)
			}
			if gotSig == "" || gotTS == "" {
				t.Error("upstream did not receive the signing headers")
			}
		})
	}
}

// TestHandlerRejectsUnsignedLmProxy verifies that a request to the enabled
// /lm-proxy provider without a valid signature is rejected before forwarding.
func TestHandlerRejectsUnsignedLmProxy(t *testing.T) {
	var forwarded bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	p := providers["/lm-proxy"]
	oldUpstream, oldClient, oldSecret := p.upstream, httpClient, p.secret
	p.upstream = u
	httpClient = upstream.Client()
	p.secret = "test-secret"
	defer func() {
		p.upstream, httpClient, p.secret = oldUpstream, oldClient, oldSecret
	}()

	body := `{"input":10,"output":42,"cache_read":5,"cache_write":0}`
	req := events.APIGatewayV2HTTPRequest{
		RawPath: "/lm-proxy",
		Headers: map[string]string{
			"x-webhook-timestamp": strconv.FormatInt(time.Now().Unix(), 10),
			"x-webhook-signature": "sha256=" + strings.Repeat("0", 64),
		},
		Body: body,
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: "POST", Path: "/lm-proxy"},
		},
	}

	resp, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if forwarded {
		t.Error("invalid request was forwarded upstream")
	}
}
