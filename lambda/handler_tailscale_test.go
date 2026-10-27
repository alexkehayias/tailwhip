package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
)

// TestHandlerForwardsTailscale exercises the full /tailscale path: reserved-path
// routing (including slash-normalized variants), signature verification, and
// forwarding to the provider upstream.
func TestHandlerForwardsTailscale(t *testing.T) {
	for _, path := range []string{"/tailscale", "/tailscale/", "//tailscale"} {
		t.Run(path, func(t *testing.T) {
			var (
				gotBody   []byte
				gotHeader string
			)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotBody, _ = io.ReadAll(r.Body)
				gotHeader = r.Header.Get("Tailscale-Webhook-Signature")
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			u, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}

			p := providers["/tailscale"]
			oldUpstream, oldClient, oldSecret := p.upstream, httpClient, p.secret
			p.upstream = u
			httpClient = upstream.Client()
			p.secret = "test-secret"
			defer func() {
				p.upstream, httpClient, p.secret = oldUpstream, oldClient, oldSecret
			}()

			body := []byte(`[{"type":"nodeCreated","message":"test"}]`)
			req := events.APIGatewayV2HTTPRequest{
				RawPath: path,
				Headers: map[string]string{
					"tailscale-webhook-signature": tailscaleSig(p.secret, time.Now(), body),
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
			if gotHeader == "" {
				t.Error("upstream did not receive Tailscale-Webhook-Signature header")
			}
		})
	}
}
