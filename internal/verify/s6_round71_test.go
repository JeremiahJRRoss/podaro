// SPDX-License-Identifier: AGPL-3.0-only

package verify

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Review round 71: the adapter replaced the URL's host with the resolved
// loopback address, so net/http derived the TLS server name from an IP —
// which means no SNI at all. A product that selects a virtual host by
// SNI would be reached at its default one, or refuse the handshake,
// while the checkpoint named a service that is running.
//
// The dialer the adapter attaches ignores the address entirely, so the
// URL's host costs nothing to keep and is what SNI is taken from.

// sniTarget resolves and dials a real TLS server on loopback while
// telling the caller the service name it was asked for — exactly what
// the engine's target does for a lab's internal hostnames.
type sniTarget struct{ addr string }

func (s sniTarget) Resolve(service string, port int) (string, error) { return s.addr, nil }
func (s sniTarget) Dial(ctx context.Context, service string, port int) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", s.addr)
}

func (s sniTarget) Container(ctx context.Context, service string) (*ContainerFacts, error) {
	return &ContainerFacts{}, nil
}

func TestAnHTTPSCheckpointOffersTheServiceNameAsSNI(t *testing.T) {
	var got string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	srv.TLS = &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			got = hello.ServerName // "" when the client offered no SNI
			return nil, nil        // fall back to the server's own certificate
		},
	}
	srv.StartTLS()
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	ev := &Evaluator{Target: sniTarget{addr: addr}}
	res := ev.Evaluate(context.Background(), cp("ready", "http",
		map[string]any{"url": "https://prometheus:9090/-/ready"},
		map[string]any{"status": float64(200)}))

	if res.Status != StatusPass {
		t.Fatalf("the checkpoint did not pass: %+v", res)
	}
	if got != "prometheus" {
		t.Fatalf("the TLS handshake offered ServerName %q; the checkpoint named the service prometheus", got)
	}
}
