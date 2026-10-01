// SPDX-License-Identifier: AGPL-3.0-only

package seed

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Review round 72: round 71 made a seed's URL carry the service's own
// host, so an https endpoint is offered that name as its TLS SNI. A
// web-logs seed with an authored `params.headers.Host` overwrote that
// same variable before the URL was built, so the virtual-host name went
// out as the server name — the two are different questions, and must not
// be the same variable.

func TestAnAuthoredHostIsTheWireHostAndNeverTheServerName(t *testing.T) {
	var mu sync.Mutex
	var serverName, wireHost string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		wireHost = r.Host
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			if serverName == "" {
				serverName = hello.ServerName // "" when the client offered no SNI
			}
			mu.Unlock()
			return nil, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()

	r := &Runner{Resolver: &sniResolver{addr: strings.TrimPrefix(srv.URL, "https://"), port: 9090, scheme: "https"}}
	_, perr := r.Run(context.Background(), Run{
		Instance: "lab", Name: "logs", Generator: "web-logs", Count: 1, SeedValue: "s",
		Params: map[string]any{
			"service": "sink",
			"headers": map[string]any{"Host": "tenant.example"},
		},
	})
	if perr != nil {
		t.Fatalf("the seed did not run: %v", perr)
	}
	mu.Lock()
	defer mu.Unlock()
	if serverName != "sink" {
		t.Fatalf("the TLS handshake offered ServerName %q; the seed delivers to the service sink", serverName)
	}
	if wireHost != "tenant.example" {
		t.Fatalf("the request's Host was %q; the seed authored tenant.example", wireHost)
	}
}
