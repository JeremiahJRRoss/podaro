// SPDX-License-Identifier: AGPL-3.0-only

package seed

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Review round 71: a seed built its request URL from the resolved
// loopback address, so an https endpoint was reached with the TLS server
// name taken from an IP — that is, with no SNI. The dialer ignores the
// address, so the service's own host costs nothing to keep and is what
// SNI comes from.

type sniResolver struct {
	addr   string
	port   int
	scheme string
}

func (s *sniResolver) Resolve(service string, port int) (string, error) { return s.addr, nil }
func (s *sniResolver) Dial(ctx context.Context, service string, port int) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", s.addr)
}
func (s *sniResolver) Endpoint(service, purpose string) (int, string, bool) {
	return s.port, s.scheme, true
}

func TestASeedOffersTheServiceNameAsSNI(t *testing.T) {
	var got string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if got == "" {
				got = hello.ServerName // "" when the client offered no SNI
			}
			return nil, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()

	r := &Runner{Resolver: &sniResolver{addr: strings.TrimPrefix(srv.URL, "https://"), port: 9090, scheme: "https"}}
	rep, perr := r.Run(context.Background(), Run{
		Instance: "lab", Name: "probe", Generator: "http-requests", Count: 1, SeedValue: "s",
		Params: map[string]any{"service": "prometheus"},
	})
	if perr != nil {
		t.Fatalf("the seed did not run: %v", perr)
	}
	if rep == nil {
		t.Fatal("no report")
	}
	if got != "prometheus" {
		t.Fatalf("the TLS handshake offered ServerName %q; the seed named the service prometheus", got)
	}
}
