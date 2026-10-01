// SPDX-License-Identifier: AGPL-3.0-only

package runtime

// TLS on the ports a service declares as https (plan S8). A checkpoint
// or a readiness probe that names https must meet a real handshake here
// — otherwise the fake would prove the adapter against a scheme the
// product does not speak. The mechanism is the platform's, so it lives
// in its own file, beside a vendor-neutral personality that exercises
// it (the reconciliation plan's R1); a product personality opts in
// through the tlsProduct interface.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"
)

// tlsProduct is a personality that answers TLS on some of its container
// ports.
type tlsProduct interface {
	servesTLS(port int) bool
}

// fakeTLSEcho is the vendor-neutral https personality (`example/tls-echo`):
// every port it publishes answers a real handshake and then 200, so the
// engine's probe (internal/engine/tls.go) and the http adapter are
// proven against https with no product in the picture. Plain HTTP on
// one of its ports meets the handshake and is refused, as it would be
// by any TLS listener.
type fakeTLSEcho struct {
	name string
}

func (p *fakeTLSEcho) servesTLS(int) bool { return true }

func (p *fakeTLSEcho) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "fake %s ok · tls · path %s\n", p.name, r.URL.Path)
}

// fakeCert is the self-signed certificate the fake's TLS ports present —
// one per process, as a lab product's own would be. The adapters and the
// probe accept it the way they accept a lab's: without verifying the
// chain, so the names it carries are not load-bearing.
var (
	fakeCertOnce sync.Once
	fakeCertVal  *tls.Certificate
	fakeCertErr  error
)

func fakeCertificate() (*tls.Certificate, error) {
	fakeCertOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fakeCertErr = err
			return
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			fakeCertErr = err
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "podaro-fake-product"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			DNSNames:              []string{"localhost"},
			IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			fakeCertErr = err
			return
		}
		fakeCertVal = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	})
	return fakeCertVal, fakeCertErr
}
