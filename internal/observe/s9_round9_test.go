// SPDX-License-Identifier: AGPL-3.0-only

package observe

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/config"
)

// The `insecure` escape hatch replaced the client's transport with a
// zero-valued one, which is not "the same transport without
// verification" — it is a different transport with nothing configured.
// A destination that needs `HTTPS_PROXY` became unreachable for exactly
// the one signal the operator marked insecure, and any transport a
// caller supplied was discarded with it.
//
// The effective transport is cloned and only its TLS configuration is
// changed.
func TestTheInsecureClientKeepsTheTransportItWasGiven(t *testing.T) {
	base := &http.Transport{
		Proxy:               func(*http.Request) (*url.URL, error) { return nil, nil },
		MaxIdleConnsPerHost: 7,
	}
	e, err := New(Options{
		Config: &config.Observability{
			Logs:    &config.Signal{Exporter: "http", Endpoint: "https://collector.internal/records", Insecure: true},
			Metrics: &config.Signal{Exporter: "http", Endpoint: "https://collector.internal/records"},
		},
		Filter: identity,
		Client: &http.Client{Transport: base, Timeout: RequestTimeout},
	})
	if err != nil {
		t.Fatal(err)
	}

	lax, ok := e.logs.(*httpSink).client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("the insecure signal's transport is not an *http.Transport")
	}
	if lax.Proxy == nil {
		t.Error("the insecure signal lost the transport's proxy: a destination reached through HTTPS_PROXY cannot be reached at all")
	}
	if lax.MaxIdleConnsPerHost != 7 {
		t.Errorf("the insecure signal lost the transport's settings: MaxIdleConnsPerHost is %d, not 7", lax.MaxIdleConnsPerHost)
	}
	if lax.TLSClientConfig == nil || !lax.TLSClientConfig.InsecureSkipVerify {
		t.Error("the escape hatch the operator asked for did not take effect")
	}

	// And the escape hatch stays where it was opened: the verifying
	// client is the one every other signal keeps.
	strict, ok := e.metrics.(*httpSink).client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("the verifying signal's transport is not an *http.Transport")
	}
	if strict.TLSClientConfig != nil && strict.TLSClientConfig.InsecureSkipVerify {
		t.Error("marking one signal insecure stopped another one verifying")
	}
	// Not "the caller's TLSClientConfig is still nil": Transport.Clone
	// materialises the HTTP/2 defaults on its *receiver*, so the field
	// stops being nil whoever clones it. What must hold is the thing
	// that matters — the caller's transport still verifies.
	if base.TLSClientConfig != nil && base.TLSClientConfig.InsecureSkipVerify {
		t.Error("the transport the caller supplied was made insecure in place")
	}
}

// A destination credential belongs in a 0600 `token_file`. The config
// refuses an endpoint that carries userinfo, and this is the second
// line of that defence: whatever an exporter was built with, the
// endpoint it *shows* — in `GET /system/observe`, in `observe test`, and
// in the line printed at every start — carries no credential.
//
// The assertions name the case and never echo the value.
func TestAShownEndpointCarriesNoCredential(t *testing.T) {
	const cred = "s3cr3t-in-a-url" // a fixture, not a secret this tree holds
	e, err := New(Options{Config: &config.Observability{
		Logs: &config.Signal{Exporter: "http", Endpoint: "https://svc:" + cred + "@collector.internal/records"},
	}, Filter: identity})
	if err != nil {
		t.Fatal(err)
	}
	p := e.Posture()
	if strings.Contains(p.Logs.Endpoint, cred) {
		t.Error("the posture showed the endpoint's credential")
	}
	if !strings.Contains(p.Logs.Endpoint, "collector.internal") {
		t.Errorf("the posture no longer says where the export goes: %q", p.Logs.Endpoint)
	}
	for _, pb := range e.Test(context.Background()) {
		if strings.Contains(pb.Endpoint, cred) {
			t.Error("a probe showed the endpoint's credential")
		}
	}
}
