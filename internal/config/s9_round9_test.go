// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// A destination credential belongs in a 0600 `token_file` and nowhere
// else — that is why `token_file`'s mode is checked three lines below.
// An endpoint written `https://user:…@collector.internal` put the same
// credential in the config file, in the posture `GET /system/observe`
// returns, and in the line the engine prints at every start.
//
// The endpoint is refused, and the refusal — like every other message
// about a credential — does not repeat it.
func TestAnEndpointMayNotCarryUserinfo(t *testing.T) {
	const cred = "s3cr3t-in-a-url" // a fixture, not a secret this tree holds
	for _, c := range []struct{ name, endpoint string }{
		{"user and password", "https://svc:" + cred + "@collector.internal:4318"},
		{"a name alone", "https://" + cred + "@collector.internal:4318"},
		// The neighbour: an endpoint that fails the *scheme* check took
		// the same path and its message printed the whole URL.
		{"not an http(s) URL", "ftp://svc:" + cred + "@collector.internal"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(write(t, "observability:\n  logs: { exporter: otlp, endpoint: \""+c.endpoint+"\" }\n"))
			e := asPDR(t, err, pdr.CodeConfigInvalid)
			if strings.Contains(e.Message, cred) || strings.Contains(e.Cause, cred) {
				t.Fatal("the refusal repeated the credential it was refusing")
			}
			if !strings.Contains(e.Message, "endpoint") {
				t.Fatalf("message %q should name the endpoint", e.Message)
			}
		})
	}
}

// And an endpoint with no userinfo is still accepted, with its host and
// port intact — the rule must not cost the operator a working config.
func TestAnEndpointWithoutUserinfoIsStillAccepted(t *testing.T) {
	c, err := Load(write(t, "observability:\n  logs: { exporter: otlp, endpoint: https://collector.internal:4318 }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Observability.Logs.Endpoint; got != "https://collector.internal:4318" {
		t.Fatalf("endpoint came back %q", got)
	}
}
