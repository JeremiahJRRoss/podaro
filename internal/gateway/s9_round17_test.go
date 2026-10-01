// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"strings"
	"testing"
)

// Round 16 put the generation check in the round trip, and a check is
// still something that finishes before the transport picks a connection.
// A stale request can pass it, pause while the lab is destroyed and its
// name taken, and resume onto a connection a current-generation request
// has since put in the shared pool.
//
// `http.Transport` pools by the address it is asked for, so the answer
// is not a better-timed check: it is that two generations never address
// the same upstream. Then there is no shared entry to reuse, and the
// question of when the check runs stops mattering.
func TestTwoGenerationsNeverSharePoolKey(t *testing.T) {
	var older, newer int64 = 7, 8
	a := upstreamHostFor("lab", "web", &older)
	b := upstreamHostFor("lab", "web", &newer)
	if a == b {
		t.Fatalf("both generations address %q, so they share a pooled connection", a)
	}

	// Each still names the instance and service it is for, or the
	// route guard and the dialer could not act on it.
	for _, host := range []string{a, b} {
		instance, service, ok := upstreamParts(host)
		if !ok || instance != "lab" || service != "web" {
			t.Fatalf("upstreamParts(%q) = %q, %q, %v", host, instance, service, ok)
		}
	}

	// The operator, entitled to no generation, keeps the plain upstream
	// and the pool it has always used.
	plain := upstreamHostFor("lab", "web", nil)
	if plain != upstreamHost("lab", "web") {
		t.Errorf("an unbound caller's upstream changed: %q", plain)
	}
	if strings.Contains(plain, ".g") {
		t.Errorf("an unbound caller's upstream carries a generation: %q", plain)
	}

	// A negative generation is a real one — an unknown job carries -1 —
	// and must survive the round trip through the host name.
	var unknown int64 = -1
	if instance, service, ok := upstreamParts(upstreamHostFor("lab", "web", &unknown)); !ok || instance != "lab" || service != "web" {
		t.Errorf("a negative generation broke the upstream name: %q %q %v", instance, service, ok)
	}
}
