// SPDX-License-Identifier: AGPL-3.0-only

package seed

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// Plan S10, the drift audit: a seed failure's `next` names the lab it is
// about.
//
// User Manual §14 and UX §6 make `next` an action — "a real button or
// copyable command". These three lines read `podaro status <instance>`,
// `podaro logs <instance> <service>` and `podaro seed <instance> <seed>`:
// a placeholder the operator has to edit before it runs, on a failure that
// already knows which lab it belongs to (Run.Instance, set by the engine
// on every run). A run made without a name keeps the placeholder, since a
// blank would be worse than either.
func TestSeedFailureNamesTheLab(t *testing.T) {
	// The target that cannot be reached: the resolver refuses the dial,
	// as it does for a service that is not running.
	r := &Runner{Resolver: &unreachable{}}
	run := Run{Instance: "pii-lab", Name: "events", Generator: "web-logs", Count: 1,
		Params: map[string]any{"service": "sink", "port": 8080, "path": "/ingest"}, SeedValue: "9f2c66d1a4e07b53"}
	_, perr := r.Run(context.Background(), run)
	if perr == nil {
		t.Fatal("a seed that cannot reach its target fails")
	}
	if !strings.Contains(perr.Next, "podaro status pii-lab") {
		t.Errorf("the next action names the lab: %q", perr.Next)
	}
	if strings.Contains(perr.Next, "<instance>") {
		t.Errorf("a next action with a placeholder cannot be copied: %q", perr.Next)
	}

	// The generic failure line, and the two the request path builds.
	generic := seedErr(run, "request 1 of 1 to sink/ingest failed", errors.New("connection refused"))
	if !strings.Contains(generic.Next, "podaro seed pii-lab events") || strings.Contains(generic.Next, "<instance>") {
		t.Errorf("the re-run action names the lab and the seed: %q", generic.Next)
	}

	// A run with no instance keeps the placeholder rather than printing
	// `podaro seed  events`.
	nameless := seedErr(Run{Name: "events"}, "something", nil)
	if !strings.Contains(nameless.Next, "podaro seed <instance> events") {
		t.Errorf("without a lab the placeholder stands: %q", nameless.Next)
	}
}

// unreachable is a resolver whose dial always fails — a service that is
// not running, from the seed runner's point of view.
type unreachable struct{}

func (unreachable) Resolve(service string, port int) (string, error) {
	return "", errors.New("no container for " + service)
}

func (unreachable) Dial(ctx context.Context, service string, port int) (net.Conn, error) {
	return nil, errors.New("connection refused")
}

func (unreachable) Endpoint(service, purpose string) (int, string, bool) { return 0, "", false }
