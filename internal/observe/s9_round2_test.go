// SPDX-License-Identifier: AGPL-3.0-only

package observe

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/config"
)

// Round 1 made `observe test` withhold every probe when the filter
// cannot be built — correctly — but it wrote one failure for logs,
// metrics and traces whatever was configured. §5 says an unconfigured
// signal is *absent* from the answer, so a logs-only deployment was told
// that two exporters it does not have had failed, with empty exporter
// and endpoint fields.
func TestWithheldProbesFollowTheConfiguration(t *testing.T) {
	c := newCapture(t)
	e, err := New(Options{Config: &config.Observability{
		Attributes: map[string]string{"deployment.region": "eu-west-1"},
		Logs:       &config.Signal{Exporter: "http", Endpoint: c.srv.URL},
	}, Filter: func() (func(string) string, error) {
		return nil, errors.New("PDR-E412 the secret store cannot be read")
	}})
	if err != nil {
		t.Fatal(err)
	}
	probes := e.Test(context.Background())
	if len(probes) != 1 {
		t.Fatalf("%d probes for a logs-only deployment: %+v", len(probes), probes)
	}
	p := probes[0]
	if p.Signal != "logs" || p.OK {
		t.Errorf("the one probe is a failed logs probe: %+v", p)
	}
	// It still says which exporter and endpoint it was for: a withheld
	// probe an operator cannot place is a row they cannot act on.
	if p.Exporter == "" || p.Endpoint == "" {
		t.Errorf("the withheld probe names neither exporter nor endpoint: %+v", p)
	}
	if c.all() != "" {
		t.Errorf("something was sent despite the filter failing")
	}
}
