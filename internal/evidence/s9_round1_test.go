// SPDX-License-Identifier: AGPL-3.0-only

package evidence

import (
	"strings"
	"testing"
)

// The "What ran" table prints each service's image, and an image
// reference carries a registry: a lab pulled from an internal one names
// a host address or an internal hostname there. Every other free-text
// field on the page goes through the scrubber; this one did not — so the
// report disclosed exactly what the note beneath the table says it
// excludes, on the one row an operator is most likely to forward.
func TestTheImageATableNamesIsScrubbedLikeEverythingElse(t *testing.T) {
	d := sampleReport()
	d.Scrub = Scrubber("lab.example.com")
	d.Services = []ReportService{
		{Name: "alpha", Module: "alpha",
			Image:  "10.0.0.5/team/alpha",
			Digest: "sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"},
		{Name: "beta", Module: "beta",
			Image:  "registry.lab.example.com/team/beta",
			Digest: "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"},
	}
	raw, err := Report(d)
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)
	for _, leak := range []string{"10.0.0.5", "registry.lab.example.com", "lab.example.com"} {
		if strings.Contains(page, leak) {
			t.Errorf("the report leaks %q from an image reference", leak)
		}
	}
	// What the table is for survives: the repository, and the digest that
	// says what actually ran.
	for _, keep := range []string{"team/alpha", "team/beta", "sha256:aaaabbbb"} {
		if !strings.Contains(page, keep) {
			t.Errorf("scrubbing took %q with the registry", keep)
		}
	}
	// Round 2: the registry host comes off the reference before the
	// scrubber sees it, so what the page says is that a registry was
	// withheld — an address the scrubber caught would have said so too,
	// and TestReportExcludesAddressesAndHostnames still pins that.
	if !strings.Contains(page, "[registry withheld]") {
		t.Errorf("a registry was removed without saying so")
	}
}
