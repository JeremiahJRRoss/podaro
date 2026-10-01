// SPDX-License-Identifier: AGPL-3.0-only

package evidence

import (
	"strings"
	"testing"
)

// The heading is the template's own title — free text up to 80
// characters by schema — and it was the one free-text field on the page
// that did not pass the scrubber. Its neighbours cannot carry a host:
// `metadata.name` is a DNS label and `version` is three numbers.
func TestTheTitleIsScrubbedLikeEveryOtherPieceOfFreeText(t *testing.T) {
	d := sampleReport()
	d.Scrub = Scrubber("lab.example.com")
	d.Title = "Investigate 10.0.0.5 and alpha-pii-lab.lab.example.com"
	raw, err := Report(d)
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)
	for _, leak := range []string{"10.0.0.5", "lab.example.com"} {
		if strings.Contains(page, leak) {
			t.Errorf("the report's heading leaks %q", leak)
		}
	}
	// The title is still a title: what the scrubber takes is the host,
	// not the words around it.
	if !strings.Contains(page, "Investigate") {
		t.Errorf("scrubbing took the title with the address")
	}
	if !strings.Contains(page, "[address withheld]") {
		t.Errorf("an address was removed without saying so")
	}
}
