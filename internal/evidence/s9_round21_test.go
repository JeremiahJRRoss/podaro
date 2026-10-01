// SPDX-License-Identifier: AGPL-3.0-only

package evidence

import (
	"testing"
)

// The host rules required the final label to be two or more *letters* —
// a guess about top-level domains rather than a fact about DNS. A host
// named in authored text as `https://db.corp1/health`, an internal name
// of exactly the kind a lab's notes carry, was matched only as far as
// `db.corp` and the report went out reading `[hostname withheld]1`: the
// label that identifies the host, left behind by the rule that exists to
// remove it. With a port and no scheme, nothing matched at all.
func TestAHostIsWithheldWhateverItsLastLabel(t *testing.T) {
	scrub := Scrubber("lab.example.com")
	for _, tc := range []struct{ name, in, want string }{
		{"digit in the final label", "see https://db.corp1/health for the fork",
			"see https://[hostname withheld]/health for the fork"},
		{"digits only", "see https://svc.corp2024/x", "see https://[hostname withheld]/x"},
		{"hyphen in the final label", "see https://svc.my-corp/x", "see https://[hostname withheld]/x"},
		{"punycode", "see https://xn--80ak6aa92e.xn--p1ai/health", "see https://[hostname withheld]/health"},
		{"with a port, no scheme", "curl db.corp1:9200/_cluster/health",
			"curl [hostname withheld]:9200/_cluster/health"},
		{"the ordinary case still holds", "see https://es.corp.example/x",
			"see https://[hostname withheld]/x"},
	} {
		if got := scrub(tc.in); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}

	// And the words the report prints are still its own: a dotted string
	// that is not an authority is untouched, which is the property the
	// narrow rule was protecting.
	for _, keep := range []string{
		"apiVersion: lab.podaro.dev/v1alpha1",
		"the file lab.yaml at line 12",
		"version 1.2.3 of the module",
		"the checkpoint pii-absent-beta is red",
	} {
		if got := scrub(keep); got != keep {
			t.Errorf("the report mangled its own words: %q → %q", keep, got)
		}
	}
}
