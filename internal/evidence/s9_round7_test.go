// SPDX-License-Identifier: AGPL-3.0-only

package evidence

import "testing"

// The scrubber removed addresses and names under this deployment's
// domain, and the footer claimed "full internal hostnames are excluded".
// `https://db.internal/health` in a checkpoint message went out whole.
//
// A host is withheld where it is named as one — a URL's authority, or a
// name with a port. A bare dotted word is not: the false positives are
// worse than the miss, and the report now claims exactly what it does.
func TestAHostNamedAsAHostIsWithheld(t *testing.T) {
	scrub := Scrubber("lab.example.com")
	for _, c := range []struct{ name, in, want string }{
		{"a URL authority", "GET https://db.internal/health failed", "GET https://[hostname withheld]/health failed"},
		{"a host with a port", "dial tcp db.internal:5432: refused", "dial tcp [hostname withheld]:5432: refused"},
		{"an address is still an address", "dial tcp 10.0.0.5:9200: refused", "dial tcp [address withheld]:9200: refused"},
		{"an address in a URL", "GET https://10.0.0.5/health", "GET https://[address withheld]/health"},
		// The deployment's own domain still reads as the service, which
		// is the name the rest of the report uses — the URL rule must
		// not undo that by withholding the label it leaves behind.
		{"this deployment's own host", "is https://alpha-pii-lab.lab.example.com/ up?", "is https://alpha-pii-lab/ up?"},
		// And the words a report prints stay printed.
		{"an API group", "apiVersion lab.podaro.dev/v1alpha1", "apiVersion lab.podaro.dev/v1alpha1"},
		{"a metric name", "podaro.jobs.finished is 3", "podaro.jobs.finished is 3"},
		{"a file name", "see report.junit.xml", "see report.junit.xml"},
		{"a clock time", "started 10:30:00", "started 10:30:00"},
		{"a version", "engine 1.0.0", "engine 1.0.0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := scrub(c.in); got != c.want {
				t.Errorf("scrub(%q)\n got %q\nwant %q", c.in, got, c.want)
			}
		})
	}
}
