// SPDX-License-Identifier: AGPL-3.0-only

package evidence

import (
	"strings"
	"testing"
)

// Round 7 narrowed the guarantee to "a host named as a host" and left
// three ways past it. A URL's authority may carry userinfo, and the
// pattern wanted the hostname immediately after `://`, so
// `https://reader@db.internal/health` went out whole. The domain cut
// compared bytes, and DNS does not: `DB.LAB.EXAMPLE.COM` was not
// recognised as this deployment's own name, and having no port and no
// scheme it then passed both of the other rules too.
//
// The authority goes whole, userinfo included — a URL that carries a
// password carries it into a forwardable report otherwise — and the
// suffix is matched without regard to case.
func TestAHostNamedAsAHostIsWithheldWhateverItsShape(t *testing.T) {
	scrub := Scrubber("lab.example.com")
	for _, c := range []struct{ name, in, want string }{
		{"a URL with userinfo", "GET https://reader@db.internal/health failed", "GET https://[hostname withheld]/health failed"},
		{"userinfo and a port", "dial https://svc@db.internal:8443/x", "dial https://[hostname withheld]:8443/x"},
		{"an uppercase name under this domain", "DB.LAB.EXAMPLE.COM is down", "DB is down"},
		{"a mixed-case name with a port", "dial tcp db.LAB.example.com:9200: refused", "dial tcp db:9200: refused"},
		{"a mixed-case name in a URL", "is https://Beta-PII-Lab.Lab.Example.COM/ up?", "is https://Beta-PII-Lab/ up?"},

		// The boundary the userinfo rule must not cross: `@` counts only
		// inside an authority, which ends at the first `/` or space. An
		// address in prose is a bare dotted word, and stays one.
		{"an address after a URL", "see https://x.io/ and mail ops@corp.internal", "see https://[hostname withheld]/ and mail ops@corp.internal"},

		// Round 7's cases, unchanged: the rules were widened, not swapped.
		{"a URL authority", "GET https://db.internal/health failed", "GET https://[hostname withheld]/health failed"},
		{"a host with a port", "dial tcp db.internal:5432: refused", "dial tcp [hostname withheld]:5432: refused"},
		{"this deployment's own host", "is https://alpha-pii-lab.lab.example.com/ up?", "is https://alpha-pii-lab/ up?"},
		{"an API group", "apiVersion lab.podaro.dev/v1alpha1", "apiVersion lab.podaro.dev/v1alpha1"},
		{"a file name", "see report.junit.xml", "see report.junit.xml"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := scrub(c.in); got != c.want {
				t.Errorf("scrub(%q)\n got %q\nwant %q", c.in, got, c.want)
			}
		})
	}
}

// A URL's userinfo is a credential by construction. Invariant 6 says a
// secret never appears in evidence, and the report is the one artefact
// built to leave the building — so the authority goes whole rather than
// keeping the half in front of the `@`.
//
// The assertions name the case and never echo the value, so a failure
// here cannot print what it is complaining about.
func TestAURLsUserinfoNeverReachesTheReport(t *testing.T) {
	const cred = "s3cr3t-in-a-url" // a fixture, not a secret this tree holds
	scrub := Scrubber("lab.example.com")
	for _, c := range []struct{ name, in string }{
		{"password in an error cause", "curl https://svc:" + cred + "@db.internal:8443/x failed"},
		{"a name alone", "GET https://" + cred + "@db.internal/health"},
		{"under this deployment's own domain", "GET https://svc:" + cred + "@es.lab.example.com/health"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if strings.Contains(scrub(c.in), cred) {
				t.Error("the userinfo of a URL survived the scrubber: a credential in a forwardable report")
			}
		})
	}
}

// The footer is the line a recipient reads, and it claimed more than the
// filter does: "no internal hostname", while a bare dotted word an
// author wrote is deliberately left as written. The services note and
// API §10 were narrowed in round 7; this one was not.
func TestTheFooterClaimsWhatTheFilterDoes(t *testing.T) {
	d := sampleReport()
	d.Milestones = append(d.Milestones, ReportMilestone{
		At: d.Generated, Event: "note", Detail: "checked db.internal by hand",
	})
	raw, err := Report(d)
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)
	i := strings.Index(page, "<footer>")
	if i < 0 {
		t.Fatal("the report has no footer")
	}
	footer := page[i:]
	// The report keeps the bare dotted word, by the rule round 7 set.
	if !strings.Contains(page, "db.internal") {
		t.Fatal("the fixture no longer exercises a preserved bare hostname")
	}
	if strings.Contains(footer, "no internal hostname") {
		t.Error("the footer still promises no internal hostname while the report prints one")
	}
	for _, want := range []string{"host address", "own domain", "named as one"} {
		if !strings.Contains(footer, want) {
			t.Errorf("the footer does not state the exclusion %q that the services note and API §10 do", want)
		}
	}
}
