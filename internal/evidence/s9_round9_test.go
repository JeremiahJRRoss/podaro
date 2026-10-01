// SPDX-License-Identifier: AGPL-3.0-only

package evidence

import (
	"strings"
	"testing"
)

// The fourth shape, and the one I asked the review to look for: a
// scheme-relative authority. `//svc:…@db.internal/health` is a valid URL
// reference, and both URL rules wanted an explicit `<scheme>://` while
// `hostPort` cannot cross the `@` — so the credential and the host went
// out together, past both of round 8's guarantees.
//
// The authority is now recognised with or without its scheme. Without
// one it must begin the text or follow a byte that cannot continue a
// path, which is what keeps the rule off the second slash of
// `…/a.b//report.junit.xml`.
func TestASchemeRelativeAuthorityIsAnAuthority(t *testing.T) {
	scrub := Scrubber("lab.example.com")
	for _, c := range []struct{ name, in, want string }{
		{"a scheme-relative host", "GET //db.internal/health failed", "GET //[hostname withheld]/health failed"},
		{"scheme-relative with userinfo", "GET //reader@db.internal/health failed", "GET //[hostname withheld]/health failed"},
		{"at the very start of the text", "//db.internal/health is down", "//[hostname withheld]/health is down"},
		{"scheme-relative under this deployment's domain", "see //beta-pii-lab.lab.example.com/app", "see //beta-pii-lab/app"},

		// The false positives the rule must not create: a doubled slash
		// inside a path is a path, not an authority.
		{"a doubled slash in a path", "wrote /var/log//report.junit.xml", "wrote /var/log//report.junit.xml"},
		{"a doubled slash after a URL's host", "GET https://db.internal//report.junit.xml", "GET https://[hostname withheld]//report.junit.xml"},
		{"a comment, not an authority", "// see report.junit.xml", "// see report.junit.xml"},

		// Round 8's cases, unchanged.
		{"a URL with userinfo", "GET https://reader@db.internal/health failed", "GET https://[hostname withheld]/health failed"},
		{"an uppercase name under this domain", "DB.LAB.EXAMPLE.COM is down", "DB is down"},
		{"an address after a URL", "see https://x.io/ and mail ops@corp.internal", "see https://[hostname withheld]/ and mail ops@corp.internal"},
		{"an API group", "apiVersion lab.podaro.dev/v1alpha1", "apiVersion lab.podaro.dev/v1alpha1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := scrub(c.in); got != c.want {
				t.Errorf("scrub(%q)\n got %q\nwant %q", c.in, got, c.want)
			}
		})
	}
}

// The credential half of the same hole. The assertions name the case and
// never echo the value, so a failure here cannot print what it is
// complaining about.
func TestASchemeRelativeURLsUserinfoNeverReachesTheReport(t *testing.T) {
	const cred = "s3cr3t-in-a-url" // a fixture, not a secret this tree holds
	scrub := Scrubber("lab.example.com")
	for _, c := range []struct{ name, in string }{
		{"password in a scheme-relative authority", "curl //svc:" + cred + "@db.internal/health failed"},
		{"a name alone", "GET //" + cred + "@db.internal/health"},
		{"under this deployment's own domain", "GET //svc:" + cred + "@es.lab.example.com/health"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if strings.Contains(scrub(c.in), cred) {
				t.Error("the userinfo of a scheme-relative URL survived the scrubber: a credential in a forwardable report")
			}
		})
	}
}
