// SPDX-License-Identifier: AGPL-3.0-only

package evidence

import (
	"strings"
	"testing"
)

// Round 1 sent the image through the scrubber, and the scrubber removes
// addresses and *this deployment's* domain — which an internal registry
// usually is not. `registry.corp/team/product` went out untouched: the
// finding round 1 was answering, still standing in the revision that
// answered it.
//
// The registry host comes off the reference now, by the OCI rule, before
// anything else looks at it.
func TestAnImageNamesNoRegistryAtAll(t *testing.T) {
	for _, c := range []struct{ name, image, want string }{
		{"an internal registry the scrubber cannot know", "registry.corp/team/product", "[registry withheld]/team/product"},
		{"a public one, since which is which is not knowable here", "registry.example.net/alpha/alpha", "[registry withheld]/alpha/alpha"},
		{"an address", "10.0.0.5/team/product", "[registry withheld]/team/product"},
		{"a port makes it a host too", "registry:5000/team/product", "[registry withheld]/team/product"},
		{"localhost is a registry by the same rule", "localhost/team/product", "[registry withheld]/team/product"},
		// A Docker Hub short name has no host: the first element is the
		// namespace, and removing it would name a different image.
		{"a short name has no registry", "library/nginx", "library/nginx"},
		{"a bare name has none either", "nginx", "nginx"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := sampleReport()
			d.Scrub = Scrubber("lab.example.com")
			d.Services = []ReportService{{Name: "svc", Module: "m", Image: c.image,
				Digest: "sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"}}
			raw, err := Report(d)
			if err != nil {
				t.Fatal(err)
			}
			page := string(raw)
			if !strings.Contains(page, c.want) {
				t.Errorf("the report does not carry %q", c.want)
			}
			if host, _, ok := strings.Cut(c.image, "/"); ok && c.want != c.image && strings.Contains(page, host) {
				t.Errorf("the report still names the registry %q", host)
			}
		})
	}
}
