// SPDX-License-Identifier: AGPL-3.0-only

package doctor

import (
	"testing"

	"github.com/jeremiahjrross/podaro/internal/config"
)

// withLegal is the fixture host with the optional legal-notices probe.
type withLegal struct {
	fakeProbes
	present bool
}

func (w withLegal) LegalNotices() (string, bool) { return "~/.local/state/podaro/legal/", w.present }

// Doctor gains a row only when <state>/legal/ is missing (the
// reconciliation plan's R5, task 3): a warning that names the command
// that writes it, never a failure — `podaro legal` reads the binary.
// Present, or on a host whose probes do not ask, the board is the one
// INSTALL §2 step 3 shows.
func TestDoctorNamesAMissingLegalDirectoryOnly(t *testing.T) {
	cfg := &config.Config{Gateway: config.Gateway{Port: 7777}}
	count := func(r Report) int {
		n := 0
		for _, c := range r.Checks {
			if c.ID == "legal-notices" {
				n++
			}
		}
		return n
	}
	if n := count(Run(fakeProbes{}, cfg)); n != 0 {
		t.Fatalf("a host whose probes do not ask got %d legal row(s)", n)
	}
	if n := count(Run(withLegal{present: true}, cfg)); n != 0 {
		t.Fatalf("a present directory got %d legal row(s)", n)
	}
	r := Run(withLegal{present: false}, cfg)
	if count(r) != 1 {
		t.Fatalf("a missing directory got %d legal row(s)", count(r))
	}
	for _, c := range r.Checks {
		if c.ID == "legal-notices" && (c.Status != Warn || c.Finding != "~/.local/state/podaro/legal/ missing · podaro system install writes it (podaro legal prints the same)") {
			t.Fatalf("the row: %+v", c)
		}
	}
	if base := Run(fakeProbes{}, cfg); r.Summary.Fail != base.Summary.Fail || r.Summary.Warn != base.Summary.Warn+1 {
		t.Fatalf("the row is a warning and nothing else: %+v against %+v", r.Summary, base.Summary)
	}
}
