// SPDX-License-Identifier: AGPL-3.0-only

package evidence

import (
	"strings"
	"testing"
	"time"
)

// An attendee's name is the access name an operator chose, and
// `CheckUsername` allows digits and dots: `10.0.0.5` is a name a link
// can be issued to. It was rendered as authored, in the attendee table
// and again as a reveal's actor, so the report carried a host address
// under its own exclusion contract.
//
// Round 5 looked at this field and left it, on the reasoning that
// scrubbing a name might mangle a legitimate one. That weighed a
// hypothetical against a stated contract.
func TestAnIdentityThatLooksLikeAnAddressIsWithheld(t *testing.T) {
	at := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	d := sampleReport()
	d.Scrub = Scrubber("lab.example.com")
	d.Attendees = []ReportAttendee{
		{Name: "alice", First: at, Last: at, Joins: 1},
		{Name: "10.0.0.5", First: at, Last: at, Joins: 1},
	}
	d.Reveals = []ReportReveal{
		{Secret: "admin", Actor: "alice", At: at},
		{Secret: "admin", Actor: "10.0.0.5", At: at},
	}
	raw, err := Report(d)
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)
	if strings.Contains(page, "10.0.0.5") {
		t.Errorf("the report names an attendee that is a host address")
	}
	// An ordinary name is untouched: the identity is what the report is
	// for, and only a name shaped like an address is withheld.
	if !strings.Contains(page, "alice") {
		t.Errorf("scrubbing took an ordinary attendee name with it")
	}
	if !strings.Contains(page, "[address withheld]") {
		t.Errorf("an address was removed without saying so")
	}
}
