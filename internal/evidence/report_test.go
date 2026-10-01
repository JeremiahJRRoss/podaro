// SPDX-License-Identifier: AGPL-3.0-only

package evidence

// Plan S9, API §10's report content contract: what the report must
// carry, what it must not, and that it opens on its own.

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

func sampleReport() ReportData {
	at := time.Date(2026, 9, 7, 10, 30, 0, 0, time.UTC)
	return ReportData{
		Instance: "pii-lab", Template: "conformance-lab", Title: "PII redaction in flight",
		Version: "1.0.0", Profile: "standard", Mode: "delivery",
		Created: at, Generated: at.Add(time.Hour), Engine: "0.1.0",
		Services: []ReportService{{
			Name: "alpha", Module: "alpha",
			Image:  "registry.example.net/team/alpha",
			Digest: "sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
		}},
		Results: []state.CheckpointResult{
			{ID: "alpha-up", Class: "baseline", Adapter: "http", Status: "pass", At: at, Duration: "1.2s",
				Observed: json.RawMessage(`{"status":200}`), Expected: json.RawMessage(`{"status":200}`)},
			{ID: "pii-absent", Class: "objective", Adapter: "http", Status: "fail", At: at, Duration: "0.8s",
				Observed: json.RawMessage(`{"count":200}`), Expected: json.RawMessage(`{"count":0}`),
				Message: "200 documents still carry an SSN", Hint: "add a mask function to the pipeline"},
			{ID: "beta-up", Class: "baseline", Adapter: "http", Status: "error", At: at,
				Error: &pdr.Error{Code: "PDR-E401", Message: "the probe timed out", Cause: "no answer in 30s"}},
			{ID: "reduction", Class: "objective", Status: "", At: time.Time{}},
		},
		Seeds: []ReportSeed{{Name: "events", Generator: "web-logs", Count: 200,
			Duration: "3.1s", At: at, Seed: "0f1e2d3c"}},
		Attendees: []ReportAttendee{{Name: "alice", First: at, Last: at.Add(time.Minute), Joins: 2}},
		Reveals:   []ReportReveal{{Secret: "admin", Actor: "alice", At: at}},
		Milestones: []ReportMilestone{
			{At: at, Event: "ready", Stage: "ready"},
			{At: at, Event: "warning", Code: "PDR-W101", Detail: "an objective was already green at create"},
		},
	}
}

// TestReportCarriesTheContract: everything §10 says it contains.
func TestReportCarriesTheContract(t *testing.T) {
	raw, err := Report(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)
	for _, want := range []string{
		"pii-lab", "conformance-lab", "1.0.0", "delivery", "standard", // instance and template
		"PII redaction in flight",
		// Versions and digests. The repository is named; the registry is
		// not — §10 excludes hostnames, and which registries are internal
		// cannot be known from here, so none is kept.
		"team/alpha", "sha256:aaaabbbbcccc",
		"alpha-up", "pii-absent", "beta-up", // class-split results
		`{&#34;count&#34;:200}`, `{&#34;count&#34;:0}`, // observed vs expected
		"200 documents still carry an SSN", "add a mask function to the pipeline",
		"PDR-E401", "the probe timed out",
		"events", "3.1s", "0f1e2d3c", // seed runs and durations
		"alice",    // the attendee identity
		"admin",    // the reveal, by secret name
		"PDR-W101", // the lifecycle warning
		"not evaluated",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the report does not carry %q", want)
		}
	}
	if strings.Contains(page, "registry.example.net") {
		t.Errorf("the report names the registry an image came from")
	}
	// The classes are split and never summed.
	if !strings.Contains(page, "Baseline") || !strings.Contains(page, "Objective") {
		t.Errorf("the report does not split the two checkpoint classes")
	}
	for _, tally := range []string{
		"1 passed, 0 failed, 0 attested, 1 errored, 0 not evaluated (of 2).", // baseline
		"0 passed, 1 failed, 0 attested, 0 errored, 1 not evaluated (of 2).", // objective
	} {
		if !strings.Contains(page, tally) {
			t.Errorf("missing the tally %q", tally)
		}
	}
}

// TestReportOpensStandalone: no external request, no script. A report
// is forwarded and opened from a mail attachment; one that fetches
// anything is one that tells someone it was opened.
func TestReportOpensStandalone(t *testing.T) {
	raw, err := Report(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)
	if strings.Contains(strings.ToLower(page), "<script") {
		t.Errorf("the report carries a script")
	}
	for _, external := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)<link\b`),
		regexp.MustCompile(`(?i)\bsrc\s*=`),
		regexp.MustCompile(`(?i)@import`),
		regexp.MustCompile(`(?i)url\(\s*['"]?https?:`),
		regexp.MustCompile(`(?i)<img\b`),
		regexp.MustCompile(`(?i)<iframe\b`),
	} {
		if external.MatchString(page) {
			t.Errorf("the report reaches outside itself: %s", external)
		}
	}
	if !strings.Contains(page, "<style>") {
		t.Errorf("the report carries no stylesheet of its own")
	}
}

// TestReportEscapesEveryValue: a template author's text — a checkpoint
// hint, a seed's message — cannot become markup in the report any more
// than it can in the console.
func TestReportEscapesEveryValue(t *testing.T) {
	d := sampleReport()
	d.Results = append(d.Results, state.CheckpointResult{
		ID: "<img src=x onerror=alert(1)>", Class: "baseline", Status: "fail",
		Message: `</table><script>alert("x")</script>`,
		Hint:    `"><b>bold</b>`,
	})
	raw, err := Report(d)
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)
	if strings.Contains(page, "<script>alert") || strings.Contains(page, "<img src=x") {
		t.Fatalf("authored text became markup")
	}
	if !strings.Contains(page, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Fatalf("the id is not rendered as the text it is")
	}
}

// TestReportExcludesAddressesAndHostnames: the §10 exclusions, applied
// to the free text a result carries.
func TestReportExcludesAddressesAndHostnames(t *testing.T) {
	d := sampleReport()
	d.Scrub = Scrubber("lab.example.com")
	d.Results = append(d.Results, state.CheckpointResult{
		ID: "reachable", Class: "baseline", Status: "error", Adapter: "http",
		Message: "dial tcp 203.0.113.10:9200: connection refused",
		Hint:    "is https://alpha-pii-lab.lab.example.com/ up?",
		Error: &pdr.Error{Code: "PDR-E401", Message: "no answer from pii-lab.lab.example.com",
			Cause: "the host 2001:db8::1 did not reply"},
	})
	raw, err := Report(d)
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)
	for _, leak := range []string{"203.0.113.10", "2001:db8::1", "lab.example.com"} {
		if strings.Contains(page, leak) {
			t.Errorf("the report leaks %q", leak)
		}
	}
	// The service is still named — the exclusion is the hostname, not
	// the identity a reader needs.
	if !strings.Contains(page, "alpha") {
		t.Errorf("scrubbing took the service name with the hostname")
	}
	if !strings.Contains(page, "[address withheld]") {
		t.Errorf("an address was removed without saying so")
	}
}

// TestScrubber pins the filter itself, including what it must leave
// alone: a dotted word is not a hostname.
func TestScrubber(t *testing.T) {
	scrub := Scrubber("lab.example.com")
	for _, tc := range []struct{ in, want string }{
		{"https://alpha-pii-lab.lab.example.com/_search", "https://alpha-pii-lab/_search"},
		{"pii-lab.lab.example.com", "pii-lab"},
		{"connect 10.88.0.7:9200", "connect [address withheld]:9200"},
		{"fe80::1%eth0", "[address withheld]%eth0"},
		// Left alone: not this domain, not an address.
		{"lab.podaro.dev/v1alpha1", "lab.podaro.dev/v1alpha1"},
		{"podaro.jobs.finished", "podaro.jobs.finished"},
		{"alpha", "alpha"},
		{"a.lab.example.company", "a.lab.example.company"},
		{"version 1.0.0", "version 1.0.0"},
	} {
		if got := scrub(tc.in); got != tc.want {
			t.Errorf("scrub(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// Before `podaro setup` there is no domain to cut back to, so a
	// hostname cannot be reduced to the service it names — but a host
	// named as a host is still a host, and is withheld. This assertion
	// used to require that nothing but an address was touched; that was
	// a statement about not *guessing* at hostnames, and the rule no
	// longer guesses — it reads the syntax that says "this is a host".
	bare := Scrubber("")
	if got := bare("https://alpha-pii-lab.lab.example.com/ at 10.0.0.1"); got != "https://[hostname withheld]/ at [address withheld]" {
		t.Errorf("scrubber with no domain: %q", got)
	}
	// And it still does not guess: a dotted word that is not named as a
	// host is left as written, domain or no domain.
	if got := bare("apiVersion lab.podaro.dev/v1alpha1"); got != "apiVersion lab.podaro.dev/v1alpha1" {
		t.Errorf("scrubber with no domain mangled ordinary text: %q", got)
	}
}
