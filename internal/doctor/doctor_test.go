// SPDX-License-Identifier: AGPL-3.0-only

package doctor

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// fakeProbes replays the exact broken host the INSTALL manual documents in
// §2 step 3: podman fine, subids fine, lingering off, low max_map_count,
// port free, 118 GB disk, no domain configured.
type fakeProbes struct{}

func (fakeProbes) Username() string { return "jross" }
func (fakeProbes) PodmanInfo() (PodmanFacts, error) {
	return PodmanFacts{Version: "4.9.4", Rootless: true, CgroupVersion: "v2"}, nil
}
func (fakeProbes) SubIDs(string) (IDRange, IDRange, error) {
	r := IDRange{Start: 165536, Count: 65536}
	return r, r, nil
}
func (fakeProbes) Linger(string) (bool, error)     { return false, nil }
func (fakeProbes) MaxMapCount() (int, error)       { return 65530, nil }
func (fakeProbes) PortFree(int) (bool, error)      { return true, nil }
func (fakeProbes) DiskFree(string) (uint64, error) { return 118_500_000_000, nil }
func (fakeProbes) LookupHost(string) ([]string, error) {
	return nil, errors.New("not configured")
}

// installBlock extracts the fenced acceptance block that follows the given
// command line in public-docs/INSTALL.md — the docs are the golden files.
func installBlock(t *testing.T, command string) string {
	t.Helper()
	raw, err := os.ReadFile("../../public-docs/INSTALL.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	marker := "```\n" + command + "\n"
	start := strings.Index(doc, marker)
	if start < 0 {
		t.Fatalf("INSTALL.md has no fenced block starting %q", command)
	}
	rest := doc[start+len(marker):]
	end := strings.Index(rest, "```")
	if end < 0 {
		t.Fatalf("unterminated fence after %q", command)
	}
	return rest[:end]
}

// TestDoctorMatchesInstallManual is the S1 acceptance item made
// executable: on the manual's broken host, doctor's output must equal the
// INSTALL step-3 block byte for byte — the two sudo remediations included.
func TestDoctorMatchesInstallManual(t *testing.T) {
	report := Run(fakeProbes{}, nil)

	var buf bytes.Buffer
	report.Render(render.New(&buf, false, true))

	want := installBlock(t, "$ podaro doctor")
	if got := buf.String(); got != want {
		t.Fatalf("doctor output diverges from INSTALL §2 step 3\n--- want ---\n%s\n--- got ---\n%s", want, got)
	}
}

func TestDoctorJSONShape(t *testing.T) {
	report := Run(fakeProbes{}, nil)
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Checks []struct {
			ID          string `json:"id"`
			Status      string `json:"status"`
			Remediation string `json:"remediation"`
		} `json:"checks"`
		Summary struct {
			Fail     int `json:"fail"`
			NeedRoot int `json:"need_root"`
			Pending  int `json:"pending"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Checks) != 7 || decoded.Checks[0].ID != "podman" {
		t.Fatalf("checks wrong: %s", raw)
	}
	if decoded.Summary.Fail != 1 || decoded.Summary.NeedRoot != 1 || decoded.Summary.Pending != 1 {
		t.Fatalf("summary wrong: %s", raw)
	}
	if !strings.Contains(decoded.Checks[2].Remediation, "sudo loginctl enable-linger") {
		t.Fatalf("lingering remediation missing: %s", raw)
	}
}

// dnsRecorder overrides LookupHost to capture the probed hostname.
type dnsRecorder struct {
	fakeProbes
	queried string
}

func (d *dnsRecorder) LookupHost(host string) ([]string, error) {
	d.queried = host
	return []string{"203.0.113.10"}, nil
}

// The documented DNS setup creates only the wildcard record (Manual §5);
// wildcards do not cover the apex, so doctor must probe beneath it.
func TestDNSProbesWildcardCoveredName(t *testing.T) {
	rec := &dnsRecorder{}
	cfg := &config.Config{Domain: "lab.example.com", Gateway: config.Gateway{Port: 8443}}
	report := Run(rec, cfg)

	if want := WildcardProbe + ".lab.example.com"; rec.queried != want {
		t.Fatalf("probed %q, want %q", rec.queried, want)
	}
	dns := report.Checks[len(report.Checks)-1]
	if dns.ID != "dns" || dns.Status != Pass {
		t.Fatalf("dns check = %+v", dns)
	}
	if want := "*.lab.example.com → 203.0.113.10"; dns.Finding != want {
		t.Fatalf("finding = %q, want %q", dns.Finding, want)
	}
}

func TestVersionAtLeast(t *testing.T) {
	for _, tc := range []struct {
		have, want string
		ok         bool
	}{
		{"4.9.4", "4.4", true}, {"4.4", "4.4", true}, {"4.3.1", "4.4", false},
		{"5.0", "4.4", true}, {"3.9", "4.4", false},
	} {
		if got := versionAtLeast(tc.have, tc.want); got != tc.ok {
			t.Errorf("versionAtLeast(%q,%q) = %v, want %v", tc.have, tc.want, got, tc.ok)
		}
	}
}
