// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/legal"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/sysinfo"
)

var update = flag.Bool("update", false, "rewrite fragment goldens")

// Fixtures: the JSON twins, as the API would marshal them.
func fixtureInstances() []engine.InstanceView {
	created := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	rootless := true
	_ = rootless
	return []engine.InstanceView{
		{
			Name: "pii-lab", Template: "conformance-lab@1.0.0", Mode: "delivery", Created: created,
			Ladder:     engine.LadderView{Stage: "healthy", Condensed: "●●◐○○○○", Rank: 2, InProgress: true, Label: "initializing"},
			ConsoleURL: "https://pii-lab.lab.example.com:8443",
			Services: []engine.ServiceView{
				{Name: "alpha", Stage: "healthy", Word: "healthy", Context: "healthy in 38s", Took: "38s", Embed: "api-only"},
				{Name: "beta", Stage: "alive", Word: "initializing", Context: "typically 90s · elapsed 0:41", Embed: "iframe", URL: "https://beta-pii-lab.lab.example.com:8443"},
				{Name: "gamma", Stage: "", Word: "creating", Context: "waiting for the runtime", Embed: "iframe"},
			},
			Checkpoints: engine.Tally{Baseline: engine.Count{Passed: 0, Total: 8}, Objective: engine.ObjectiveCount{Passed: 0, Failed: 0, Total: 4}},
		},
		{
			Name: "my-lab", Template: "hello-nginx@0.1.0", Mode: "authoring", Created: created,
			Ladder:     engine.LadderView{Stage: "healthy", Condensed: "●●○○○○○", Rank: 2, Label: "failed"},
			ConsoleURL: "https://my-lab.lab.example.com:8443",
			Services:   []engine.ServiceView{{Name: "web", Stage: "healthy", Word: "failed", Context: "PDR-E204 pull failed", Error: "PDR-E204 pull failed", Embed: "iframe"}},
			Error:      &pdr.Error{Code: "PDR-E204", Message: "pull docker.io/library/nginx@sha256:552e failed", Cause: "registry unreachable", Next: "podaro doctor · then re-run to resume at this step"},
		},
	}
}

// fixtureLegal is GET /system/legal's value for a release build — with an
// operator's statement — or for an unreleased one, as internal/legal
// builds it; fixed here so the goldens do not move with VERSION.
func fixtureLegal(release bool) legal.Info {
	info := legal.Info{
		Product: "Podaro", Title: "Podaro Community", Version: "0.1.0",
		License: "AGPL-3.0-only", LicenseText: "LICENSE — the GNU Affero General Public License, version 3",
		Copyright: "Copyright © 2026 Jeremiah Ross, to the extent copyright subsists in first-party material and such copyright is owned by Jeremiah Ross. No copyright is claimed in AI-generated material that is not eligible for copyright protection under applicable law.",
		Licensing: "To the extent copyright subsists, copyrightable first-party material owned by Jeremiah Ross is licensed under AGPL-3.0-only.",
		Source: legal.Source{Build: "release", Tag: "v0.1.0", Repository: "https://git.example.com/podaro",
			URL:      "https://git.example.com/podaro/tree/v0.1.0",
			Offer:    "the source of Podaro v0.1.0 is at https://git.example.com/podaro/tree/v0.1.0 — the tag v0.1.0 of https://git.example.com/podaro",
			Operator: "https://git.example.com/fork/podaro"},
		Releases: legal.Releases{URL: "https://git.example.com/podaro/releases",
			Verify: "official releases are published at https://git.example.com/podaro/releases, each with a SHA256SUMS file beside its artifacts; a download is one of them only if its digest is listed there — sha256sum --ignore-missing -c SHA256SUMS"},
		Trademarks: "The Podaro name is covered separately by TRADEMARKS.md, a proposed policy: the licence grants no trademark rights beyond what applicable law permits, and LICENSE, the AGPL text, is unmodified.",
		ThirdParty: []legal.Component{
			{Name: "the Go standard library and runtime", License: "BSD-3-Clause", How: "compiled in, from the Go release that built the binary (a release's RELEASE-MANIFEST.json names it)"},
			{Name: "github.com/spf13/cobra", Version: "v1.10.2", License: "Apache-2.0", How: "compiled in"},
			{Name: "htmx.org (npm)", Version: "2.0.10", License: "0BSD", How: "embedded in the console bundle: htmx.min.js"},
		},
		Files: []string{"LICENSE", "LICENSES/Apache-2.0.txt", "NOTICE", "SOURCE", "SOURCE-AND-BUILD.md", "THIRD-PARTY-NOTICES.md", "TRADEMARKS.md"},
	}
	if !release {
		info.Version = "0.0.1-dev"
		info.Source = legal.Source{Build: "unreleased", Repository: "https://git.example.com/podaro",
			Offer: "an unreleased build (v0.0.1-dev): no release tag holds its exact source — obtain its source from whoever gave you this binary"}
	}
	return info
}

func TestFragmentGoldens(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	views := fixtureInstances()
	expires := time.Date(2026, 9, 3, 22, 0, 0, 0, time.UTC)
	rootless := true
	cases := []struct {
		name string
		data any
	}{
		{"instances", views},
		{"instances-empty", []engine.InstanceView{}},
		{"instance", views[0]},
		{"instance-failed", views[1]},
		{"system", sysinfo.Info{
			Engine: sysinfo.EngineInfo{Version: "0.1.0", APIVersion: "v1alpha1"}, Runtime: "podman",
			Host: sysinfo.HostInfo{PodmanVersion: "4.9.4", Rootless: &rootless, Domain: "lab.example.com", GatewayPort: 8443,
				Gateway:       sysinfo.Gateway{Listening: true, Address: ":8443", Domain: "lab.example.com", Certificate: "local-ca", Expires: "2027-09-03T10:00:00Z"},
				Observability: sysinfo.Posture{Logs: "off", Metrics: "off", Traces: "off"}},
		}},
		{"system-unconfigured", sysinfo.Info{Engine: sysinfo.EngineInfo{Version: "0.1.0", APIVersion: "v1alpha1"}, Runtime: "fake",
			Host: sysinfo.HostInfo{GatewayPort: 8443, Observability: sysinfo.Posture{Logs: "off", Metrics: "off", Traces: "off"}}}},
		{"session", auth.Whoami{Subject: "jross", Mechanism: "session", Scope: "admin", Expires: &expires, CSRF: "csrf-token"}},
		{"error", &pdr.Error{Code: "PDR-E301", Message: "username or password is wrong", Next: "check the credentials", Details: []pdr.Detail{{Code: "PDR-E101", Path: "lab.yaml:12", Hint: "missing image"}}}},
		{"login", LoginData{Username: "jross", Next: "https://pii-lab.lab.example.com:8443/", Error: &pdr.Error{Code: "PDR-E301", Message: "username or password is wrong"}}},
		{"login-empty", LoginData{}},
		{"legal", fixtureLegal(true)},
		{"legal-unreleased", fixtureLegal(false)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			frag := strings.SplitN(c.name, "-", 2)[0]
			got, err := r.Fragment(frag, c.data)
			if err != nil {
				t.Fatal(err)
			}
			check(t, filepath.Join("testdata", c.name+".html"), []byte(got))
		})
	}
	t.Run("page-home", func(t *testing.T) {
		body, _ := r.Fragment(FragmentInstances, views)
		var buf bytes.Buffer
		err := r.Page(&buf, ShellData{Version: "0.1.0", Assets: "0123456789ab", HomeURL: "https://lab.example.com:8443", Session: &SessionView{Subject: "jross", CSRF: "csrf-token"}, Poll: "/api/v1alpha1/instances", Body: body})
		if err != nil {
			t.Fatal(err)
		}
		check(t, filepath.Join("testdata", "page-home.html"), buf.Bytes())
	})
	t.Run("page-login", func(t *testing.T) {
		body, _ := r.Fragment(FragmentLogin, LoginData{})
		var buf bytes.Buffer
		if err := r.Page(&buf, ShellData{Title: "Sign in · Podaro", Version: "0.1.0", Assets: "0123456789ab", HomeURL: "https://lab.example.com:8443", Body: body}); err != nil {
			t.Fatal(err)
		}
		check(t, filepath.Join("testdata", "page-login.html"), buf.Bytes())
	})
	t.Run("page-legal", func(t *testing.T) {
		// The public page: no session, so no "signed in as" and no sign-out,
		// and the wordmark goes to this host's own root.
		body, _ := r.Fragment(FragmentLegal, fixtureLegal(true))
		var buf bytes.Buffer
		if err := r.Page(&buf, ShellData{Title: PageTitle("Licence and source"), Version: "0.1.0", Assets: "0123456789ab", Body: body}); err != nil {
			t.Fatal(err)
		}
		check(t, filepath.Join("testdata", "page-legal.html"), buf.Bytes())
	})
	t.Run("page-instance", func(t *testing.T) {
		body, _ := r.Fragment(FragmentInstance, views[0])
		var buf bytes.Buffer
		if err := r.Page(&buf, ShellData{Title: "pii-lab · Podaro", Version: "0.1.0", Assets: "0123456789ab", HomeURL: "https://lab.example.com:8443", Instance: &views[0], Session: &SessionView{Subject: "jross", CSRF: "csrf-token"}, Poll: "/api/v1alpha1/instances/pii-lab", Body: body}); err != nil {
			t.Fatal(err)
		}
		check(t, filepath.Join("testdata", "page-instance.html"), buf.Bytes())
	})
}

func check(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no golden %s (run: go test ./internal/console -update): %v", path, err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("fragment diverges from %s (review, then -update)\n--- want ---\n%s--- got ---\n%s", path, want, got)
	}
}

// The binding rule (ADR-0003): every fragment renders from the value its
// JSON twin marshals — the templates reference no field the JSON lacks.
// Enforced here by construction: the fixtures above are the API types.
// This test guards the shell against external references (UX §2 no. 9).
func TestShellMakesNoExternalRequests(t *testing.T) {
	r, _ := New()
	var buf bytes.Buffer
	body, _ := r.Fragment(FragmentLogin, LoginData{})
	_ = r.Page(&buf, ShellData{Version: "0.1.0", Assets: "0123456789ab", HomeURL: "https://lab.example.com:8443", Body: body})
	page := buf.String()
	for _, needle := range []string{"http://", "https://cdn", "googleapis", "unpkg", "jsdelivr", "//"} {
		for _, line := range strings.Split(page, "\n") {
			if strings.Contains(line, needle) && !strings.Contains(line, "https://lab.example.com:8443") {
				t.Errorf("shell references %q: %s", needle, line)
			}
		}
	}
	for _, want := range []string{`src="/assets/htmx.min.js`, `src="/assets/alpine-csp.min.js`, `href="/assets/console.css`, `"allowEval":false`} {
		if !strings.Contains(page, want) {
			t.Errorf("shell lacks %s", want)
		}
	}
}

// TestPageSuppliesTheAssetRevision: a page framed without an asset
// revision gets the embedded bundle's, on every asset URL — never an
// empty key, which a browser would cache for a day (the failed plain-form sign-in framed its own page and carried none).
func TestPageSuppliesTheAssetRevision(t *testing.T) {
	r := Must()
	var buf bytes.Buffer
	if err := r.Page(&buf, ShellData{Version: "0.1.0", HomeURL: "https://lab.example.com:8443", Body: "<p>x</p>"}); err != nil {
		t.Fatal(err)
	}
	page := buf.String()
	if strings.Contains(page, `?v=""`) || strings.Contains(page, `?v="`) {
		t.Fatalf("an asset URL has an empty cache key:\n%s", page)
	}
	want := `?v=` + podaro.ConsoleRevision() + `"`
	if n := strings.Count(page, want); n != 6 {
		t.Fatalf("%d asset URLs carry the bundle's revision %s, want 6:\n%s", n, podaro.ConsoleRevision(), page)
	}
}
