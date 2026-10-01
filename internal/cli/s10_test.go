// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/state"
	"github.com/jeremiahjrross/podaro/internal/system"
)

// Plan S10, the drift audit: three commands the acceptance docs promise
// and the binary did not have. Each of these tests fails on the code as
// S9 left it — with cobra's own "unknown command" or "unknown flag", or
// with the one-line empty state — which is the proof that the doc was
// describing something that did not exist.

// `podaro lab init --from <template> <dir>` is roadmap §9's MVP CLI row
// and User Manual §11's first authoring command. The scaffold has to
// validate: an authoring loop whose first step produces an invalid
// template is worse than no scaffolder.
func TestLabInitScaffoldsATemplateThatValidates(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	dir := filepath.Join(t.TempDir(), "my-lab")

	code, out, errOut := run(t, "lab", "init", "--from", "grafana-prometheus-intro", dir)
	if code != 0 {
		t.Fatalf("lab init exits %d, want 0: %q / %q", code, out, errOut)
	}
	for _, want := range []string{"scaffolded", "metadata.name", "my-lab", "podaro lab validate " + dir} {
		if !strings.Contains(out, want) {
			t.Errorf("the scaffold block does not carry %q:\n%s", want, out)
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(raw)
	if !strings.Contains(manifest, "name: my-lab") || strings.Contains(manifest, "name: grafana-prometheus-intro") {
		t.Errorf("metadata.name was not renamed after the directory:\n%s", manifest)
	}
	// The schema header line and the comments are the interface (UX §7);
	// a YAML round-trip would have eaten both.
	if !strings.HasPrefix(manifest, "# yaml-language-server: $schema=") {
		t.Errorf("the schema header line did not survive the rename:\n%s", manifest[:60])
	}
	if !strings.Contains(manifest, "SPDX-License-Identifier") {
		t.Error("the SPDX header did not survive the rename")
	}
	if _, err := os.Stat(filepath.Join(dir, "playbooks", "first-dashboard.yaml")); err != nil {
		t.Errorf("the playbook was not copied: %v", err)
	}
	// The whole point: the inner loop's next command is green.
	if code, out, errOut := run(t, "lab", "validate", dir); code != 0 || !strings.Contains(out, "valid") {
		t.Errorf("the scaffold does not validate: code=%d out=%q err=%q", code, out, errOut)
	}

	// The --json twin names what was written, from where.
	other := filepath.Join(t.TempDir(), "j-lab")
	code, out, _ = run(t, "--json", "lab", "init", "--from", "grafana-prometheus-intro", other)
	if code != 0 {
		t.Fatalf("--json lab init exits %d", code)
	}
	var body struct {
		Init struct {
			Path, Name, From, Source, Playbook string
			Files                              []string
		} `json:"init"`
	}
	if err := json.Unmarshal([]byte(out), &body); err != nil {
		t.Fatalf("--json is not JSON: %v (%q)", err, out)
	}
	if body.Init.Name != "j-lab" || body.Init.From != "grafana-prometheus-intro" || body.Init.Source != "binary" ||
		len(body.Init.Files) != 2 || body.Init.Playbook != "playbooks/first-dashboard.yaml" {
		t.Errorf("the json twin: %+v", body.Init)
	}
}

// An installed catalog entry wins over the copy in the binary — the
// operator's catalog is what `up` runs, so it is what a scaffold copies.
func TestLabInitPrefersTheInstalledCatalog(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	installed := filepath.Join(config.StateDir(), "catalog", "grafana-prometheus-intro")
	if err := os.MkdirAll(installed, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "# yaml-language-server: $schema=https://schemas.podaro.dev/lab/v1alpha1.json\n" +
		"apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata:\n  name: grafana-prometheus-intro\n  title: the operator's own copy\n"
	if err := os.WriteFile(filepath.Join(installed, "lab.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "mine")
	code, out, errOut := run(t, "--json", "lab", "init", "--from", "grafana-prometheus-intro", dir)
	if code != 0 {
		t.Fatalf("lab init exits %d: %q", code, errOut)
	}
	if !strings.Contains(out, `"source":"catalog"`) {
		t.Errorf("the installed catalog must be the source: %s", out)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "the operator's own copy") || !strings.Contains(string(raw), "name: mine") {
		t.Errorf("the installed copy was not the one scaffolded:\n%s", raw)
	}
	// The engine writes the current contract (the reconciliation plan's
	// D-R2): a catalog entry an earlier build installed at v1alpha1 is
	// scaffolded at v1alpha2, its schema header with it.
	if !strings.HasPrefix(string(raw), "# yaml-language-server: $schema=https://schemas.podaro.dev/lab/v1alpha2.json\napiVersion: lab.podaro.dev/v1alpha2\n") {
		t.Errorf("a v1alpha1 source must scaffold at v1alpha2:\n%s", raw)
	}
}

// Every refusal happens before the first file is written, and each names
// what to do instead (User Manual §14's anatomy).
func TestLabInitRefusesBeforeWritingAnything(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	// No --from: a precondition (exit 2), with the installed names.
	empty := filepath.Join(t.TempDir(), "no-from")
	code, _, errOut := run(t, "lab", "init", empty)
	if code != 2 || !strings.Contains(errOut, "PDR-E105") || !strings.Contains(errOut, "grafana-prometheus-intro") {
		t.Errorf("missing --from: code=%d err=%q", code, errOut)
	}
	if _, err := os.Stat(empty); !os.IsNotExist(err) {
		t.Error("a refusal created the target directory")
	}

	// A directory name that cannot be a template name (spec 0003 §2).
	code, _, errOut = run(t, "lab", "init", "--from", "grafana-prometheus-intro", filepath.Join(t.TempDir(), "My_Lab"))
	if code != 2 || !strings.Contains(errOut, "PDR-E105") || !strings.Contains(errOut, "DNS label") {
		t.Errorf("a name that is not a DNS label: code=%d err=%q", code, errOut)
	}

	// A target that already holds files is never merged into.
	occupied := filepath.Join(t.TempDir(), "taken")
	if err := os.MkdirAll(occupied, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(occupied, "lab.yaml"), []byte("mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = run(t, "lab", "init", "--from", "grafana-prometheus-intro", occupied)
	if code != 2 || !strings.Contains(errOut, "PDR-E105") {
		t.Errorf("an occupied target: code=%d err=%q", code, errOut)
	}
	if raw, _ := os.ReadFile(filepath.Join(occupied, "lab.yaml")); string(raw) != "mine\n" {
		t.Errorf("the refusal overwrote a file: %q", raw)
	}

	// A template nobody installed is the engine's own refusal shape.
	code, _, errOut = run(t, "lab", "init", "--from", "nope", filepath.Join(t.TempDir(), "x"))
	if code != 1 || !strings.Contains(errOut, "PDR-E207") || !strings.Contains(errOut, "grafana-prometheus-intro") {
		t.Errorf("an uninstalled template: code=%d err=%q", code, errOut)
	}
	// --from takes a name, never a path: a path would read a directory
	// the operator did not install.
	code, _, errOut = run(t, "lab", "init", "--from", "../scenarios/grafana-prometheus-intro", filepath.Join(t.TempDir(), "y"))
	if code != 1 || !strings.Contains(errOut, "PDR-E207") {
		t.Errorf("--from with a path: code=%d err=%q", code, errOut)
	}
}

// `podaro status [X] --watch` is User Manual §8's "the ladder, live". It
// ends on Ctrl-C — or when the lab is gone, which is the one end that is
// not the operator's own.
func TestStatusWatchRendersEachChangeAndEndsWhenTheLabIsGone(t *testing.T) {
	store := serveLab(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.PutInstance(state.Instance{Name: "demo", Template: "t", Mode: "delivery",
		Source: "/s", Created: now, Updated: now, Stage: state.StageAlive}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutService(state.Service{Instance: "demo", Name: "grafana", Module: "grafana",
		Image: "docker.io/library/grafana", Container: "pdr-demo-grafana", Stage: state.StageAlive}); err != nil {
		t.Fatal(err)
	}
	restore := watchInterval
	watchInterval = 10 * time.Millisecond
	t.Cleanup(func() { watchInterval = restore })

	go func() {
		time.Sleep(150 * time.Millisecond)
		inst, err := store.GetInstance("demo")
		if err != nil || inst == nil {
			return
		}
		inst.Stage = state.StageReady
		_ = store.PutInstance(*inst)
		time.Sleep(150 * time.Millisecond)
		_ = store.DeleteInstance("demo")
	}()

	code, out, errOut := run(t, "status", "demo", "--watch")
	// Piped, a watch prints only what changed — two stages over some
	// thirty polls. A third frame is possible and not a failure: the
	// engine composes a view from several reads, so a destroy landing
	// between them shows the instance with its services already gone.
	if n := strings.Count(out, "demo · t ·"); n < 2 || n > 3 {
		t.Errorf("a piped watch prints one frame per change, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "alive") || !strings.Contains(out, "ready") {
		t.Errorf("both stages must be rendered:\n%s", out)
	}
	// The lab is gone: the watch ends with the engine's own refusal
	// rather than looping on a lab that no longer exists.
	if code != 1 || !strings.Contains(errOut, "PDR-E202") {
		t.Errorf("a destroyed lab ends the watch: code=%d err=%q", code, errOut)
	}
}

// Under --json a watch is one object per change, newline-delimited — the
// same shape the one-shot read returns (UX §7: --json on every read).
func TestStatusWatchJSONIsOneObjectPerChange(t *testing.T) {
	store := serveLab(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.PutInstance(state.Instance{Name: "demo", Template: "t", Mode: "delivery",
		Source: "/s", Created: now, Updated: now, Stage: state.StageAlive}); err != nil {
		t.Fatal(err)
	}
	restore := watchInterval
	watchInterval = 10 * time.Millisecond
	t.Cleanup(func() { watchInterval = restore })

	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = store.DeleteInstance("demo")
	}()
	code, out, _ := run(t, "--json", "status", "demo", "--watch")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	// An unchanged instance is one object however many times it is read,
	// and the last line is the refusal that ended the watch — the API §3
	// envelope on stdout, as every --json read reports an error.
	var instances, envelopes int
	for _, line := range lines {
		var body struct {
			Instance *struct{ Name string } `json:"instance"`
			Error    *struct{ Code string } `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &body); err != nil {
			t.Fatalf("every line is one JSON object: %v (%q)", err, line)
		}
		switch {
		case body.Instance != nil:
			instances++
			if body.Instance.Name != "demo" {
				t.Errorf("each object is the one-shot shape: %q", line)
			}
		case body.Error != nil:
			envelopes++
			if body.Error.Code != "PDR-E202" {
				t.Errorf("the closing envelope names the refusal: %q", line)
			}
		}
	}
	if instances < 1 || instances > 2 || envelopes != 1 {
		t.Errorf("%d instance objects and %d envelopes:\n%s", instances, envelopes, out)
	}
	if code != 1 {
		t.Errorf("the watch ends on the destroyed lab: code=%d", code)
	}
}

// INSTALL §2 step 6's empty state is the dual on-ramp (Journey §2 stage
// 0): every installed template, the open-source lab first, each with the
// description its own standard profile declares.
func TestStatusEmptyStateOffersEveryInstalledTemplate(t *testing.T) {
	serveLab(t)
	catalog := filepath.Join(config.StateDir(), "catalog")
	for _, tc := range []struct{ name, description string }{
		{"grafana-prometheus-intro", "4 GB host · all open source"},
		{"middle-lab", "8 GB host · one open-source product"},
		{"zz-other", ""},
	} {
		if err := os.MkdirAll(filepath.Join(catalog, tc.name), 0o755); err != nil {
			t.Fatal(err)
		}
		manifest := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata:\n  name: " + tc.name + "\n"
		if tc.description != "" {
			manifest += "profiles:\n  standard:\n    description: " + tc.description + "\n"
		}
		if err := os.WriteFile(filepath.Join(catalog, tc.name, "lab.yaml"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	code, out, errOut := run(t, "status")
	if code != 0 {
		t.Fatalf("status exits %d: %q", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 || lines[0] != "no instances yet" {
		t.Fatalf("the empty state is its headline and one line per template:\n%s", out)
	}
	// The open-source lab first, then anything else alphabetically — the
	// order `system install` extracts them in.
	for i, want := range []string{"grafana-prometheus-intro", "middle-lab", "zz-other"} {
		if !strings.Contains(lines[i+1], "podaro up "+want) {
			t.Errorf("line %d is %q, want the offer for %s", i+1, lines[i+1], want)
		}
	}
	if !strings.Contains(lines[1], "4 GB host · all open source") || !strings.Contains(lines[2], "8 GB host · one open-source product") {
		t.Errorf("each offer carries its own profile's description:\n%s", out)
	}
	// A template with no description is still offered — the name is the
	// action (UX §6).
	if strings.TrimRight(lines[3], " ") != lines[3] {
		t.Errorf("a missing clause must not leave a padded line: %q", lines[3])
	}
	// The engine was asked for the instances; nothing about the catalog
	// reached it (GET /catalog/templates is not routed, API §6).
	if strings.Contains(out, "No instances yet →") {
		t.Error("the one-line empty state is the console's, not the CLI's")
	}
}

// The in-place redraw both `up` and `status --watch` use erases what the
// previous frame wrote below the new one. A create's frames only grow, so
// this never showed there; a destroy's shrink as services go, and a watch
// outliving its lab shrinks to nothing — and clearing line by line left
// the tail of the taller frame on screen, reading as a ladder that still
// holds services the instance does not.
func TestRedrawFrameErasesWhatTheLastFrameLeft(t *testing.T) {
	var buf strings.Builder
	tall := []string{"pii-lab · t · ●●●●◐○○ verifying", "  grafana  ● ready", "  checkpoints  baseline 8/8"}
	if n := redrawFrame(&buf, 0, tall); n != 3 {
		t.Fatalf("the first frame is three lines, got %d", n)
	}
	buf.Reset()
	short := []string{"pii-lab · t · ●○○○○○○ alive"}
	if n := redrawFrame(&buf, 3, short); n != 1 {
		t.Fatalf("the second frame is one line, got %d", n)
	}
	out := buf.String()
	if strings.Count(out, "\x1b[F") != 3 {
		t.Errorf("the redraw moves up over every line of the last frame: %q", out)
	}
	if !strings.Contains(out, "\x1b[J") {
		t.Errorf("a shrinking frame must erase to the end of the screen, or the old tail stays: %q", out)
	}
	// The escape that erases only the current line cannot do it: it leaves
	// lines four and five of a five-line frame exactly where they were.
	if strings.Contains(out, "\x1b[K") {
		t.Errorf("line-by-line clearing is what left the stale tail: %q", out)
	}
	if !strings.HasSuffix(out, short[0]+"\n") {
		t.Errorf("the new frame is printed last: %q", out)
	}
}

// The scaffold is written into a staging directory and renamed into place,
// so a write that fails halfway leaves nothing behind. Before that it was
// written file by file into the author's own directory: a full filesystem
// after `lab.yaml` and before the playbook left a partial template, and
// the re-run the refusal suggested then refused *that* — "already holds 2
// entries" — about a directory this command had made itself.
func TestLabInitLeavesNothingWhenAWriteFails(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	dir := filepath.Join(t.TempDir(), "my-lab")

	// The second file of the scaffold refuses; the first has already
	// landed, which is exactly the half-written case.
	restore := writeScaffoldFile
	var written int
	writeScaffoldFile = func(name string, data []byte, perm os.FileMode) error {
		written++
		if written == 2 {
			return errors.New("no space left on device")
		}
		return restore(name, data, perm)
	}
	t.Cleanup(func() { writeScaffoldFile = restore })

	code, _, errOut := run(t, "lab", "init", "--from", "grafana-prometheus-intro", dir)
	if code != 2 || !strings.Contains(errOut, "PDR-E105") || !strings.Contains(errOut, "no space left on device") {
		t.Fatalf("a failed write is a refusal naming its cause: code=%d err=%q", code, errOut)
	}
	if written < 2 {
		t.Fatalf("the test did not reach the second write (%d)", written)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		entries, _ := os.ReadDir(dir)
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("a failed scaffold left %s behind: %v", dir, names)
	}
	// And no staging directory outlives the failure.
	siblings, err := os.ReadDir(filepath.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range siblings {
		if strings.Contains(e.Name(), "podaro-init-") {
			t.Errorf("the staging directory was left behind: %s", e.Name())
		}
	}
}

// A quoted `metadata.name` is as valid as a plain one, and the rename used
// to refuse every scalar that was not plain — so an operator's own catalog
// entry written `name: "vendor-lab"` could not be scaffolded from at all.
// The quoting survives the rename, because it is the author's.
func TestLabInitRenamesAQuotedName(t *testing.T) {
	for _, tc := range []struct{ style, declared, want string }{
		{"double-quoted", `  name: "vendor-lab"`, `  name: "mine"`},
		{"single-quoted", `  name: 'vendor-lab'`, `  name: 'mine'`},
		{"plain", `  name: vendor-lab`, `  name: mine`},
	} {
		t.Run(tc.style, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			installed := filepath.Join(config.StateDir(), "catalog", "vendor-lab")
			if err := os.MkdirAll(installed, 0o755); err != nil {
				t.Fatal(err)
			}
			manifest := "# yaml-language-server: $schema=https://schemas.podaro.dev/lab/v1alpha1.json\n" +
				"apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata:\n" + tc.declared + "\n  title: a vendor's own lab\n"
			if err := os.WriteFile(filepath.Join(installed, "lab.yaml"), []byte(manifest), 0o644); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(t.TempDir(), "mine")
			code, out, errOut := run(t, "lab", "init", "--from", "vendor-lab", dir)
			if code != 0 {
				t.Fatalf("a %s name must scaffold: code=%d out=%q err=%q", tc.style, code, out, errOut)
			}
			raw, err := os.ReadFile(filepath.Join(dir, "lab.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), tc.want+"\n") {
				t.Errorf("the %s name was not rewritten in its own style (want %q):\n%s", tc.style, tc.want, raw)
			}
			if strings.Contains(string(raw), "vendor-lab") {
				t.Errorf("the old name survived:\n%s", raw)
			}
			// The comment and the header are still the author's.
			if !strings.HasPrefix(string(raw), "# yaml-language-server:") || !strings.Contains(string(raw), "a vendor's own lab") {
				t.Errorf("the rename disturbed the rest of the document:\n%s", raw)
			}
		})
	}
}

// A column is not an offset: the parser counts characters, a Go string is
// indexed in bytes, and a title or description may hold anything. Measured
// with go1.24.7 and yaml.v3, `metadata: {description: café, name: *label}`
// reports the alias at column 62 where the token begins at byte 62 — so
// treating the column as an index landed a byte early, the token did not
// match, and `lab init` refused a valid template.
// Flow style is what makes it reachable: in block style the name is alone
// on its line behind an ASCII key.
func TestLabInitRenamesANameBehindNonASCIIOnItsLine(t *testing.T) {
	for _, tc := range []struct{ name, metadata, want string }{
		{
			"aliased name after a non-ASCII description",
			"metadata: {title: &label vendor-lab, description: café, name: *label}",
			"metadata: {title: &label vendor-lab, description: café, name: mine}",
		},
		{
			"plain name after a non-ASCII description",
			"metadata: {description: café, name: vendor-lab}",
			"metadata: {description: café, name: mine}",
		},
		{
			"quoted name after several multi-byte runes",
			`metadata: {description: naïve café ☕, name: "vendor-lab"}`,
			`metadata: {description: naïve café ☕, name: "mine"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			installed := filepath.Join(config.StateDir(), "catalog", "vendor-lab")
			if err := os.MkdirAll(installed, 0o755); err != nil {
				t.Fatal(err)
			}
			manifest := "# yaml-language-server: $schema=https://schemas.podaro.dev/lab/v1alpha1.json\n" +
				"apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\n" + tc.metadata + "\n"
			if err := os.WriteFile(filepath.Join(installed, "lab.yaml"), []byte(manifest), 0o644); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(t.TempDir(), "mine")
			code, out, errOut := run(t, "lab", "init", "--from", "vendor-lab", dir)
			if code != 0 {
				t.Fatalf("a name behind non-ASCII text must still scaffold: code=%d out=%q err=%q", code, out, errOut)
			}
			raw, err := os.ReadFile(filepath.Join(dir, "lab.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), tc.want+"\n") {
				t.Errorf("the name was not rewritten where the parser put it (want %q):\n%s", tc.want, raw)
			}
			// The non-ASCII text is the author's and is untouched, byte for
			// byte — a mis-sliced edit would have eaten into it.
			for _, keep := range []string{"café", "naïve", "☕"} {
				if strings.Contains(tc.metadata, keep) && !strings.Contains(string(raw), keep) {
					t.Errorf("the rename damaged %q:\n%s", keep, raw)
				}
			}
		})
	}
}

// A block scalar spans lines, so its end is not on the name's own line: it
// is refused rather than guessed at, and the refusal says what to do.
func TestLabInitRefusesABlockScalarName(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	installed := filepath.Join(config.StateDir(), "catalog", "folded")
	if err := os.MkdirAll(installed, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata:\n  name: >-\n    folded\n"
	if err := os.WriteFile(filepath.Join(installed, "lab.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "mine")
	code, _, errOut := run(t, "lab", "init", "--from", "folded", dir)
	if code != 2 || !strings.Contains(errOut, "PDR-E100") || !strings.Contains(errOut, "metadata.name to mine") {
		t.Errorf("a folded name is refused with what to do instead: code=%d err=%q", code, errOut)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("the refusal left a directory behind")
	}
}

// A target may be written with a trailing separator, and it names the same
// directory. Deriving the staging parent from the uncleaned form made
// filepath.Dir(dir) the target itself, so the staging directory landed
// inside the scaffold, os.Remove(dir) then failed, and the empty target
// left behind made every re-run fail the same way.
func TestLabInitAcceptsATrailingSeparator(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	base := t.TempDir()
	dir := filepath.Join(base, "my-lab")

	code, out, errOut := run(t, "lab", "init", "--from", "grafana-prometheus-intro", dir+string(filepath.Separator))
	if code != 0 {
		t.Fatalf("a target with a trailing separator exits %d, want 0: %q / %q", code, out, errOut)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "lab.yaml"))
	if err != nil {
		t.Fatalf("the scaffold is not at the target: %v", err)
	}
	if !strings.Contains(string(raw), "name: my-lab") {
		t.Errorf("metadata.name was not renamed after the directory:\n%s", raw)
	}
	// Nothing beside the scaffold, and nothing hidden inside it: a staging
	// directory anywhere is the failure this test is about.
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "my-lab" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the parent holds %v, want my-lab alone", names)
	}
	inside, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range inside {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("a staging directory is inside the scaffold: %s", e.Name())
		}
	}
	// And the re-run an author would reach for refuses for the right
	// reason — the scaffold is there — rather than failing the same way.
	code, _, errOut = run(t, "lab", "init", "--from", "grafana-prometheus-intro", dir+string(filepath.Separator))
	if code != 2 || !strings.Contains(errOut, "already holds") {
		t.Errorf("the re-run must refuse an occupied target: code=%d err=%q", code, errOut)
	}
}

// A manifest may inherit metadata.name through a YAML merge key: the
// loader expands `<<` (internal/lab/document.go), so such a template
// validates, and a direct scan of the mapping's own pairs would refuse a
// scaffold of a template the engine accepts.
// The rename edits the scalar where the value actually lives — inside the
// anchor — and the re-read confirms the document now declares the new name.
func TestLabInitRenamesANameBehindAMergeKey(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	installed := filepath.Join(config.StateDir(), "catalog", "vendor-lab")
	if err := os.MkdirAll(installed, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "# yaml-language-server: $schema=https://schemas.podaro.dev/lab/v1alpha1.json\n" +
		"apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\n" +
		"x-base: &base\n  name: vendor-lab\n  title: inherited through a merge key\n" +
		"metadata:\n  <<: *base\n"
	if err := os.WriteFile(filepath.Join(installed, "lab.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "merged")
	code, out, errOut := run(t, "lab", "init", "--from", "vendor-lab", dir)
	if code != 0 {
		t.Fatalf("a merged name must scaffold, exits %d: %q / %q", code, out, errOut)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "name: merged") || strings.Contains(string(raw), "name: vendor-lab") {
		t.Errorf("the inherited name was not rewritten:\n%s", raw)
	}
	// The merge key, the anchor and the schema header all survive: the edit
	// is textual, and the document still means what its author wrote.
	for _, want := range []string{"<<: *base", "x-base: &base", "# yaml-language-server:", "inherited through a merge key"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the scaffold lost %q:\n%s", want, raw)
		}
	}
	// An alias at the name site is replaced where it stands, and the
	// anchor it pointed at is left alone — the value belongs to whichever
	// key declared it, and renaming that key is not what init was asked to
	// do. This assertion is the reverse of
	// the one round 4 shipped, which rewrote the anchor and so renamed the
	// title along with the template.
	installed2 := filepath.Join(config.StateDir(), "catalog", "alias-lab")
	if err := os.MkdirAll(installed2, 0o755); err != nil {
		t.Fatal(err)
	}
	aliased := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata:\n" +
		"  title: &label alias-lab\n  name: *label\n"
	if err := os.WriteFile(filepath.Join(installed2, "lab.yaml"), []byte(aliased), 0o644); err != nil {
		t.Fatal(err)
	}
	dir2 := filepath.Join(t.TempDir(), "aliased")
	if code, out, errOut := run(t, "lab", "init", "--from", "alias-lab", dir2); code != 0 {
		t.Fatalf("an aliased name must scaffold, exits %d: %q / %q", code, out, errOut)
	}
	raw2, err := os.ReadFile(filepath.Join(dir2, "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw2), "name: aliased") {
		t.Errorf("the alias at the name site was not replaced:\n%s", raw2)
	}
	if !strings.Contains(string(raw2), "title: &label alias-lab") {
		t.Errorf("the anchor the alias pointed at must survive, title and all:\n%s", raw2)
	}

	// The mirror image: the name carries the anchor and another key aliases
	// it. The value is the name's own, but it is shared, so this refuses
	// rather than renaming a key nobody asked about.
	installed3 := filepath.Join(config.StateDir(), "catalog", "shared-lab")
	if err := os.MkdirAll(installed3, 0o755); err != nil {
		t.Fatal(err)
	}
	shared := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata:\n" +
		"  name: &label shared-lab\n  title: *label\n"
	if err := os.WriteFile(filepath.Join(installed3, "lab.yaml"), []byte(shared), 0o644); err != nil {
		t.Fatal(err)
	}
	dir3 := filepath.Join(t.TempDir(), "shared")
	code, _, errOut = run(t, "lab", "init", "--from", "shared-lab", dir3)
	if code != 2 || !strings.Contains(errOut, "&label") || !strings.Contains(errOut, "other keys alias") {
		t.Errorf("a shared anchor at the name site must be refused, and say why: code=%d err=%q", code, errOut)
	}
	if _, err := os.Stat(dir3); !os.IsNotExist(err) {
		t.Errorf("the refusal must happen before anything is written: %v", err)
	}
}

// The printed next actions are commands to copy (UX §6), so a path with a
// space in it has to survive the copy — and a path that starts with a dash
// must not read as a flag.
func TestLabInitQuotesThePathInItsNextActions(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	base := filepath.Join(t.TempDir(), "My Labs")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "my-lab")
	code, out, errOut := run(t, "lab", "init", "--from", "grafana-prometheus-intro", dir)
	if code != 0 {
		t.Fatalf("lab init exits %d: %q / %q", code, out, errOut)
	}
	for _, want := range []string{
		"podaro lab validate '" + dir + "'",
		"podaro up '" + dir + "' --name dev",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("a next action must be copyable as it stands, want %q:\n%s", want, out)
		}
	}
	// The refusal that names the target quotes it too.
	if _, _, errOut = run(t, "lab", "init", dir); !strings.Contains(errOut, "--from <template> '"+dir+"'") {
		t.Errorf("the refusal's next action must quote the path too: %q", errOut)
	}
	// The scaffold's own directory name has to be a DNS label, so it can
	// never start with a dash — but a relative path *through* one can, and
	// cleaning `./-weird/my-lab` drops the `./`. The printed command has to
	// put it back, or the action it advertises is parsed as a flag.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)
	if err := os.Mkdir("-weird", 0o755); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut = run(t, "lab", "init", "--from", "grafana-prometheus-intro", "./-weird/my-lab"); code != 0 {
		t.Fatalf("a dash-leading parent exits %d: %q / %q", code, out, errOut)
	}
	if !strings.Contains(out, "podaro lab validate ./-weird/my-lab") {
		t.Errorf("a leading dash must be rendered as a path:\n%s", out)
	}
}

// The release has to carry every architecture the code can ask for:
// internal/system.AssetName resolves the asset from the *operator's*
// runtime architecture, so an architecture the packaging script does not
// build is a 404 for everyone on it. This
// keeps the script's list, the sentence INSTALL §2 step 1 prints, and the
// architecture this test runs on in lockstep.
func TestTheReleaseBuildsEveryArchitectureTheAssetNameCanAsk(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "hack", "release_package.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`arches="\$\{PODARO_RELEASE_ARCHES:-([^}]*)\}"`).FindSubmatch(script)
	if m == nil {
		t.Fatal("hack/release_package.sh declares no default architecture list")
	}
	built := map[string]bool{}
	for _, a := range strings.Fields(string(m[1])) {
		built[a] = true
	}

	install, err := os.ReadFile(filepath.Join("..", "..", "public-docs", "INSTALL.md"))
	if err != nil {
		t.Fatal(err)
	}
	sentence := regexp.MustCompile(`The architectures are ([^.]*?), because`).FindSubmatch(install)
	if sentence == nil {
		t.Fatal("INSTALL §2 step 1 no longer names the release's architectures")
	}
	named := map[string]bool{}
	for _, q := range regexp.MustCompile("`([a-z0-9]+)`").FindAllSubmatch(sentence[1], -1) {
		named[string(q[1])] = true
	}
	if len(named) != len(built) {
		t.Errorf("INSTALL names %v, the script builds %v", keysOf(named), keysOf(built))
	}
	for a := range named {
		if !built[a] {
			t.Errorf("INSTALL promises linux/%s and the script does not build it", a)
		}
	}
	// And the one that can be checked from here rather than read: a host
	// of this architecture must find its own asset in a release.
	if !built[runtime.GOARCH] {
		t.Errorf("AssetName asks for %q on this host (%s), which the release does not build",
			system.AssetName("0.1.0"), runtime.GOARCH)
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The release build pins the target feature levels, because a builder who
// has persisted `go env -w GOAMD64=v3` would otherwise produce a different
// binary from the same commit — which is what the reproducible-build
// instruction in INSTALL §2 step 1 rests on — and a v3 binary will not
// start on an amd64 host without AVX2.
// The host guard reads GOHOSTARCH, since GOARCH is the target and a
// cross-configured builder would otherwise try to run a foreign binary.
func TestTheReleaseBuildPinsWhatTheBuilderCouldChange(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "hack", "release_package.sh"))
	if err != nil {
		t.Fatal(err)
	}
	build := regexp.MustCompile(`(?s)build\(\) \{.*?\n\}`).FindString(string(script))
	if build == "" {
		t.Fatal("hack/release_package.sh declares no build() function")
	}
	for _, want := range []string{"GOAMD64=v1", "GOARM64=v8.0", "CGO_ENABLED=0", "-trimpath", "-buildvcs=false"} {
		if !strings.Contains(build, want) {
			t.Errorf("the release build does not pin %s:\n%s", want, build)
		}
	}
	if strings.Contains(string(script), `native="$(go env GOARCH)"`) {
		t.Error(`the host guard reads GOARCH, which is the target: a builder with GOARCH set would run a foreign binary`)
	}
	if !strings.Contains(string(script), `native="$(go env GOHOSTARCH)"`) {
		t.Error("the host guard must read GOHOSTARCH")
	}
	// The same mistake one variable over: `go env GOOS` is the target too,
	// so a macOS builder with GOOS=linux configured passed the OS gate and
	// then tried to execute a Linux binary.
	if strings.Contains(string(script), `goos="$(go env GOOS)"`) {
		t.Error(`the OS gate reads GOOS, which is the target: a macOS builder with GOOS=linux would pass it`)
	}
	if !strings.Contains(string(script), `hostos="$(go env GOHOSTOS)"`) {
		t.Error("the OS gate must read GOHOSTOS")
	}
	// And the toolchain settings the build cannot pin are compared against
	// what this toolchain says its defaults are, not against defaults
	// written down here: `go env` prints an empty value with status 0 for a
	// name it does not know, so a literal `GOFIPS140=off` comparison refused
	// every release on a Go that has no GOFIPS140 — measured on a stub
	// toolchain, exit 2 and "configured: GOFIPS140=" on a stock builder.
	// Read the code, not the prose: the comment above the gate cites the
	// measured digests, GOFIPS140=v1.0.0 among them.
	code := regexp.MustCompile(`(?m)^[\t ]*#.*$`).ReplaceAllString(string(script), "")
	if !strings.Contains(code, "GOENV=off GOOS=linux") ||
		!strings.Contains(code, "env -u GOEXPERIMENT -u GOFLAGS -u GOFIPS140 go env") {
		t.Error("the toolchain gate must ask for each default with the go env file off and the settings unset")
	}
	if regexp.MustCompile(`GOFIPS140=(off|v)`).MatchString(code) {
		t.Error("the toolchain gate writes a default down: a Go without GOFIPS140 would then be refused")
	}
}

// A release has to be what a *stock* toolchain produces, because INSTALL §2
// step 1 offers rebuild-and-compare in place of signing and the reader who
// takes that offer has a stock one. GOEXPERIMENT, GOFLAGS and GOFIPS140
// survive everything build() pins and change what the compiler puts in the
// binary anyway — and they do it invisibly: both builds of a pair inherit
// the same setting, so the script's own comparison agrees with itself, and
// the toolchain line it prints cannot explain the difference.
// Measured with go1.24.7, same commit and flags: the stock amd64
// binary is 0fb8cf1d…, a persisted GOEXPERIMENT=newinliner gives
// a6403422…, and GOFIPS140=v1.0.0 gives 06e0527d…. Clearing them is not an
// option either: GOEXPERIMENT= does not clear it, because an empty
// environment variable does not override the go env file, and
// GOEXPERIMENT=none is a third binary again, since it zeroes the
// toolchain's own baseline. No value means "the default", which is why the
// script refuses a configured toolchain instead of clearing one.
func TestTheReleaseRefusesAConfiguredToolchain(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("a non-Linux host is refused before any toolchain setting is read")
	}
	version, err := os.ReadFile(filepath.Join("..", "..", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "hack", "release_package.sh"))
	if err != nil {
		t.Fatal(err)
	}
	gated := []string{"GOEXPERIMENT", "GOFLAGS", "GOFIPS140"}

	// Whatever this shell carries for the three, the child gets none of it.
	// The gate names the first setting it finds, so a contributor who runs
	// the suite with their own GOFLAGS set would otherwise read the wrong
	// refusal — measured, before this filter: the GOFIPS140 case failed
	// with "the refusal never says go env -u GOFIPS140" and a refusal that
	// named GOFLAGS.
	bare := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if name, _, ok := strings.Cut(kv, "="); ok && slices.Contains(gated, name) {
			continue
		}
		bare = append(bare, kv)
	}

	// `go env -u` deletes what `go env -w` persisted and nothing else, so the
	// command the refusal prints has to match where the value came from:
	// advising it for an exported variable would delete an unrelated
	// preference from the file and the next run would refuse all the same.
	// Measured: with `-mod=mod` in the file and
	// `-tags=x` in the environment, `go env` reports `-tags=x`.
	for _, configured := range []struct{ setting, value, from, remedy string }{
		{"GOEXPERIMENT", "newinliner", "environment", "unset GOEXPERIMENT"},
		{"GOFLAGS", "-mod=mod", "environment", "unset GOFLAGS"},
		{"GOFIPS140", "v1.0.0", "environment", "unset GOFIPS140"},
		{"GOFLAGS", "-mod=mod", "go env file", "go env -u GOFLAGS"},
		{"GOFLAGS", "-mod=mod", "both", "unset GOFLAGS; go env -u GOFLAGS"},
	} {
		t.Run(configured.setting+"/from-"+strings.ReplaceAll(configured.from, " ", "-"), func(t *testing.T) {
			// A go env file of this test's own, so the case is exactly the
			// source it names and not whatever this builder has persisted.
			goenv := filepath.Join(t.TempDir(), "env")
			persisted := ""
			if configured.from != "environment" {
				persisted = configured.setting + "=" + configured.value + "\n"
			}
			if err := os.WriteFile(goenv, []byte(persisted), 0o600); err != nil {
				t.Fatal(err)
			}
			child := append(slices.Clone(bare), "GOENV="+goenv)
			if configured.from != "go env file" {
				child = append(child, configured.setting+"="+configured.value)
			}
			// The same baseline the script asks for: no go env file, none of
			// the three in the environment.
			pristine := append(slices.Clone(bare), "GOENV=off")

			// This subtest can only speak when the toolchain agrees — the
			// setting under test has to differ from this toolchain's own
			// default, and the other two have to match theirs. Experiment
			// names come and go between Go releases, GOFIPS140 arrived in
			// go1.24, and a `go env -w` file that no environment variable
			// can override would make the script refuse something else. Skip
			// in those cases rather than fail: none of them is this test's
			// claim.
			for _, name := range gated {
				stock, here := goEnvValue(t, pristine, name), goEnvValue(t, child, name)
				if name == configured.setting {
					if here != configured.value || here == stock {
						t.Skipf("this toolchain reports %s=%q where the test asked for %q and its own default is %q",
							name, here, configured.value, stock)
					}
					continue
				}
				if here != stock {
					t.Skipf("this builder already carries %s=%q (default %q), so the refusal would name that one",
						name, here, stock)
				}
			}

			out := t.TempDir()
			release := exec.Command(script, strings.TrimSpace(string(version)), out)
			release.Env = child
			said, err := release.CombinedOutput()

			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 2 {
				t.Fatalf("the release did not refuse a toolchain with %s=%s configured (err %v):\n%s",
					configured.setting, configured.value, err, said)
			}
			for _, want := range []string{
				configured.setting + "=" + configured.value,
				"next      " + configured.remedy,
			} {
				if !strings.Contains(string(said), want) {
					t.Errorf("the refusal never says %q:\n%s", want, said)
				}
			}
			// And it does not print a command that would not remove this
			// value: `go env -u` for something the environment carries
			// deletes an unrelated persisted preference and refuses again.
			if configured.from == "environment" && strings.Contains(string(said), "go env -u") {
				t.Errorf("the refusal offers `go env -u` for a value the environment carries:\n%s", said)
			}
			// And it refused before building anything: UX §7 reserves 2 for
			// "refused, nothing done", and the output directory proves it.
			if entries, err := os.ReadDir(out); err != nil || len(entries) != 0 {
				t.Errorf("the refused run left %d entries under the output directory (err %v)",
					len(entries), err)
			}
		})
	}
}

// goEnvValue asks the toolchain what one setting is under a given
// environment. A toolchain that refuses the value — an experiment it has
// never heard of — fails `go env` itself, which is a skip and not a
// verdict on the script.
func goEnvValue(t *testing.T, env []string, name string) string {
	t.Helper()
	probe := exec.Command("go", "env", name)
	probe.Env = env
	said, err := probe.Output()
	if err != nil {
		t.Skipf("this toolchain will not answer `go env %s` here: %v", name, err)
	}
	return strings.TrimSpace(string(said))
}
