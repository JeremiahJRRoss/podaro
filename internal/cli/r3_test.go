// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// The reconciliation plan's R3: a template the owner retired may still
// sit in <state>/catalog/, where an earlier build extracted it. It stays
// there — nothing deletes it — and no surface that offers templates
// offers it. The name comes from the embedded manifest; nothing here
// spells it.

// retiredCatalogEntry puts the retired template into the installed
// catalog as an earlier build would have left it, beside the starter lab.
func retiredCatalogEntry(t *testing.T) (retired, catalog string) {
	t.Helper()
	m := podaro.Retirement()
	if len(m.Scenarios) == 0 {
		t.Fatal("the embedded manifest lists no retired template")
	}
	retired = m.Scenarios[0].Name
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	catalog = filepath.Join(config.StateDir(), "catalog")
	for _, dir := range []string{filepath.Join(catalog, retired, "playbooks"), filepath.Join(catalog, "grafana-prometheus-intro", "playbooks")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for dst, src := range map[string]string{
		filepath.Join(catalog, "grafana-prometheus-intro", "lab.yaml"):                          "../../scenarios/grafana-prometheus-intro/lab.yaml",
		filepath.Join(catalog, "grafana-prometheus-intro", "playbooks", "first-dashboard.yaml"): "../../scenarios/grafana-prometheus-intro/playbooks/first-dashboard.yaml",
	} {
		raw, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manifest := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata:\n  name: " + retired + "\n" +
		"profiles:\n  standard:\n    description: an earlier build's copy\n"
	if err := os.WriteFile(filepath.Join(catalog, retired, "lab.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return retired, catalog
}

// `podaro status` on a host with no instances offers every installed
// template but the retired one, and one PDR-W103 line says it is there.
func TestTheEmptyStateNeverOffersARetiredCatalogEntry(t *testing.T) {
	retired, catalog := retiredCatalogEntry(t)
	var buf bytes.Buffer
	lines := emptyStateLines(render.New(&buf, false, true))
	want := []string{
		"no instances yet",
		"→ podaro up grafana-prometheus-intro    4 GB host · all open source",
	}
	if len(lines) != 3 || lines[0] != want[0] || lines[1] != want[1] {
		t.Fatalf("the empty state:\n%s", strings.Join(lines, "\n"))
	}
	w := lines[2]
	if !strings.HasPrefix(w, "! "+pdr.CodeRetiredPresent+" "+retired+" in the catalog") || !strings.Contains(w, "not offered") {
		t.Errorf("the one warning line: %q", w)
	}
	for _, l := range lines {
		if strings.Contains(l, "podaro up "+retired) {
			t.Errorf("the retired template is offered: %q", l)
		}
	}
	if _, err := os.Stat(filepath.Join(catalog, retired, "lab.yaml")); err != nil {
		t.Errorf("the retired entry must stay where the earlier build left it: %v", err)
	}
}

// A host whose catalog holds nothing but the retired entry still names
// the action that fills the screen, and the warning.
func TestTheEmptyStateWithOnlyARetiredEntryOffersTheStarterLab(t *testing.T) {
	retired, catalog := retiredCatalogEntry(t)
	if err := os.RemoveAll(filepath.Join(catalog, "grafana-prometheus-intro")); err != nil {
		t.Fatal(err)
	}
	lines := emptyStateLines(render.New(&bytes.Buffer{}, false, true))
	if len(lines) != 3 || lines[1] != "→ podaro up grafana-prometheus-intro" || !strings.Contains(lines[2], retired) {
		t.Fatalf("the empty state:\n%s", strings.Join(lines, "\n"))
	}
}

// `lab init --from <retired>` is PDR-E107 before the catalog is read,
// although an earlier build left the template there; nothing is written,
// and the installed names it offers instead leave it out.
func TestLabInitRefusesARetiredTemplateEvenFromTheCatalog(t *testing.T) {
	retired, _ := retiredCatalogEntry(t)
	dir := filepath.Join(t.TempDir(), "scaffold")
	code, out, errOut := run(t, "lab", "init", "--from", retired, dir)
	if code != 1 || !strings.Contains(errOut, pdr.CodeTemplateRetired) || !strings.Contains(errOut, "retired by the owner on "+podaro.Retirement().RetiredOn) {
		t.Fatalf("lab init --from the retired template: code=%d out=%q err=%q", code, out, errOut)
	}
	if !strings.Contains(errOut, "grafana-prometheus-intro") || strings.Count(errOut, retired) != 1 {
		t.Errorf("the refusal must offer the other templates and name the retired one only in its message: %q", errOut)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("a refusal created the target directory: %v", err)
	}
	for _, n := range installedTemplates() {
		if n == retired {
			t.Errorf("the installed-names list offers the retired template: %v", installedTemplates())
		}
	}
	// A typo's refusal, too, never offers it.
	code, _, errOut = run(t, "lab", "init", "--from", "nope", filepath.Join(t.TempDir(), "x"))
	if code != 1 || !strings.Contains(errOut, "PDR-E207") || strings.Contains(errOut, retired) {
		t.Errorf("an uninstalled template's refusal: code=%d err=%q", code, errOut)
	}
}
