// SPDX-License-Identifier: AGPL-3.0-only

package system

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

// The reconciliation plan's R3, INSTALL §2 step 2: what an earlier build
// extracted of a template the owner has since retired is never offered by
// the install board and never deleted by it; one row says it is there.
// Names come from the embedded manifest; nothing here spells one.

func retiredTemplateName(t *testing.T) string {
	t.Helper()
	m := podaro.Retirement()
	if len(m.Scenarios) == 0 {
		t.Fatal("the embedded manifest lists no retired template")
	}
	return m.Scenarios[0].Name
}

// leaveRetiredCatalogEntry writes the retired template into the state
// directory's catalog, as an earlier build's extraction left it.
func leaveRetiredCatalogEntry(t *testing.T, retired string) string {
	t.Helper()
	dir := filepath.Join(config.StateDir(), "catalog", retired)
	if err := os.MkdirAll(filepath.Join(dir, "playbooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte("an earlier build's copy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The board's catalog row offers only what may be offered; a retired
// entry an earlier build extracted stays on disk, untouched, and is named
// on a row of its own — and a host that never held one gets the board
// INSTALL §2 shows, with no row added.
func TestTheInstallBoardNeverOffersARetiredCatalogEntry(t *testing.T) {
	retired := retiredTemplateName(t)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	if _, ok := retiredCatalogRow(); ok {
		t.Fatal("a host that never held retired content must get no warning row")
	}
	dir := leaveRetiredCatalogEntry(t, retired)
	detail, err := extractCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if detail != "grafana-prometheus-intro" {
		t.Fatalf("the catalog row offers %q, want the starter lab alone", detail)
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "lab.yaml")); err != nil || string(raw) != "an earlier build's copy\n" {
		t.Fatalf("extraction touched the retired entry: %q %v", raw, err)
	}
	row, ok := retiredCatalogRow()
	if !ok || !row.Warn || row.Label != "retired template" || !strings.HasPrefix(row.Detail, retired+" present") || !strings.HasSuffix(row.Detail, pdr.CodeRetiredPresent) {
		t.Fatalf("the warning row: %+v %v", row, ok)
	}
	var buf bytes.Buffer
	RenderInstallBlock(render.New(&buf, false, true), []StepResult{
		{Label: "starter catalog", Detail: detail},
		row,
	}, false)
	want := "✓ starter catalog    grafana-prometheus-intro\n" +
		"! retired template   " + retired + " present, unsupported by this release · not offered · " + pdr.CodeRetiredPresent + "\n"
	if buf.String() != want {
		t.Fatalf("the board:\n%s\nwant:\n%s", buf.String(), want)
	}
}
