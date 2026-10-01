// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/brand"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// The reconciliation plan's R5, task 5 — the bare-binary path: `system
// install` writes the licence and the notices the binary carries to
// <state>/legal/ and names the directory on its board; the directory
// holds the release tarball's legal entries.
func TestInstallWritesTheLegalFilesFromTheBinary(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	detail, err := writeLegal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(detail, "/legal/ · licence and notices, from the binary") {
		t.Fatalf("the board's row: %q", detail)
	}
	for _, name := range []string{"LICENSE", "NOTICE", "TRADEMARKS.md", "THIRD-PARTY-NOTICES.md", "LICENSES/Apache-2.0.txt", "SOURCE-AND-BUILD.md"} {
		got, err := os.ReadFile(filepath.Join(state, "podaro", "legal", name))
		if err != nil {
			t.Errorf("<state>/legal/%s: %v", name, err)
			continue
		}
		want, _ := os.ReadFile(filepath.Join("..", "..", name))
		if string(got) != string(want) {
			t.Errorf("<state>/legal/%s is not the binary's copy", name)
		}
	}
}

// The engine keeps what an install wrote current — after `system upgrade`
// replaced the binary, <state>/legal/ says what the new binary says — and
// creates nothing the install did not: a state directory without it stays
// without it, for doctor to name.
func TestTheEngineRefreshesOnlyWhatTheInstallWrote(t *testing.T) {
	state := t.TempDir()
	logf := func(string, ...any) {}
	refreshLegalFiles(state, logf)
	if _, err := os.Stat(filepath.Join(state, "legal")); !os.IsNotExist(err) {
		t.Fatal("the engine created <state>/legal/, which is the install's to write")
	}
	dir := filepath.Join(state, "legal")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "NOTICE"), []byte("an older release's NOTICE\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	refreshLegalFiles(state, logf)
	got, _ := os.ReadFile(filepath.Join(dir, "NOTICE"))
	want, _ := os.ReadFile(filepath.Join("..", "..", "NOTICE"))
	if string(got) != string(want) {
		t.Fatal("<state>/legal/NOTICE was not refreshed to the running binary's")
	}
	if _, err := os.Stat(filepath.Join(dir, "LICENSES", "Apache-2.0.txt")); err != nil {
		t.Fatalf("the refresh did not write the whole set: %v", err)
	}
}

// Uninstall takes the notices install.sh put beside the binary with the
// binary they cover (INSTALL §7: what remains is only what Podman owns).
func TestUninstallRemovesTheNoticesBesideTheBinary(t *testing.T) {
	_, home := paths(t)
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "podaro"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"LICENSE", "NOTICE", "TRADEMARKS.md", "THIRD-PARTY-NOTICES.md"} {
		b, _ := os.ReadFile(filepath.Join("..", "..", name))
		if err := os.WriteFile(filepath.Join(bin, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Another program's file in the same directory stays.
	if err := os.WriteFile(filepath.Join(bin, "other-tool"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if code := removeInstallation(render.New(&buf, false, true)); code != 0 {
		t.Fatalf("exit %d\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "✓ binary and the notices beside it removed") {
		t.Fatalf("the board:\n%s", buf.String())
	}
	entries, _ := os.ReadDir(bin)
	if len(entries) != 1 || entries[0].Name() != "other-tool" {
		t.Fatalf("~/.local/bin holds %v, want only the other program's file", entries)
	}
}

// The systemd unit's description is the build's display title
// (internal/brand; hack/rebrand_test.sh leaves this one to a unit test,
// since writing the unit needs a systemd user manager); its name,
// podaro.service, and its command are identifiers and do not move.
func TestTheUnitDescriptionIsTheBuildsTitle(t *testing.T) {
	old := brand.Title
	brand.Title = "Workbench Studio"
	defer func() { brand.Title = old }()
	unit := UnitFile("/opt/podaro/.local/bin/podaro")
	if !strings.Contains(unit, "\nDescription=Workbench Studio engine\n") || !strings.Contains(unit, "\nExecStart=/opt/podaro/.local/bin/podaro engine serve\n") {
		t.Fatalf("the unit:\n%s", unit)
	}
}
