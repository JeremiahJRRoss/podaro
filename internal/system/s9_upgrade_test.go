// SPDX-License-Identifier: AGPL-3.0-only

package system

// Plan S9, INSTALL §6: `podaro system upgrade`. The properties that
// matter are about what does *not* happen — a download that does not
// match its manifest never becomes the binary, and no failure before the
// replacement leaves anything changed.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// release serves a version, its binary and its SHA256SUMS — a mirror of
// exactly the shape an air-gapped operator fills by hand.
type release struct {
	version string
	binary  []byte
	// corrupt makes the manifest disagree with the file, which is the
	// case the whole download order exists for.
	corrupt bool
	srv     *httptest.Server
}

func newRelease(t *testing.T, version string, body string) *release {
	t.Helper()
	r := &release{version: version, binary: []byte(body)}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case strings.HasSuffix(req.URL.Path, "/latest"):
			fmt.Fprintf(w, "/tag/v%s\n", r.version)
		case strings.HasSuffix(req.URL.Path, "/SHA256SUMS"):
			sum := sha256.Sum256(r.binary)
			digest := hex.EncodeToString(sum[:])
			if r.corrupt {
				digest = strings.Repeat("0", 64)
			}
			fmt.Fprintf(w, "%s  %s\n", digest, AssetName(r.version))
		case strings.HasSuffix(req.URL.Path, AssetName(r.version)):
			_, _ = w.Write(r.binary)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

// upgradeEnv gives the test its own XDG tree and a binary to replace.
func upgradeEnv(t *testing.T) (exe string, stateDB string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "run"))
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	exe = filepath.Join(bin, "podaro")
	if err := os.WriteFile(exe, []byte("the running binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	stateDB = filepath.Join(dir, "state", "podaro", "state.db")
	if err := os.MkdirAll(filepath.Dir(stateDB), 0o700); err != nil {
		t.Fatal(err)
	}
	// A real state file, held open by a real store, with a row committed
	// into it — because that is what an upgrade runs against. The fixture
	// here used to be the bytes "pretend this is sqlite", and a file copy
	// passes that trivially: it could not tell whether the backup held
	// what the database held.
	store, err := state.OpenSQLite(stateDB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.PutInstance(state.Instance{Name: "class", Template: "t", Mode: "delivery",
		Source: "/s", Created: now, Updated: now}); err != nil {
		t.Fatal(err)
	}
	return exe, stateDB
}

// backedUpInstances opens a backup read-only and lists what it holds.
func backedUpInstances(t *testing.T, path string) []state.Instance {
	t.Helper()
	store, err := state.OpenSQLite(path)
	if err != nil {
		t.Fatalf("opening the backup at %s: %v", path, err)
	}
	defer store.Close()
	got, err := store.ListInstances()
	if err != nil {
		t.Fatalf("reading the backup: %v", err)
	}
	return got
}

// TestUpgradeVerifiesBeforeItReplaces: a download whose digest does not
// match the release manifest is refused, the running binary is untouched
// and the download is gone. This is the property the command's whole
// order of operations exists for.
func TestUpgradeVerifiesBeforeItReplaces(t *testing.T) {
	exe, stateDB := upgradeEnv(t)
	rel := newRelease(t, "9.9.9", "a binary that is not what the manifest says")
	rel.corrupt = true
	var restarted bool
	err := Upgrade(render.New(io.Discard, false, false), UpgradeOptions{
		Base: rel.srv.URL, Exe: exe, Restart: func() error { restarted = true; return nil },
	})
	if code(err) != pdr.CodeUpgradeRefused {
		t.Fatalf("a corrupt download: %v — want %s", err, pdr.CodeUpgradeRefused)
	}
	if got, _ := os.ReadFile(exe); string(got) != "the running binary" {
		t.Fatalf("the binary was replaced by a download that failed its checksum")
	}
	if restarted {
		t.Fatalf("the service was restarted after a refused upgrade")
	}
	if _, err := os.Stat(stateDB + ".bak-v" + podaro.Version()); err == nil {
		t.Fatalf("the state was backed up before the download was verified")
	}
	// The discarded download is not left beside the binary.
	entries, _ := os.ReadDir(filepath.Dir(exe))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".podaro-upgrade-") {
			t.Fatalf("a refused download was left behind: %s", e.Name())
		}
	}
}

// TestUpgradeReplacesAndBacksUp: the happy path, in the order INSTALL §6
// prints — verified, backed up, replaced, restarted.
func TestUpgradeReplacesAndBacksUp(t *testing.T) {
	exe, stateDB := upgradeEnv(t)
	rel := newRelease(t, "9.9.9", "the new binary")
	var restarted bool
	var out strings.Builder
	err := Upgrade(render.New(&out, false, false), UpgradeOptions{
		Base: rel.srv.URL, Exe: exe,
		Restart: func() error {
			// The restart happens after the replacement, never before.
			if got, _ := os.ReadFile(exe); string(got) != "the new binary" {
				t.Errorf("the service was restarted before the binary was replaced")
			}
			restarted = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("upgrade: %v\n%s", err, out.String())
	}
	if !restarted {
		t.Errorf("the service was not restarted")
	}
	if got, _ := os.ReadFile(exe); string(got) != "the new binary" {
		t.Errorf("the binary was not replaced")
	}
	if fi, err := os.Stat(exe); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("the new binary is mode %v, want 0755", fi.Mode().Perm())
	}
	backup := stateDB + ".bak-v" + podaro.Version()
	if got := backedUpInstances(t, backup); len(got) != 1 || got[0].Name != "class" {
		t.Errorf("the backup at %s holds %+v, not the lab the state holds", backup, got)
	}
	if got := backedUpInstances(t, stateDB); len(got) != 1 || got[0].Name != "class" {
		t.Errorf("the backup moved the state instead of copying it: %+v", got)
	}
	board := out.String()
	for _, want := range []string{"checksum verified", "state backed up", "binary replaced", "engine v9.9.9"} {
		if !strings.Contains(board, want) {
			t.Errorf("the board does not say %q:\n%s", want, board)
		}
	}
}

// TestUpgradeRefusesADowngrade: migrations are forward-only, so an older
// binary would refuse the state a newer one migrated (PDR-E211). The
// refusal names the way back rather than performing half of it.
func TestUpgradeRefusesADowngrade(t *testing.T) {
	exe, _ := upgradeEnv(t)
	rel := newRelease(t, "0.0.0", "an older binary")
	err := Upgrade(render.New(io.Discard, false, false), UpgradeOptions{
		Base: rel.srv.URL, Exe: exe, Restart: func() error { return nil },
	})
	if code(err) != pdr.CodeUpgradeRefused {
		t.Fatalf("a downgrade: %v — want %s", err, pdr.CodeUpgradeRefused)
	}
	var pe *pdr.Error
	if errors.As(err, &pe) && !strings.Contains(pe.Next, "state.db.bak-v") {
		t.Errorf("the refusal does not name the way back: %+v", pe)
	}
	if got, _ := os.ReadFile(exe); string(got) != "the running binary" {
		t.Fatalf("a downgrade replaced the binary")
	}
}

// TestUpgradeIsANoOpOnTheCurrentVersion: the release location says the
// version already running, and the command says so rather than
// downloading and replacing a binary with itself.
func TestUpgradeIsANoOpOnTheCurrentVersion(t *testing.T) {
	exe, stateDB := upgradeEnv(t)
	rel := newRelease(t, podaro.Version(), "same version")
	var out strings.Builder
	if err := Upgrade(render.New(&out, false, false), UpgradeOptions{
		Base: rel.srv.URL, Exe: exe, Restart: func() error { t.Error("restarted"); return nil },
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "already current") {
		t.Errorf("the board does not say it is current:\n%s", out.String())
	}
	if _, err := os.Stat(stateDB + ".bak-v" + podaro.Version()); err == nil {
		t.Errorf("a no-op upgrade backed up the state")
	}
}

// TestDigestOfReadsAManifest: the format sha256sum writes, and the
// `*name` form a binary-mode manifest uses.
func TestDigestOfReadsAManifest(t *testing.T) {
	sums := "aaaa  podaro-1.0.0-linux-amd64\nbbbb  SHA256SUMS.txt\ncccc *podaro-1.0.0-linux-arm64\n"
	for _, tc := range []struct{ asset, want string }{
		{"podaro-1.0.0-linux-amd64", "aaaa"},
		{"podaro-1.0.0-linux-arm64", "cccc"},
	} {
		got, ok := digestOf(sums, tc.asset)
		if !ok || got != tc.want {
			t.Errorf("digestOf(%s) = %q %v", tc.asset, got, ok)
		}
	}
	if _, ok := digestOf(sums, "podaro-1.0.0-linux-riscv64"); ok {
		t.Errorf("an asset the manifest does not name must not be found")
	}
}
