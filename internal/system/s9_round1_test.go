// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/state"
)

// The rollback backup copied `state.db` byte for byte while the engine
// held it. The store runs in WAL mode, so a row committed since the last
// checkpoint lives in `state.db-wal` and is not in the main file at all:
// the backup an operator is told to restore was missing the newest
// instances, jobs, credentials and evidence — silently, since it is a
// perfectly valid database of an older moment.
func TestTheRollbackBackupHoldsWhatWasCommitted(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "state.db")
	store, err := state.OpenSQLite(src)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.PutInstance(state.Instance{Name: "class", Template: "t", Mode: "delivery",
		Source: "/s", Created: now, Updated: now}); err != nil {
		t.Fatal(err)
	}

	// The premise: the row is committed, and the store is still open —
	// which is the state an upgrade runs against, the engine being the
	// thing being upgraded. Whether it has reached the main file yet is
	// SQLite's business and not something a backup may depend on.
	if got, err := store.ListInstances(); err != nil || len(got) != 1 {
		t.Fatalf("premise: the store holds %+v %v", got, err)
	}

	dst := filepath.Join(dir, "state.db.bak-v0.0.1-dev")
	if ok, err := backupState(src, dst); err != nil || !ok {
		t.Fatalf("backing up: %v %v", ok, err)
	}
	backup, err := state.OpenSQLite(dst)
	if err != nil {
		t.Fatalf("the backup is not a database: %v", err)
	}
	defer backup.Close()
	got, err := backup.ListInstances()
	if err != nil {
		t.Fatalf("reading the backup: %v", err)
	}
	if len(got) != 1 || got[0].Name != "class" {
		t.Errorf("the backup holds %+v, not the lab that was committed before it", got)
	}
	// And the state it copied is still there: a backup that moved the
	// database would be the worst of the failures it exists to prevent.
	if left, err := store.ListInstances(); err != nil || len(left) != 1 {
		t.Errorf("the backup disturbed the state it copied: %+v %v", left, err)
	}
}

// GitHub answers `/releases/latest` with a redirect to the tag. Following
// it — which the default client does — lands on the release *page*, whose
// HTML carries a `/tag/` link for every release the repository has ever
// had, so "the text after the last /tag/" named some other version
// entirely. The redirect's own Location is the answer.
func TestTheLatestReleaseIsTheOneTheRedirectNames(t *testing.T) {
	var page string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/latest") {
			http.Redirect(w, r, "/releases/tag/v9.9.9", http.StatusFound)
			return
		}
		// What the redirect leads to, as GitHub's release page does:
		// links to every release, newest first, so the *last* one named
		// is the oldest.
		fmt.Fprint(w, page)
	}))
	defer srv.Close()
	page = `<!DOCTYPE html><html><body>` +
		`<a href="/releases/tag/v9.9.9">v9.9.9</a>` +
		`<a href="/releases/tag/v0.9.0">v0.9.0</a>` +
		`<a href="/releases/tag/v0.0.1">v0.0.1</a></body></html>`

	got, err := latestVersion(UpgradeOptions{Base: srv.URL + "/releases", Client: http.DefaultClient})
	if err != nil {
		t.Fatalf("resolving latest: %v", err)
	}
	if got != "9.9.9" {
		t.Errorf("latest is %q, want 9.9.9 — the redirect names the release, the page it leads to names all of them", got)
	}
}

// A mirror filled by hand answers 200 with the line the redirect would
// have carried (§5, and hack/upgrade_test.sh writes exactly that), so
// both shapes must work — but a *page* arriving where a one-line answer
// belongs is an error, not something to scrape.
func TestAMirrorAnswersWithItsOwnLineAndNothingElse(t *testing.T) {
	for _, c := range []struct {
		name, body, want string
	}{
		{"the tag line a mirror writes", "/tag/v1.2.3\n", "1.2.3"},
		{"a bare version", "1.2.3\n", "1.2.3"},
		{"a page is not an answer", "<!DOCTYPE html><a href=\"/tag/v0.0.1\">old</a>", ""},
		// A mirror being filled: the file is there and empty. The
		// refusal is the point — indexing the first field of nothing
		// took the command down instead.
		{"an empty file is a refusal, not a panic", "", ""},
		{"whitespace is the same", "   \n\n", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, c.body)
			}))
			defer srv.Close()
			got, err := latestVersion(UpgradeOptions{Base: srv.URL, Client: http.DefaultClient})
			if c.want == "" {
				if err == nil {
					t.Fatalf("a page answered as version %q", got)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got %q %v, want %q", got, err, c.want)
			}
		})
	}
}
