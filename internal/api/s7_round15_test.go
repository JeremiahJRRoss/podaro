// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// progressFault is a store whose progress reads fail on demand.
type progressFault struct {
	state.Store
	fail bool
}

func (p *progressFault) GetProgress(instance, playbook string) (*state.Progress, error) {
	if p.fail {
		return nil, errors.New("database is locked (transient)")
	}
	return p.Store.GetProgress(instance, playbook)
}

// newCatalogServerWith is newCatalogServer over a store the caller
// supplies, so a fault can be planted under the lab surface.
func newCatalogServerWith(t *testing.T, store state.Store) (*httptest.Server, *engine.Engine) {
	t.Helper()
	t.Setenv(runtime.EnvFakeReadyDelay, "100ms")
	dir := t.TempDir()
	fake, err := runtime.NewFake(filepath.Join(dir, "world.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fake.Close)
	eng := engine.New(engine.Options{Store: store, Runtime: fake, StateDir: dir,
		CatalogDir: filepath.Join("..", "..", "scenarios"), PollInterval: 50 * time.Millisecond})
	t.Cleanup(func() { shutdown(eng) })
	srv := httptest.NewServer(New(Options{Engine: eng}).SocketHandler())
	t.Cleanup(srv.Close)
	return srv, eng
}

// TestTheRailIsRefusedWhenTheProgressItWritesBackCannotBeRead.
//
// The rail is not a read-only view of progress: the page changes one
// field of the record it is handed and `PUT …/progress` replaces the
// stored row whole. So a rail rendered while the engine could not read
// that record hands the page a writable *empty* one — and the next
// navigation writes `steps: {}` back over everything the learner earned.
//
// A store fault is not absence (D27). The HTML representation is refused
// rather than rendered; the JSON twin, which carries no progress, is
// unaffected, because a twin the console needs must not fail a request
// that does not carry it.
func TestTheRailIsRefusedWhenTheProgressItWritesBackCannotBeRead(t *testing.T) {
	store := &progressFault{Store: state.NewMemory()}
	srv, eng := newCatalogServerWith(t, store)
	code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"template": "grafana-prometheus-intro", "name": "intro"})
	if code != http.StatusAccepted {
		t.Fatalf("create: %d %v", code, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := eng.Wait(ctx, out["job"].(map[string]any)["id"].(string)); err != nil {
		t.Fatal(err)
	}
	// There is work to lose: a step the learner walked to. (A status
	// needs a checkpoint result behind it — the engine refuses one that
	// has none — and the position alone is enough to prove the point.)
	code, out = call(t, srv, http.MethodPut, "/instances/intro/playbooks/first-dashboard/progress",
		map[string]any{"current_step": "drive-real-traffic", "steps": map[string]any{}})
	if code != http.StatusOK {
		t.Fatalf("seed the progress: %d %v", code, out)
	}
	// The fixture produced the state this case is about, before anything
	// is asserted about the behaviour.
	if code, out := call(t, srv, http.MethodGet, "/instances/intro/playbooks/first-dashboard/progress", nil); code != http.StatusOK || out["current_step"] != "drive-real-traffic" {
		t.Fatalf("the fixture did not record a position to lose: %d %v", code, out)
	}

	store.fail = true
	status, body := getHTML(t, srv, "/instances/intro/playbooks/first-dashboard")
	if status == http.StatusOK {
		t.Fatalf("the rail rendered while its progress could not be read, and hands the page %s to write back over the position the store holds",
			progressAttr(body))
	}
	if !strings.Contains(body, "PDR-") {
		t.Errorf("the refusal does not name a code: %d %s", status, body)
	}
	// And the JSON twin still answers: it carries the playbook, not the
	// progress, so a console-only twin must not fail it.
	if code, out := call(t, srv, http.MethodGet, "/instances/intro/playbooks/first-dashboard", nil); code != http.StatusOK {
		t.Fatalf("the JSON twin carries no progress and must not be refused with it: %d %v", code, out)
	}
}

// getHTML asks for the HTML representation of a path.
func getHTML(t *testing.T, srv *httptest.Server, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+Prefix+path, nil)
	req.Header.Set("Accept", "text/html")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// progressAttr is the rail's data-progress value, or a note that the
// markup carries none — never a slice taken from an index of -1.
func progressAttr(html string) string {
	const key = `data-progress="`
	i := strings.Index(html, key)
	if i < 0 {
		return "(no data-progress attribute)"
	}
	rest := html[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return "(unterminated data-progress attribute)"
	}
	return `data-progress="` + rest[:j] + `"`
}

// TestTheFeedFollowsAJobThatEndedBehindTheNextOne.
//
// Round 14 sent the job row as a frame and compared only `View.Job`,
// which is the newest row. A job that ends without journal evidence
// while the next is admitted inside one 1.5 s tick is already behind
// that row by the time the feed looks, so its terminal state was never
// sent at all — the same promise round 14 was about, broken in a
// narrower window.
//
// The feed follows every row it has not spoken about since, oldest
// first, which is the order the transitions happened in.
func TestTheFeedFollowsAJobThatEndedBehindTheNextOne(t *testing.T) {
	srv, eng, store := eventsHarness(t)
	ctx := context.Background()
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: "behind"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	v, err := eng.View("behind", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	body, closeFeed := openFeed(t, srv, "behind", "")
	defer closeFeed()
	opening := readFrames(t, body, len(v.Services)+2, 5*time.Second, closeFeed)
	if len(jobFrames(opening, job.ID)) == 0 {
		t.Fatalf("the feed did not open with the instance's job; frames: %s", describe(opening))
	}
	before, err := eng.Evidence("behind", engine.EvidenceFilter{}, engine.Socket)
	if err != nil {
		t.Fatal(err)
	}

	// Inside one tick: a short job ends, and the next is admitted behind
	// it. Neither journals anything, so the rows are the only record.
	done := time.Now().UTC()
	short := state.Job{ID: "job_short15", Kind: "seed", Instance: "behind", State: state.JobSucceeded,
		Stage: "done", Started: done.Add(-time.Second), Finished: &done}
	next := state.Job{ID: "job_next15", Kind: "verify", Instance: "behind", State: state.JobRunning,
		Stage: "running its checkpoints", Started: done}
	for _, j := range []state.Job{short, next} {
		if err := store.PutJob(j); err != nil {
			t.Fatal(err)
		}
	}
	// The fixture produced the state: the short job is behind the newest
	// row, and neither is in the journal.
	settled, err := eng.View("behind", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if settled.Job == nil || settled.Job.ID != next.ID {
		t.Fatalf("the fixture must leave the short job behind the newest row; the view names %+v", settled.Job)
	}
	after, err := eng.Evidence("behind", engine.EvidenceFilter{}, engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("the fixture journalled %d entries; this case is about jobs the journal does not carry", len(after)-len(before))
	}

	frames := readFrames(t, body, 4, 6*time.Second, closeFeed)
	ended := jobFrames(frames, short.ID)
	if len(ended) == 0 {
		t.Fatalf("job %s ended behind %s and the feed never said so; frames: %s", short.ID, next.ID, describe(frames))
	}
	if got := ended[len(ended)-1].Data["state"]; got != string(state.JobSucceeded) {
		t.Fatalf("the feed followed job %s to state %v, not %s", short.ID, got, state.JobSucceeded)
	}
	// And the one that replaced it is reported too, after it: the frames
	// are in the order the transitions happened.
	admitted := jobFrames(frames, next.ID)
	if len(admitted) == 0 {
		t.Fatalf("the job admitted behind the short one was never reported; frames: %s", describe(frames))
	}
	if indexOfFrame(frames, short.ID) > indexOfFrame(frames, next.ID) {
		t.Errorf("the job that ended first was reported after the one that replaced it; frames: %s", describe(frames))
	}
}

// indexOfFrame is where a job's first frame sits, or len(frames) when it
// has none — so an ordering check never reads -1 as "first".
func indexOfFrame(frames []sseFrame, id string) int {
	for i, f := range frames {
		if f.Event == "job" && f.Data["id"] == id {
			return i
		}
	}
	return len(frames)
}
