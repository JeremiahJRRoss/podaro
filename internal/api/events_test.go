// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The live feed (API §4, plan S7). Every case runs the real handler over
// a real HTTP connection on the fake runtime and reads the wire.

func eventsHarness(t *testing.T) (*httptest.Server, *engine.Engine, state.Store) {
	t.Helper()
	srv, eng, store, _ := eventsHarnessDir(t)
	return srv, eng, store
}

// eventsHarnessDir is the same harness and also hands back the state
// directory, so a test can reach an instance's evidence journal — the
// journal is files under instances/<name>/evidence, not the store's
// event rows, and a test that writes to the wrong one produces no state
// at all (found writing round 13's fixture).
func eventsHarnessDir(t *testing.T) (*httptest.Server, *engine.Engine, state.Store, string) {
	t.Helper()
	t.Setenv(runtime.EnvFakeReadyDelay, "50ms")
	dir := t.TempDir()
	fake, err := runtime.NewFake(filepath.Join(dir, "world.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fake.Close)
	store := state.NewMemory()
	eng := engine.New(engine.Options{Store: store, Runtime: fake, StateDir: dir,
		Library:      lab.DirLibrary(filepath.Join("..", "lab", "testdata", "modules")),
		PollInterval: 20 * time.Millisecond})
	t.Cleanup(func() { shutdown(eng) })
	srv := httptest.NewServer(New(Options{Engine: eng}).SocketHandler())
	t.Cleanup(srv.Close)
	return srv, eng, store, dir
}

// sseFrame is one parsed frame off the wire.
type sseFrame struct {
	ID    string
	Event string
	Data  map[string]any
}

// readFrames reads frames until want are seen or the budget passes. The
// read itself blocks, so the budget is enforced by closing the stream
// from another goroutine — a deadline checked only between reads would
// wait for the next heartbeat.
func readFrames(t *testing.T, body *bufio.Reader, want int, budget time.Duration, stop func()) []sseFrame {
	t.Helper()
	done := make(chan struct{})
	timer := time.AfterFunc(budget, func() {
		stop()
		close(done)
	})
	defer func() {
		if timer.Stop() {
			return
		}
		<-done
	}()
	var out []sseFrame
	cur := sseFrame{}
	for len(out) < want {
		line, err := body.ReadString('\n')
		if err != nil {
			return out
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "":
			if cur.Event != "" {
				out = append(out, cur)
			}
			cur = sseFrame{}
		case strings.HasPrefix(line, "id: "):
			cur.ID = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "event: "):
			cur.Event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			_ = json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &cur.Data)
		}
	}
	return out
}

// journalFrames are the frames that are journal facts. A snapshot — the
// ladder, and the job row the feed sends beside it — carries no id by
// rule, precisely so a reconnect cannot resume after one; that rule is
// what separates the two here, rather than a list of event names a new
// snapshot would quietly fall outside of.
func journalFrames(frames []sseFrame) []sseFrame {
	var out []sseFrame
	for _, f := range frames {
		if f.ID != "" {
			out = append(out, f)
		}
	}
	return out
}

func openFeed(t *testing.T, srv *httptest.Server, name, lastID string) (*bufio.Reader, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+Prefix+"/instances/"+name+"/events", nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("feed status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		cancel()
		t.Fatalf("feed content-type %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		cancel()
		t.Fatalf("an event stream must not be cached, got %q", cc)
	}
	return bufio.NewReader(resp.Body), func() { cancel(); resp.Body.Close() }
}

func TestTheFeedOpensWithALadderSnapshot(t *testing.T) {
	srv, eng, _ := eventsHarness(t)
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(context.Background(), engine.CreateRequest{Path: fixture, Name: "feed"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	body, closeFeed := openFeed(t, srv, "feed", "")
	defer closeFeed()
	frames := readFrames(t, body, 3, 5*time.Second, closeFeed)
	if len(frames) == 0 {
		t.Fatal("the feed sent nothing on connect")
	}
	if frames[0].Event != "ladder" {
		t.Fatalf("the first frame is the ladder snapshot, got %q", frames[0].Event)
	}
	// A snapshot is not a journal fact: it must not move the client's
	// cursor, or a reconnect would resume past facts it never saw.
	for _, f := range frames {
		if f.Event == "ladder" && f.ID != "" {
			t.Fatalf("a ladder frame carries an id (%s); it must not", f.ID)
		}
	}
}

func TestTheFeedReplaysTheJournalFromLastEventID(t *testing.T) {
	srv, eng, store := eventsHarness(t)
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(context.Background(), engine.CreateRequest{Path: fixture, Name: "feed"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	// Journal facts to replay. Audit records are written through the
	// engine's own store, so they arrive in the merged evidence list
	// exactly as a reveal's or a reset's would — and with `au_<seq>` ids,
	// which is the case a text cursor gets wrong.
	base := time.Now().UTC()
	for i := 1; i <= 12; i++ {
		if err := store.AppendAudit(state.Audit{Seq: int64(i), At: base.Add(time.Duration(i) * time.Millisecond),
			Action: "reveal", Actor: "operator", Mechanism: "session", Instance: "feed",
			Detail: "secret nginx-admin"}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := eng.Evidence("feed", engine.EvidenceFilter{}, engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 6 {
		t.Fatalf("the replay case needs journal facts to replay, got %d", len(entries))
	}
	// Resume from the first entry: every later one must be replayed, in
	// id order, and none at or before it.
	from := entries[0].ID
	body, closeFeed := openFeed(t, srv, "feed", from)
	defer closeFeed()
	frames := readFrames(t, body, len(entries)-1, 5*time.Second, closeFeed)
	var ids []string
	for _, f := range frames {
		if f.ID != "" {
			ids = append(ids, f.ID)
		}
	}
	if len(ids) == 0 {
		t.Fatalf("nothing was replayed after %s", from)
	}
	// The wanted ids are exactly the entries after `from` in the engine's
	// own order — the order the feed must reproduce, ids from both
	// namespaces included.
	var want []string
	seenFrom := false
	for _, e := range entries {
		if seenFrom {
			want = append(want, e.ID)
			continue
		}
		if e.ID == from {
			seenFrom = true
		}
	}
	if len(ids) != len(want) {
		t.Fatalf("replayed %d entries after %s, want %d\n got: %v\nwant: %v", len(ids), from, len(want), ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("replay diverges at %d: got %s, want %s\n got: %v\nwant: %v", i, ids[i], want[i], ids, want)
		}
	}
}

// A new client is not handed the whole history: the journal is the
// Evidence tab's job. It gets the ladder it needs to draw the screen.
func TestANewFeedIsNotTheWholeJournal(t *testing.T) {
	srv, eng, _ := eventsHarness(t)
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(context.Background(), engine.CreateRequest{Path: fixture, Name: "feed"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	body, closeFeed := openFeed(t, srv, "feed", "")
	defer closeFeed()
	frames := readFrames(t, body, 40, 2500*time.Millisecond, closeFeed)
	for _, f := range frames {
		if f.Event == "checkpoint" || f.Event == "audit" {
			t.Fatalf("a fresh feed replayed a journal fact (%s %s) it was not asked for", f.Event, f.ID)
		}
	}
}

// The feed is instance-scoped: an attendee bound to one instance cannot
// open another's (§2.4's fixed grant, enforced by scoped()).
func TestTheFeedRefusesAnotherInstance(t *testing.T) {
	srv, eng, _ := eventsHarness(t)
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(context.Background(), engine.CreateRequest{Path: fixture, Name: "mine"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+Prefix+"/instances/mine/events", nil)
	base := New(Options{Engine: eng})
	rec := httptest.NewRecorder()
	p := &Principal{Mechanism: "session", Subject: "attendee", Scope: "instance",
		Session: &state.Session{Instance: "other"}}
	req.SetPathValue("name", "mine")
	base.events(rec, req.WithContext(WithPrincipal(req.Context(), p)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("an attendee bound to another instance got %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("the refusal was written as a stream, not an error: %q", ct)
	}
}

// An instance that does not exist is an ordinary error, not an empty
// stream that looks like an idle lab.
func TestTheFeedRefusesAMissingInstanceBeforeStreaming(t *testing.T) {
	srv, _, _ := eventsHarness(t)
	resp, err := http.Get(srv.URL + Prefix + "/instances/nope/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("a missing instance opened a stream: %q", ct)
	}
}

// TestAFreshFeedStillSendsWhatHappensNext: opening without a
// Last-Event-ID means "start from now", not "send nothing ever". Before
// this was fixed the cursor stayed at its zero value and the comparator
// refused every entry against it, so a fresh client saw ladder frames
// and never a checkpoint, job or audit event — the feed the console runs
// on delivered nothing but the ladder.
func TestAFreshFeedStillSendsWhatHappensNext(t *testing.T) {
	srv, eng, store := eventsHarness(t)
	ctx := context.Background()
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: "fresh"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	body, stop := openFeed(t, srv, "fresh", "")
	defer stop()
	// Something happens after the feed is open. It must arrive — the
	// opening frames are snapshots (a ladder per service, one for the
	// instance, and the job row) and carry no history, which is the
	// other half of the promise.
	if err := store.AppendAudit(state.Audit{At: time.Now().UTC(), Instance: "fresh",
		Action: "reveal", Actor: "alice", Mechanism: "session", Detail: "admin"}); err != nil {
		t.Fatal(err)
	}
	frames := readFrames(t, body, 4, 6*time.Second, stop)
	journal := journalFrames(frames)
	if len(journal) != 1 {
		t.Fatalf("a fresh feed sent %d journal events, want the one appended after it opened; frames: %+v", len(journal), frames)
	}
	if journal[0].Event != "audit" || journal[0].Data["detail"] != "admin" {
		t.Fatalf("the wrong entry arrived: %+v", journal[0])
	}
	if journal[0].ID == "" {
		t.Fatalf("a journal frame carries its id so a reconnect can resume: %+v", journal[0])
	}
}

// TestTheFeedFollowsEvidenceOrderNotAComparator: the cursor is a
// position in the list the engine handed back, not a key derived from
// an entry. `engine.Evidence` merges the journal's own append order with
// the audit stream's sequence and re-sorts neither; a comparator that
// ordered by wall time and then by id as text disagreed with it in three
// ways — `au_10` before `au_9`, every `au_` below every `ev_`, and every
// pair a clock correction moved. This case walks the third, which is the
// one that needs no particular sequence numbers to reproduce: the host's
// clock steps back partway through, and the entries written after it
// must still arrive.
func TestTheFeedFollowsEvidenceOrderNotAComparator(t *testing.T) {
	srv, eng, store := eventsHarness(t)
	ctx := context.Background()
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: "ordered"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	// Ten audit rows, and the host's clock steps back in the middle of
	// them — an ntp correction, which happens. `engine.Evidence` keeps
	// the audit stream in its own sequence whatever the clock did
	// (mergeEvidence merges two ordered sequences; it does not re-sort
	// either), so the list holds all ten in the order they were written.
	at := time.Now().UTC().Add(10 * time.Second)
	for i := 1; i <= 10; i++ {
		when := at
		if i > 5 {
			when = at.Add(-2 * time.Second)
		}
		if err := store.AppendAudit(state.Audit{At: when, Instance: "ordered", Action: "reveal",
			Actor: "alice", Mechanism: "session", Detail: "secret-" + itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := eng.Evidence("ordered", engine.EvidenceFilter{}, engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 11 {
		t.Fatalf("expected the create's journal plus ten audit rows, got %d", len(entries))
	}
	// Resume from the first entry: everything after it must arrive, in
	// the order engine.Evidence put it. That walk crosses both traps at
	// once — the namespace jump from `ev_` to `au_`, and the single- to
	// double-digit boundary where `au_10` sorts before `au_9` as text.
	from := entries[0]
	var want []string
	for _, e := range entries[1:] {
		want = append(want, e.ID)
	}
	body, stop := openFeed(t, srv, "ordered", from.ID)
	defer stop()
	frames := readFrames(t, body, len(want)+2, 6*time.Second, stop)
	var got []string
	for _, f := range frames {
		if f.Event != "ladder" {
			got = append(got, f.ID)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("replay sent %d entries, want %d\n got: %v\nwant: %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("replay order\n got: %v\nwant: %v (engine.Evidence's own order)", got, want)
		}
	}
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}

// TestTheFeedSendsAnEntryThatLandsBeforeItsCursor: the round-two
// finding. `engine.mergeEvidence` decides between its two sequences by
// time, so an audit row written after the host's clock stepped back
// lands *ahead* of the journal entry a feed last sent. A position in
// the merged list therefore cannot represent a feed's progress: "after
// the cursor" misses that row on this connection and on every reconnect.
// The feed tracks each sequence separately, so it does not.
func TestTheFeedSendsAnEntryThatLandsBeforeItsCursor(t *testing.T) {
	srv, eng, store := eventsHarness(t)
	ctx := context.Background()
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: "backwards"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	entries, err := eng.Evidence("backwards", engine.EvidenceFilter{}, engine.Socket)
	if err != nil || len(entries) == 0 {
		t.Fatalf("evidence: %v %d", err, len(entries))
	}
	last := entries[len(entries)-1]
	body, stop := openFeed(t, srv, "backwards", "")
	defer stop()

	// The clock stepped back: this row is written now, and is timed
	// before everything the feed has already seen. In the merged list it
	// sorts ahead of the journal entry the cursor names.
	if err := store.AppendAudit(state.Audit{At: last.At.Add(-time.Hour), Instance: "backwards",
		Action: "reveal", Actor: "alice", Mechanism: "session", Detail: "written-after-a-clock-correction"}); err != nil {
		t.Fatal(err)
	}
	after, err := eng.Evidence("backwards", engine.EvidenceFilter{}, engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if after[len(after)-1].Audit != nil {
		t.Fatalf("the fixture must place the new row before the cursor to prove anything; it is last")
	}

	frames := readFrames(t, body, 4, 6*time.Second, stop)
	journal := journalFrames(frames)
	if len(journal) != 1 || journal[0].Data["detail"] != "written-after-a-clock-correction" {
		t.Fatalf("the entry that landed before the cursor was not sent; frames: %+v", frames)
	}
}
