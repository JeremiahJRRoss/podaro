// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The live feed (API §4, plan S7): `GET /instances/{name}/events`, one
// SSE stream carrying the four named events the console runs on —
// `ladder`, `job`, `checkpoint`, `audit`.
//
// Where the events come from. Three of the four are journal facts, so
// the journal is the stream: every checkpoint result, lifecycle
// milestone and audit record is already written there. Replaying from
// `Last-Event-ID` is therefore reading the journal from an entry — what
// API §4 promises — rather than a buffer a restart would lose.
//
// The cursor is the entry's (At, ID) pair, not its id alone, because the
// engine's evidence list is ordered by time and carries ids from two
// namespaces: journal files (`ev_<ulid>`) and audit records (`au_<seq>`).
// Comparing ids as text would be wrong twice over — `au_9` sorts after
// `au_10`, and every `au_` sorts below every `ev_` — so the feed orders
// exactly as engine.Evidence does and asks "is this entry after the one
// I last sent?" in that same order. `Last-Event-ID` names an entry; the
// feed finds it and resumes from its position. An id the journal does
// not hold is an unknown cursor: the client is sent the ladder and no
// replay, which leaves it no worse off than a fresh connection (the
// journal in full is the Evidence tab's job, not the feed's).
//
// `ladder` is the exception: it is a *snapshot* of the instance view,
// not a journal fact, so it carries no `id:` and never advances the
// client's `Last-Event-ID`. A reconnection resumes from the last journal
// fact the client saw and is sent a fresh ladder snapshot immediately;
// were ladder frames to carry ids, a reconnect would resume after a
// frame the journal does not hold and silently skip real facts.
//
// Change is observed by re-reading at eventTick rather than through an
// engine-wide notification bus: the engine has no such bus, the feed's
// written promise is freshness (UX §11: ≤2 s), and a reader that owns
// its own clock cannot deadlock a job or miss a wake-up. Only changes
// are sent — an idle instance costs one heartbeat comment per period.

const (
	// eventTick is how often the feed re-reads. UX §11 budgets status
	// freshness at 2 s; this leaves room for the read itself.
	eventTick = 1500 * time.Millisecond
	// eventHeartbeat keeps intermediaries from closing an idle stream.
	eventHeartbeat = 20 * time.Second
	// drainBudget is how long the feed will follow an instance's job
	// rows after the instance itself has gone, so a destroy reaches the
	// client with an outcome. The terminal write happens as soon as the
	// job's steps return; the budget is for the store that is retrying
	// one, and it is a bound, not a wait.
	drainBudget = 10 * time.Second
)

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	// The instance must exist, and the caller must be allowed it, before
	// any stream headers are written — an error after them could only be
	// an SSE frame, which no client reads as a failure.
	view, err := s.o.Engine.View(name, actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	flusher, canFlush := w.(http.Flusher)
	if !canFlush {
		// No transport that can stream: say so as an ordinary engine
		// error, before any stream header is written.
		pe := pdr.New(pdr.CodeRuntimeFailed, "this connection cannot carry an event stream")
		pe.Cause = "the HTTP transport does not support flushing"
		pe.Next = "poll GET /instances/" + name + " instead"
		s.writeError(w, r, pe)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "keep-alive")
	// Ask any reverse proxy not to buffer: a buffered event stream is a
	// stream that arrives all at once, at the end.
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// One entitlement for the life of the stream: it is the request's,
	// and the closures below outlive the line that has `r`.
	by := actorOf(r)
	feed := &sseFeed{w: w, flusher: flusher, jobState: func(id string) string {
		j, err := s.o.Engine.Job(id, by)
		if err != nil || j == nil {
			return ""
		}
		return string(j.State)
	}}
	// Where in the journal this feed stands. A fresh client starts at
	// the tail — it is here to watch what happens next, not to be handed
	// the history — and one that names a Last-Event-ID starts after that
	// entry, which is the replay.
	var cursor evCursor
	// Whether this feed has a position at all. A zero cursor means
	// "nothing sent", which is right for a feed that has just stood at
	// the tail and wrong for one whose connect read failed: the first
	// successful read would then send the instance's whole history as
	// though it had just happened.
	placed := false
	// place takes this feed's position from a list of evidence, and
	// replays what the client is owed. It runs at connect, and again on
	// the first read that works when the connect read did not — because
	// the resume is the same wherever that read happens. Round 23 jumped
	// to the tail in that case and never looked the header up, which is
	// not what an unplaceable cursor means: that is an id the journal
	// does not hold, and this was an id nobody looked for (round 24).
	place := func(entries []evidence.Entry) evCursor {
		after := r.Header.Get("Last-Event-ID")
		start, found := indexOf(entries, after)
		switch {
		case after == "" || !found:
			// No header, or a cursor the journal does not hold: replay
			// nothing (guessing would skip real entries or repeat them)
			// but stand at the tail of both sequences, so what happens
			// next still arrives.
			return cursorAt(entries, len(entries))
		default:
			// Everything up to and including the named entry is already
			// the client's; the rest is the replay.
			//
			// One id proves the position of one sequence and no more.
			// The other must not be inferred from where the merge
			// happens to put it: a row written while the client was away
			// lands wherever its timestamp says, and after a backward
			// clock correction that can be *before* the named entry,
			// where a cursor rebuilt from the merged prefix counts it
			// delivered and suppresses it for good.
			//
			// So the rule runs both ways.
			// An audit id places the audit sequence exactly and
			// the journal replays; a journal id places the journal and
			// the audits replay. What that costs is duplicate frames,
			// each carrying its original id, which a client discards.
			// What the inference cost was a reveal, or a checkpoint
			// result, that never arrived at all.
			//
			// Round 2's test walks this on an open connection; these are
			// the two reconnects it did not cover.
			named := entries[start]
			var from evCursor
			if auditRow(named) {
				from = evCursor{audit: named.Audit.Seq}
			} else {
				from = evCursor{journal: named.ID}
			}
			return feed.send(entries, from)
		}
	}
	if entries, err := s.o.Engine.Evidence(name, engine.EvidenceFilter{}, actorOf(r)); err == nil {
		cursor = place(entries)
		placed = true
	}
	ladder := feed.ladder(*view)
	// Every job row, as it stands, oldest first.
	//
	// This is a snapshot and not a replay, which is what round 15 got
	// wrong by carrying the journal's rule across.
	// The journal is append-only *events*, so a fresh feed
	// standing at its tail withholds only history — and a client can ask
	// for that history again by naming an id. A job row is *current
	// state*, row frames carry no id by rule, and `Last-Event-ID` says
	// nothing about them: a reconnecting client has no way to ask about a
	// job at all. So a row this connection has not sent is never marked
	// delivered — one that ended while the client was away, with a newer
	// job admitted behind it, was lost for good.
	//
	// The cost is one frame per job the instance has ever run, on each
	// connect. That is the same shape as the ladder snapshot, and each
	// frame says where a job stands rather than what it did.
	jobs := map[string]string{}
	if rows, err := s.o.Engine.Jobs(name, by); err == nil {
		feed.jobs(rows, jobs)
	}

	ctx := r.Context()
	tick := time.NewTicker(eventTick)
	defer tick.Stop()
	beat := time.NewTicker(eventHeartbeat)
	defer beat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-beat.C:
			if !feed.comment("ping") {
				return
			}
		case <-tick.C:
			// The credential is checked once, when a request is admitted
			// (Server.handle reads the principal the door put on the
			// context) — and this request does not return. A session that
			// expired, or a token that was revoked, went on receiving
			// checkpoint and audit frames for as long as the socket stayed
			// open, while every new request from the same credential was
			// refused. A sign-out that leaves a stream running is not a
			// sign-out.
			if !s.credentialLive(r) {
				feed.named("end", map[string]any{"instance": name,
					"reason": "the credential that opened this stream is no longer valid"}, "")
				return
			}
			v, err := s.o.Engine.View(name, actorOf(r))
			if err != nil {
				// The instance is gone (destroyed) or unreadable: say so
				// once, in the stream's own grammar, and stop. A feed that
				// went quiet would look like an idle lab.
				//
				// Not before the job that removed it has an outcome,
				// though. `destroySteps` deletes the instance and
				// `Engine.run` records the terminal state after it
				// returns, so ending here left the one job a client most
				// wants followed with no state at all — and handed it an
				// `end` frame instead.
				// Job rows outlive their instance, so they are drained
				// first.
				feed.drain(ctx, s.o.Engine, name, jobs, by)
				feed.named("end", map[string]any{"instance": name, "reason": "the instance is no longer readable"}, "")
				return
			}
			entries, err := s.o.Engine.Evidence(name, engine.EvidenceFilter{}, actorOf(r))
			switch {
			case err != nil:
				// A read that failed changes nothing: the cursor stays
				// where it was and the next tick tries again.
			case !placed:
				// The connect read failed, so this feed has never had a
				// position. It takes one here, by the same rule: the
				// tail for a client that named no `Last-Event-ID` — a
				// transient fault is not a reason to replay a lab's
				// history as live activity — and the replay it is owed
				// for one that did.
				cursor = place(entries)
				placed = true
			default:
				cursor = feed.send(entries, cursor)
			}
			if next := ladderFrame(*v); next != ladder {
				ladder = feed.ladder(*v)
			}
			// Every row, not the newest: a job that ends while the next
			// is admitted inside one tick is already behind `View.Job`,
			// and comparing only that row lost its terminal state for
			// good.
			if rows, err := s.o.Engine.Jobs(name, by); err == nil {
				feed.jobs(rows, jobs)
			}
			if feed.failed {
				return
			}
		}
	}
}

// credentialLive re-checks the credential this stream was opened with.
//
// It peeks rather than resolves: a peek enforces the idle expiry and a
// revocation without *sliding* the session, because an open stream is
// not activity. A console someone left open would otherwise keep its own
// session alive for ever, which is the opposite of what §2.2's idle
// expiry is for; an active console slides its session with the requests
// its frames provoke.
//
// A door with no auth service — the local socket — has no credential to
// outlive, and a request carrying neither cookie nor bearer reached this
// handler only through such a door.
func (s *Server) credentialLive(r *http.Request) bool {
	if s.o.Auth == nil {
		return true
	}
	if h := r.Header.Get("Authorization"); auth.IsPodaroBearer(h) {
		_, err := s.o.Auth.TokenFromBearer(h)
		return err == nil
	}
	if c, err := r.Cookie(auth.CookieName); err == nil && c.Value != "" {
		_, err := s.o.Auth.Peek(c.Value)
		return err == nil
	}
	return true
}

// sseFeed writes SSE frames and remembers the last journal id it sent.
type sseFeed struct {
	w       http.ResponseWriter
	flusher http.Flusher
	failed  bool
	// jobState answers a job id with its state, so a `job` frame can
	// carry the `state` API §4 documents. The feed emitted the journal's
	// lifecycle `event` instead — `init`, `ready`, `verify` — and no
	// state at all, so a client following the advertised feed could not
	// tell a job it had started from one that had finished. The console
	// never noticed: it uses the frame only as a signal to re-read.
	jobState func(id string) string
}

// state is the job state for a frame's job, or "" when the frame names
// no job or the engine no longer holds it.
func (f *sseFeed) state(id string) string {
	if id == "" || f.jobState == nil {
		return ""
	}
	return f.jobState(id)
}

// named writes one event. An id is written only when the event is a
// journal fact; a snapshot passes "" and leaves the client's cursor
// where it was.
func (f *sseFeed) named(event string, payload any, id string) bool {
	if f.failed {
		return false
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return true // a frame that cannot be marshalled is dropped, never half-written
	}
	var s string
	if id != "" {
		s += "id: " + id + "\n"
	}
	s += "event: " + event + "\ndata: " + string(raw) + "\n\n"
	if _, err := fmt.Fprint(f.w, s); err != nil {
		f.failed = true
		return false
	}
	f.flusher.Flush()
	return true
}

func (f *sseFeed) comment(text string) bool {
	if f.failed {
		return false
	}
	if _, err := fmt.Fprintf(f.w, ": %s\n\n", text); err != nil {
		f.failed = true
		return false
	}
	f.flusher.Flush()
	return true
}

// entry maps one journal entry to its named event (API §4). The payloads
// carry what the entry carries; nothing is fetched or inferred beside
// it, and a value never appears — the journal holds none (invariant 6).
func (f *sseFeed) entry(e evidence.Entry) {
	switch {
	case e.Checkpoint != nil:
		c := e.Checkpoint
		f.named("checkpoint", map[string]any{
			"id": c.ID, "class": c.Class, "status": c.Status, "duration": c.Duration,
		}, e.ID)
	case e.Audit != nil:
		a := e.Audit
		frame := map[string]any{
			"action": a.Action, "detail": a.Detail, "actor": a.Actor,
		}
		if a.Action == "reveal" {
			// API §4 documents a reveal's frame as carrying `secret`, and
			// the feed carried the credential's name under `detail`
			// alone: a client written against the documented payload
			// found the field missing and had to read a generic one as
			// meaning the secret for this one action.
			// It is the *name*, which is what
			// `engine.Reveal` records in the audit row's detail and what
			// the credentials list and the journal already show; the
			// audit stream holds no values at all (invariant 6). `detail`
			// stays, because every other action's audit carries one.
			frame["secret"] = a.Detail
		}
		f.named("audit", frame, e.ID)
	case e.Lifecycle != nil:
		l := e.Lifecycle
		f.named("job", map[string]any{
			"id": e.Job, "state": f.state(e.Job), "stage": l.Stage,
			"event": l.Event, "code": l.Code, "detail": l.Detail,
		}, e.ID)
	case e.Seed != nil:
		f.named("job", map[string]any{
			"id": e.Job, "state": f.state(e.Job), "stage": "",
			"event": "seed", "seed": e.Seed.Name, "detail": e.Seed.Message,
		}, e.ID)
	}
}

// ladder sends the snapshot and returns the frame it sent, so the caller
// can tell a real change from a re-read.
func (f *sseFeed) ladder(v engine.InstanceView) string {
	frame := ladderFrame(v)
	for _, svc := range v.Services {
		f.named("ladder", map[string]any{
			"service": svc.Name, "stage": svc.Stage, "word": svc.Word,
			"context": svc.Context, "took": svc.Took,
		}, "")
	}
	f.named("ladder", map[string]any{
		"instance": v.Name, "stage": v.Ladder.Stage, "condensed": v.Ladder.Condensed,
		"label": v.Ladder.Label, "in_progress": v.Ladder.InProgress,
		"baseline": v.Checkpoints.Baseline, "objective": v.Checkpoints.Objective,
	}, "")
	return frame
}

// drain follows an instance's job rows after the instance itself is
// gone, so a destroy reaches the client as `succeeded` or `failed`
// rather than as a stream that stopped. Job rows outlive their instance
// in both stores — DeleteInstance clears services, results, progress and
// generated secrets, never jobs — which is what makes this readable at
// all.
//
// It is bounded. A row that never settles is a job the engine is still
// driving, or one whose terminal write the store keeps refusing, and a
// stream held open for either would never end; the budget is spent and
// the feed says `end` regardless, which is the honest report.
func (f *sseFeed) drain(ctx context.Context, eng *engine.Engine, name string, sent map[string]string, by engine.Actor) {
	deadline := time.Now().Add(drainBudget)
	for {
		rows, err := eng.Jobs(name, by)
		if err != nil {
			return
		}
		f.jobs(rows, sent)
		if f.failed || !anyActive(rows) || !time.Now().Before(deadline) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(eventTick):
		}
	}
}

// anyActive reports whether any of these rows still holds its instance's
// exclusive slot.
func anyActive(rows []state.Job) bool {
	for i := range rows {
		if rows[i].Active() {
			return true
		}
	}
	return false
}

// jobs sends a frame for every row whose state or stage has moved since
// this feed last spoke about it, and records where it now stands. A
// cursor that has heard of no row sends them all, which is the connect
// snapshot.
//
// The journal is not the only place a job's story is written, and it is
// not where the story ends: `Engine.run` records `succeeded` and
// `failed` in the state event log and then updates the job row, and
// neither is evidence. So a job that ends without journalling produced
// no `job` frame at all, and one whose last journal entry was read
// before its row settled produced `running` and nothing after it —
// while API §4 promises a client can follow a job it started to
// `succeeded` or `failed` without polling.
// Like `ladder` these are *snapshots*: they carry no id and never
// advance the client's `Last-Event-ID`, or a reconnect would resume
// after a frame the journal does not hold.
//
// Oldest first, because that is the order the transitions happened in: a
// job that finished before the next was admitted must reach the client
// before the one that replaced it.
//
// What a client is told is where each job *stands*, not every transition
// it passed through: the feed observes by re-reading, so a row that goes
// queued → running → succeeded between two reads produces one frame. The
// terminal state is the one a client is waiting for, and it is never the
// one that is coalesced away.
func (f *sseFeed) jobs(rows []state.Job, sent map[string]string) {
	for i := len(rows) - 1; i >= 0; i-- {
		frame := jobFrame(&rows[i])
		if sent[rows[i].ID] == frame {
			continue
		}
		f.named("job", jobSnapshot(&rows[i]), "")
		sent[rows[i].ID] = frame
	}
}

// jobSnapshot is the frame a job row produces: the `id`, `state` and
// `stage` API §4 documents, and — in the place the journal's own word
// occupies on the frames evidence produces — `state`, which says this
// one is the row rather than a journalled step. A failed job's envelope
// supplies the code and detail; it has already passed the instance's
// redaction filter (engine.redactErrFor), so no value appears here
// (invariant 6).
func jobSnapshot(j *state.Job) map[string]any {
	frame := map[string]any{
		"id": j.ID, "state": string(j.State), "stage": j.Stage,
		"event": "state", "code": "", "detail": "",
	}
	if j.Error != nil {
		frame["code"], frame["detail"] = j.Error.Code, j.Error.Message
	}
	return frame
}

// jobFrame is the comparable shape of a job row: two reads that produce
// the same frame produce no traffic. No job is the empty frame, which is
// what a feed that has sent none stands at.
func jobFrame(j *state.Job) string {
	if j == nil {
		return ""
	}
	raw, err := json.Marshal(jobSnapshot(j))
	if err != nil {
		// An unmarshallable row is never equal to the last frame, so the
		// snapshot is re-sent rather than silently suppressed.
		return fmt.Sprintf("unmarshallable-%d", time.Now().UnixNano())
	}
	return string(raw)
}

// ladderFrame is the comparable shape of everything a ladder event says:
// two reads that produce the same frame produce no traffic.
func ladderFrame(v engine.InstanceView) string {
	raw, err := json.Marshal(struct {
		L engine.LadderView
		S []engine.ServiceView
		T engine.Tally
	}{v.Ladder, v.Services, v.Checkpoints})
	if err != nil {
		// An unmarshallable view is never equal to the last frame, so the
		// snapshot is re-sent rather than silently suppressed.
		return fmt.Sprintf("unmarshallable-%d", time.Now().UnixNano())
	}
	return string(raw)
}

// evCursor is where a feed stands in the two sequences the engine's
// evidence list is made of.
//
// One position is not enough.
// `engine.mergeEvidence` interleaves two independently ordered
// sequences — the journal's append order, which survives a clock that
// moved back, and the audit stream's `au_<seq>` — and decides which
// comes first by time. So an entry appended *now* can land before the
// entry a feed last sent: an audit row written after a clock correction
// sorts ahead of a journal entry, and everything "after the cursor" in
// the merged list misses it, on this connection and on every reconnect.
//
// The feed therefore tracks each sequence separately, which is what a
// position in an interleaving of two orders actually is: the last
// journal id it sent, and the last audit sequence number. Neither
// sequence is re-derived or re-sorted here — the journal's order is the
// list's own order among journal entries, and the audit's is a number
// the store assigns — so the feed cannot disagree with the engine about
// either.
type evCursor struct {
	// journal is the id of the last journal entry sent; empty means none
	// has been sent yet, and every journal entry in the list is new.
	journal string
	// audit is the sequence of the last audit-store row (`au_<n>`) sent;
	// zero means none, and the store's sequences start at one. An audit
	// that also reached the journal is a journal entry here, not one of
	// these — see auditRow.
	audit int64
}

// indexOf locates an id in an evidence list. An empty id, or one the
// list does not hold, is not found — the caller decides what that means
// rather than being handed a position that was guessed.
func indexOf(entries []evidence.Entry, id string) (int, bool) {
	if id == "" {
		return 0, false
	}
	for i, e := range entries {
		if e.ID == id {
			return i, true
		}
	}
	return 0, false
}

// cursorAt is the position that has seen everything up to and including
// entries[:n] — the tail when n is len(entries), which is where a fresh
// feed stands.
func cursorAt(entries []evidence.Entry, n int) evCursor {
	var c evCursor
	for _, e := range entries[:n] {
		c = c.seen(e)
	}
	return c
}

// auditRow reports whether an entry belongs to the audit *store's*
// sequence — the only thing the audit cursor tracks. Its id says so and
// its payload does not.
//
// A reveal is recorded twice on purpose: `Engine.Reveal` appends it to
// the audit store, which numbers it, and appends the same record to the
// instance journal, which numbers nothing (API §2.5 — security events
// land in the evidence stream). `Engine.Evidence` deduplicates the pair
// by value and keeps the journal's copy, so what a client is handed is
// an `ev_…` entry carrying an audit payload whose `Seq` is zero.
//
// Deciding by payload therefore compared that entry against the audit
// sequence, where zero is never past anything: a reveal that happened
// while a client was watching produced no frame at all, and a client
// resuming from one placed the audit sequence at zero and replayed the
// whole journal. The namespace is what
// says where an entry came from: `au_<n>` is the store's numbering,
// everything else is the journal's order.
func auditRow(e evidence.Entry) bool {
	return e.Audit != nil && strings.HasPrefix(e.ID, "au_")
}

// seen advances the cursor past one entry.
func (c evCursor) seen(e evidence.Entry) evCursor {
	if auditRow(e) {
		if e.Audit.Seq > c.audit {
			c.audit = e.Audit.Seq
		}
		return c
	}
	c.journal = e.ID
	return c
}

// send emits every entry the cursor has not seen, in the order the
// engine put them, and returns the new position.
//
// "Not seen" is decided per sequence, and which sequence an entry is in
// is its id namespace (auditRow), never its payload: an `au_<n>` row
// whose sequence is past the cursor's, and any other entry that comes
// after the cursor's journal id in this list — the journal's own order,
// which the merge preserves. Walking the list in order keeps the frames
// in the engine's order even when an entry that is new sits before one
// already sent.
func (f *sseFeed) send(entries []evidence.Entry, cursor evCursor) evCursor {
	// A cursor whose journal id this list no longer holds cannot be
	// placed. Evidence is immutable, so that means a feed older than the
	// instance's current journal (a destroy and re-create under the same
	// name): stand at the tail rather than replay a stranger's history.
	passed := cursor.journal == ""
	if !passed {
		if _, found := indexOf(entries, cursor.journal); !found {
			return cursorAt(entries, len(entries))
		}
	}
	for _, e := range entries {
		if auditRow(e) {
			if e.Audit.Seq > cursor.audit {
				f.entry(e)
				cursor = cursor.seen(e)
			}
			continue
		}
		if !passed {
			if e.ID == cursor.journal {
				passed = true
			}
			continue
		}
		f.entry(e)
		cursor = cursor.seen(e)
	}
	return cursor
}
