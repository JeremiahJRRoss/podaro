// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// RunStoreTests is the conformance suite every Store passes: the memory
// store and the SQLite store are interchangeable to the engine only
// because they both pass this.
// genOf is the generation a caller reads before issuing a credential:
// the instance's own AuditFrom. The cases below read it the way
// `auth.IssueAccess` does rather than passing a literal, so a store that
// stopped reporting it would fail here instead of passing by luck.
func genOf(t *testing.T, s Store, name string) int64 {
	t.Helper()
	inst, err := s.GetInstance(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return inst.AuditFrom
}

func RunStoreTests(t *testing.T, open func(t *testing.T) Store) {
	t.Helper()
	t.Run("instances", func(t *testing.T) {
		s := open(t)
		defer s.Close()
		if _, err := s.GetInstance("x"); err != ErrNotFound {
			t.Fatalf("missing instance: %v", err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		in := Instance{Name: "pii-lab", Template: "conformance-lab", Version: "1.0.0", Profile: "standard", Mode: ModeDelivery, Source: "/snap", Created: now, Updated: now, Stage: StageAlive, Reached: StageReady, Licenses: []string{"example-terms"}, SeedSalt: "9f2c66d1a4e07b53"}
		if err := s.PutInstance(in); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetInstance("pii-lab")
		if err != nil || !reflect.DeepEqual(*got, in) {
			t.Fatalf("round trip: %+v %v", got, err)
		}
		in.Stage = StageHealthy
		if err := s.PutInstance(in); err != nil {
			t.Fatal(err)
		}
		list, _ := s.ListInstances()
		if len(list) != 1 || list[0].Stage != StageHealthy {
			t.Fatalf("list after update: %+v", list)
		}
		// The stage and the high-water mark are two columns, not one: a
		// stage written low must leave the mark where it was, or the
		// ladder could never say it had fallen (plan S14, UX §5).
		if list[0].Reached != StageReady {
			t.Fatalf("the mark outlives a lowered stage: %+v", list[0])
		}
		// RanImage is carried beside Image on purpose: one is the plan's
		// and one is the run's, and a store that kept only the first
		// would let evidence answer with an image that never ran.
		if err := s.PutService(Service{Instance: "pii-lab", Name: "web", Module: "m-2", RanModule: "m-1", Image: "img@sha256:x", RanImage: "img@sha256:w", Container: "pdr-pii-lab-web", Stage: StageAlive, Ports: map[int]int{80: 43127}, Readiness: "r1", UIPort: 80, UIScheme: "http", Embed: "iframe"}); err != nil {
			t.Fatal(err)
		}
		svcs, _ := s.ListServices("pii-lab")
		if len(svcs) != 1 || svcs[0].Ports[80] != 43127 || svcs[0].Readiness != "r1" || svcs[0].UIPort != 80 || svcs[0].UIScheme != "http" || svcs[0].Embed != "iframe" {
			t.Fatalf("services: %+v", svcs)
		}
		if svcs[0].Image != "img@sha256:x" || svcs[0].RanImage != "img@sha256:w" {
			t.Fatalf("the plan's image and the run's must both survive a round trip: %+v", svcs[0])
		}
		if svcs[0].Module != "m-2" || svcs[0].RanModule != "m-1" {
			t.Fatalf("the plan's module and the run's must both survive a round trip: %+v", svcs[0])
		}
		_ = s.PutService(Service{Instance: "pii-lab", Name: "old", Image: "img@sha256:y", Container: "pdr-pii-lab-old"})
		if err := s.DeleteService("pii-lab", "old"); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteService("pii-lab", "never"); err != nil {
			t.Fatalf("deleting an absent service must be a no-op: %v", err)
		}
		if svcs, _ := s.ListServices("pii-lab"); len(svcs) != 1 || svcs[0].Name != "web" {
			t.Fatalf("services after delete: %+v", svcs)
		}
		if err := s.DeleteInstance("pii-lab"); err != nil {
			t.Fatal(err)
		}
		if svcs, _ := s.ListServices("pii-lab"); len(svcs) != 0 {
			t.Fatalf("services survive delete: %+v", svcs)
		}
		if _, err := s.GetInstance("pii-lab"); err != ErrNotFound {
			t.Fatalf("after delete: %v", err)
		}
	})
	t.Run("checkpoint results and progress", func(t *testing.T) {
		// The latest result per checkpoint and the learner's position per
		// playbook (plan S6): results replace by id, are listed by id, and
		// are forgotten by class (reset clears objectives); progress round
		// trips its steps; both go with the instance.
		s := open(t)
		defer s.Close()
		now := time.Now().UTC().Truncate(time.Second)
		in := Instance{Name: "lab", Template: "t", Mode: ModeAuthoring, Source: "/src", Created: now, Updated: now, Stage: StageReady, SeedSalt: "abcd"}
		if err := s.PutInstance(in); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.GetInstance("lab"); got.SeedSalt != "abcd" {
			t.Fatalf("seed salt must round-trip: %+v", got)
		}
		if list, err := s.ListCheckpointResults("lab"); err != nil || len(list) != 0 {
			t.Fatalf("no results yet: %+v %v", list, err)
		}
		// A row for an instance the store does not hold is refused: no
		// result and no progress ever precedes or outlives its instance.
		if err := s.PutCheckpointResult(CheckpointResult{Instance: "ghost", ID: "x", Class: "baseline", Status: "pass", At: now, Duration: "1ms"}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a result for an absent instance must be ErrNotFound: %v", err)
		}
		if err := s.PutProgress(Progress{Instance: "ghost", Playbook: "p", CurrentStep: "s", Updated: now}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("progress for an absent instance must be ErrNotFound: %v", err)
		}
		r1 := CheckpointResult{Instance: "lab", ID: "prometheus-ready", Class: "baseline", Adapter: "http", Status: "pass", At: now, Duration: "120ms", Job: "job_1", Evidence: "ev_1",
			Observed: json.RawMessage(`{"status":200}`), Expected: json.RawMessage(`{"status":200}`), Message: "GET /-/ready → 200", Definition: "def-0123456789abcdef"}
		r2 := CheckpointResult{Instance: "lab", ID: "dashboard-exists", Class: "objective", Adapter: "http", Status: "fail", At: now, Duration: "80ms", Hint: "Check the title", Observed: json.RawMessage(`null`)}
		r3 := CheckpointResult{Instance: "lab", ID: "broken", Class: "objective", Adapter: "exec", Status: "error", At: now, Duration: "2s",
			Error: &pdr.Error{Code: "PDR-E502", Message: "exec container exited non-zero", Cause: "exit 2"}}
		for _, r := range []CheckpointResult{r1, r2, r3} {
			if err := s.PutCheckpointResult(r); err != nil {
				t.Fatal(err)
			}
		}
		list, err := s.ListCheckpointResults("lab")
		if err != nil || len(list) != 3 || list[0].ID != "broken" || list[1].ID != "dashboard-exists" || list[2].ID != "prometheus-ready" {
			t.Fatalf("results by id: %+v %v", list, err)
		}
		if got := list[2]; got.Status != "pass" || string(got.Observed) != `{"status":200}` || string(got.Expected) != `{"status":200}` || got.Job != "job_1" || got.Evidence != "ev_1" || got.Message != "GET /-/ready → 200" || !got.At.Equal(now) || got.Definition != "def-0123456789abcdef" {
			t.Fatalf("result round trip: %+v", got)
		}
		if got := list[0]; got.Error == nil || got.Error.Code != "PDR-E502" || got.Error.Cause != "exit 2" || got.Observed != nil {
			t.Fatalf("an error result carries its envelope: %+v", got)
		}
		if got := list[1]; got.Hint != "Check the title" || got.Error != nil {
			t.Fatalf("a fail result carries its hint: %+v", got)
		}
		r2.Status, r2.Duration = "pass", "90ms"
		if err := s.PutCheckpointResult(r2); err != nil {
			t.Fatal(err)
		}
		if list, _ := s.ListCheckpointResults("lab"); len(list) != 3 || list[1].Status != "pass" || list[1].Duration != "90ms" {
			t.Fatalf("a result replaces the previous one: %+v", list)
		}
		if err := s.DeleteCheckpointResults("lab", "objective"); err != nil {
			t.Fatal(err)
		}
		if list, _ := s.ListCheckpointResults("lab"); len(list) != 1 || list[0].ID != "prometheus-ready" {
			t.Fatalf("deleting a class keeps the other: %+v", list)
		}
		if err := s.DeleteCheckpointResults("lab", ""); err != nil {
			t.Fatal(err)
		}
		if list, _ := s.ListCheckpointResults("lab"); len(list) != 0 {
			t.Fatalf("deleting every class: %+v", list)
		}

		if _, err := s.GetProgress("lab", "first-dashboard"); err != ErrNotFound {
			t.Fatalf("no progress yet: %v", err)
		}
		p := Progress{Instance: "lab", Playbook: "first-dashboard", CurrentStep: "build-a-dashboard", Updated: now,
			Steps: map[string]StepProgress{"meet-the-stack": {Status: "skipped", At: now}, "drive-real-traffic": {Status: "pass", At: now.Add(time.Second)}}}
		if err := s.PutProgress(p); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetProgress("lab", "first-dashboard")
		if err != nil || got.CurrentStep != "build-a-dashboard" || len(got.Steps) != 2 || got.Steps["drive-real-traffic"].Status != "pass" || !got.Steps["drive-real-traffic"].At.Equal(now.Add(time.Second)) || !got.Updated.Equal(now) {
			t.Fatalf("progress round trip: %+v %v", got, err)
		}
		p.CurrentStep = "leave-with-receipts"
		if err := s.PutProgress(p); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.GetProgress("lab", "first-dashboard"); got.CurrentStep != "leave-with-receipts" {
			t.Fatalf("progress replaces: %+v", got)
		}
		if err := s.PutProgress(Progress{Instance: "lab", Playbook: "other", Updated: now}); err != nil {
			t.Fatal(err)
		}
		if got, err := s.GetProgress("lab", "other"); err != nil || got.Steps == nil || len(got.Steps) != 0 {
			t.Fatalf("empty steps are an empty map, never nil: %+v %v", got, err)
		}
		if err := s.DeleteProgress("lab"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetProgress("lab", "first-dashboard"); err != ErrNotFound {
			t.Fatalf("progress cleared: %v", err)
		}
		_ = s.PutCheckpointResult(r1)
		_ = s.PutProgress(p)
		if err := s.DeleteInstance("lab"); err != nil {
			t.Fatal(err)
		}
		if list, _ := s.ListCheckpointResults("lab"); len(list) != 0 {
			t.Fatalf("results go with the instance: %+v", list)
		}
		if _, err := s.GetProgress("lab", "first-dashboard"); err != ErrNotFound {
			t.Fatalf("progress goes with the instance: %v", err)
		}
	})
	t.Run("generated secrets", func(t *testing.T) {
		s := open(t)
		defer s.Close()
		now := time.Now().UTC().Truncate(time.Second)
		if err := s.PutInstance(Instance{Name: "gen", Template: "t", Mode: ModeAuthoring, Source: "/w", Created: now, Updated: now}); err != nil {
			t.Fatal(err)
		}
		if got, err := s.GeneratedSecrets("gen"); err != nil || len(got) != 0 {
			t.Fatalf("nothing generated yet: %v %v", got, err)
		}
		if err := s.AddGeneratedSecrets("gen", []string{"tok"}); err != nil {
			t.Fatal(err)
		}
		if err := s.AddGeneratedSecrets("gen", []string{"pw", "tok"}); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.GeneratedSecrets("gen"); !reflect.DeepEqual(got, []string{"pw", "tok"}) {
			t.Fatalf("the history is an append-only union, sorted: %v", got)
		}
		if err := s.AddGeneratedSecrets("nope", []string{"x"}); err != ErrNotFound {
			t.Fatalf("an unknown instance has no history to add to: %v", err)
		}
		if got, err := s.GeneratedSecrets("nope"); err != nil || len(got) != 0 {
			t.Fatalf("an unknown instance generated nothing: %v %v", got, err)
		}
		if err := s.DeleteInstance("gen"); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.GeneratedSecrets("gen"); len(got) != 0 {
			t.Fatalf("deleting the instance takes the history with it: %v", got)
		}
	})
	t.Run("gateway backfill mark", func(t *testing.T) {
		// Which instances owe the gateway facts is recorded, never read
		// off the service rows (engine round 27): a store fresh from this
		// release owes nothing, the mark survives a write of the instance
		// it is on, and it goes with the instance.
		s := open(t)
		defer s.Close()
		if _, err := s.GatewayBackfill("gone"); err != ErrNotFound {
			t.Fatalf("an instance that does not exist: %v", err)
		}
		if err := s.SetGatewayBackfill("gone", true); err != ErrNotFound {
			t.Fatalf("marking an instance that does not exist: %v", err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		in := Instance{Name: "lab", Template: "t", Mode: ModeAuthoring, Source: "/src", Created: now, Updated: now, Stage: StageAlive}
		if err := s.PutInstance(in); err != nil {
			t.Fatal(err)
		}
		if pending, err := s.GatewayBackfill("lab"); err != nil || pending {
			t.Fatalf("an instance created under this release owes nothing: %v %v", pending, err)
		}
		if err := s.SetGatewayBackfill("lab", true); err != nil {
			t.Fatal(err)
		}
		in.Stage = StageHealthy
		if err := s.PutInstance(in); err != nil {
			t.Fatal(err)
		}
		if pending, err := s.GatewayBackfill("lab"); err != nil || !pending {
			t.Fatalf("the mark must survive a write of its instance: %v %v", pending, err)
		}
		if err := s.SetGatewayBackfill("lab", false); err != nil {
			t.Fatal(err)
		}
		if pending, err := s.GatewayBackfill("lab"); err != nil || pending {
			t.Fatalf("a cleared mark stays cleared: %v %v", pending, err)
		}
		if err := s.DeleteInstance("lab"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GatewayBackfill("lab"); err != ErrNotFound {
			t.Fatalf("the mark goes with the instance: %v", err)
		}
	})
	t.Run("unsupported mark", func(t *testing.T) {
		// Migration 16 (the reconciliation plan's R3): why this release does
		// not operate an instance. Like the backfill mark it is a record of
		// what the engine found, kept apart from the instance's columns: a
		// fresh instance carries none, a write of the instance never clears
		// one, and it goes with the instance.
		s := open(t)
		defer s.Close()
		if _, err := s.Unsupported("gone"); err != ErrNotFound {
			t.Fatalf("an instance that does not exist: %v", err)
		}
		if err := s.MarkUnsupported("gone", "retired template"); err != ErrNotFound {
			t.Fatalf("marking an instance that does not exist: %v", err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		in := Instance{Name: "old", Template: "t", Mode: ModeDelivery, Source: "/src", Created: now, Updated: now, Stage: StageReady, Reached: StageReady}
		if err := s.PutInstance(in); err != nil {
			t.Fatal(err)
		}
		if reason, err := s.Unsupported("old"); err != nil || reason != "" {
			t.Fatalf("an instance carries no mark until one is recorded: %q %v", reason, err)
		}
		if err := s.MarkUnsupported("old", "retired template"); err != nil {
			t.Fatal(err)
		}
		in.Updated = now.Add(time.Minute)
		if err := s.PutInstance(in); err != nil {
			t.Fatal(err)
		}
		if reason, err := s.Unsupported("old"); err != nil || reason != "retired template" {
			t.Fatalf("the mark must survive a write of its instance: %q %v", reason, err)
		}
		if got, err := s.GetInstance("old"); err != nil || got.Stage != StageReady || got.Template != "t" {
			t.Fatalf("the mark changes nothing else about the instance: %+v %v", got, err)
		}
		if err := s.DeleteInstance("old"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Unsupported("old"); err != ErrNotFound {
			t.Fatalf("the mark goes with the instance: %v", err)
		}
		if err := s.PutInstance(in); err != nil {
			t.Fatal(err)
		}
		if reason, err := s.Unsupported("old"); err != nil || reason != "" {
			t.Fatalf("a name used again starts without the old generation's mark: %q %v", reason, err)
		}
	})
	t.Run("jobs", func(t *testing.T) {
		s := open(t)
		defer s.Close()
		start := time.Now().UTC().Truncate(time.Second)
		j1 := Job{ID: "job_1", Kind: "create", Instance: "a", State: JobRunning, Stage: "pulling", Started: start}
		if err := s.PutJob(j1); err != nil {
			t.Fatal(err)
		}
		if active, _ := s.ActiveJob("a"); active == nil || active.ID != "job_1" {
			t.Fatalf("active job: %+v", active)
		}
		if active, _ := s.ActiveJob("b"); active != nil {
			t.Fatalf("no job expected for b: %+v", active)
		}
		fin := start.Add(time.Second)
		j1.State, j1.Finished = JobSucceeded, &fin
		if err := s.PutJob(j1); err != nil {
			t.Fatal(err)
		}
		if active, _ := s.ActiveJob("a"); active != nil {
			t.Fatalf("finished job still active: %+v", active)
		}
		j2 := Job{ID: "job_2", Kind: "seed", Instance: "a", State: JobQueued, Started: start.Add(2 * time.Second), Target: "query-load"}
		_ = s.PutJob(j2)
		jobs, _ := s.ListJobs("a")
		if len(jobs) != 2 || jobs[0].ID != "job_2" || jobs[0].Target != "query-load" {
			t.Fatalf("newest first, target kept: %+v", jobs)
		}
		fin3 := start.Add(3 * time.Second)
		j3 := Job{ID: "job_3", Kind: "create", Instance: "c", State: JobFailed, Stage: "failed", Started: start, Finished: &fin3,
			Error: &pdr.Error{Code: "PDR-E205", Message: "web did not become healthy within 2m", Cause: "probe never returned 200", Next: "podaro up again to resume"}}
		if err := s.PutJob(j3); err != nil {
			t.Fatal(err)
		}
		if got, err := s.GetJob("job_3"); err != nil || !reflect.DeepEqual(got.Error, j3.Error) {
			t.Fatalf("a failed job's error envelope must round-trip as an object: %+v %v", got, err)
		}
		got, err := s.GetJob("job_1")
		if err != nil || got.Finished == nil || !got.Finished.Equal(fin) {
			t.Fatalf("job round trip: %+v %v", got, err)
		}
		for i, step := range []string{"network", "pull", "create"} {
			if err := s.AppendEvent(Event{Job: "job_1", At: start.Add(time.Duration(i) * time.Second), Step: step, Service: "web", Status: "ok"}); err != nil {
				t.Fatal(err)
			}
		}
		events, _ := s.ListEvents("job_1")
		if len(events) != 3 || events[0].Step != "network" || events[2].Step != "create" || events[0].Seq >= events[1].Seq {
			t.Fatalf("events: %+v", events)
		}
	})
	t.Run("sessions-tokens-audit", func(t *testing.T) {
		s := open(t)
		defer s.Close()
		now := time.Now().UTC().Truncate(time.Second)
		if _, err := s.GetSession("nope"); err != ErrNotFound {
			t.Fatalf("missing session: %v", err)
		}
		sess := Session{ID: "s1", Subject: "jross", Mechanism: "session", CSRF: "c1", Created: now, LastSeen: now, Expires: now.Add(12 * time.Hour)}
		if err := s.PutSession(sess); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetSession("s1")
		if err != nil || *got != sess {
			t.Fatalf("session round trip: %+v %v", got, err)
		}
		sess.LastSeen = now.Add(time.Minute)
		_ = s.PutSession(sess)
		if got, _ := s.GetSession("s1"); !got.LastSeen.Equal(sess.LastSeen) {
			t.Fatalf("session update: %+v", got)
		}
		if err := s.TouchSession("s1", now.Add(2*time.Minute), now.Add(13*time.Hour)); err != nil {
			t.Fatalf("touch session: %v", err)
		}
		if got, _ := s.GetSession("s1"); !got.LastSeen.Equal(now.Add(2*time.Minute)) || !got.Expires.Equal(now.Add(13*time.Hour)) || got.CSRF != "c1" || got.Subject != "jross" {
			t.Fatalf("a touch moves last-seen and expiry, nothing else: %+v", got)
		}
		if err := s.TouchSession("absent", now, now.Add(time.Hour)); err != ErrNotFound {
			t.Fatalf("touching an absent session: %v", err)
		}
		if _, err := s.GetSession("absent"); err != ErrNotFound {
			t.Fatalf("a touch must never create a session: %v", err)
		}
		_ = s.PutSession(Session{ID: "s2", Subject: "alice", Mechanism: "instance-access", Instance: "pii-lab", CSRF: "c2", Created: now, LastSeen: now, Expires: now.Add(-time.Second)})
		if n, _ := s.PurgeSessions(now); n != 1 {
			t.Fatalf("purge: %d", n)
		}
		if _, err := s.GetSession("s2"); err != ErrNotFound {
			t.Fatalf("purged session survives: %v", err)
		}
		if err := s.DeleteSession("s1"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetSession("s1"); err != ErrNotFound {
			t.Fatalf("deleted session survives: %v", err)
		}
		if err := s.TouchSession("s1", now, now.Add(time.Hour)); err != ErrNotFound {
			t.Fatalf("touching a deleted session: %v", err)
		}
		if _, err := s.GetSession("s1"); err != ErrNotFound {
			t.Fatalf("a touch resurrected a deleted session: %v", err)
		}
		// A sign-out and its record are one write; a session already gone
		// still gets its record.
		_ = s.PutSession(Session{ID: "s3", Subject: "alice", Mechanism: "session", CSRF: "c3", Created: now, LastSeen: now, Expires: now.Add(time.Hour)})
		beforeOut, _ := s.ListAudit("")
		if err := s.DeleteSessionAudited("s3", Audit{At: now, Action: "logout", Actor: "alice", Mechanism: "session", Detail: "audited"}); err != nil {
			t.Fatalf("sign-out with its record: %v", err)
		}
		if _, err := s.GetSession("s3"); err != ErrNotFound {
			t.Fatalf("the signed-out session must be gone: %v", err)
		}
		if after, _ := s.ListAudit(""); len(after) != len(beforeOut)+1 || after[len(after)-1].Action != "logout" || after[len(after)-1].Detail != "audited" {
			t.Fatalf("its record must land with it: %+v", after)
		}
		if err := s.DeleteSessionAudited("s3", Audit{At: now, Action: "logout", Actor: "alice", Mechanism: "session", Detail: "again"}); err != nil {
			t.Fatalf("signing out a session already gone is recorded: %v", err)
		}
		if after, _ := s.ListAudit(""); len(after) != len(beforeOut)+2 {
			t.Fatalf("the second sign-out must be recorded too: %+v", after)
		}

		tok := Token{ID: "tok_1", Name: "ci", Prefix: "abcd1234", Hash: "h1", Scope: "read", Created: now}
		if err := s.PutToken(tok); err != nil {
			t.Fatal(err)
		}
		if err := s.PutToken(Token{ID: "tok_2", Name: "ci", Prefix: "x", Hash: "h2", Scope: "read", Created: now}); err != ErrConflict {
			t.Fatalf("duplicate name: %v", err)
		}
		if err := s.PutToken(Token{ID: "tok_2", Name: "other", Prefix: "x", Hash: "h1", Scope: "read", Created: now}); err != ErrConflict {
			t.Fatalf("duplicate hash: %v", err)
		}
		_ = s.PutToken(Token{ID: "tok_2", Name: "admin", Prefix: "efgh5678", Hash: "h2", Scope: "admin", Created: now.Add(time.Second)})
		got2, err := s.GetTokenByHash("h1")
		if err != nil || *got2 != tok {
			t.Fatalf("token by hash: %+v %v", got2, err)
		}
		if _, err := s.GetTokenByHash("nope"); err != ErrNotFound {
			t.Fatalf("missing token: %v", err)
		}
		if err := s.TouchToken("tok_1", now.Add(time.Second)); err != nil {
			t.Fatalf("touch token: %v", err)
		}
		if got, _ := s.GetTokenByHash("h1"); got.LastUsed == nil || !got.LastUsed.Equal(now.Add(time.Second)) || got.Name != "ci" || got.Scope != "read" {
			t.Fatalf("a touch records last use, nothing else: %+v", got)
		}
		if err := s.TouchToken("tok_9", now); err != ErrNotFound {
			t.Fatalf("touching an absent token: %v", err)
		}
		used := now.Add(2 * time.Second)
		tok.LastUsed = &used
		if err := s.PutToken(tok); err != nil {
			t.Fatalf("token update: %v", err)
		}
		list, _ := s.ListTokens()
		if len(list) != 2 || list[0].ID != "tok_1" || list[1].ID != "tok_2" || list[0].LastUsed == nil || !list[0].LastUsed.Equal(used) {
			t.Fatalf("tokens oldest first with last_used: %+v", list)
		}
		// A token and its record are one write: both land, or — for a
		// taken name or hash — neither does.
		before, _ := s.ListAudit("")
		if err := s.PutTokenAudited(Token{ID: "tok_3", Name: "audited", Prefix: "ijkl9012", Hash: "h3", Scope: "read", Created: now}, Audit{At: now, Action: "token-created", Actor: "jross", Mechanism: "session", Detail: "audited · read"}); err != nil {
			t.Fatalf("token with its record: %v", err)
		}
		if got, err := s.GetTokenByHash("h3"); err != nil || got.Name != "audited" {
			t.Fatalf("the audited token: %+v %v", got, err)
		}
		if after, _ := s.ListAudit(""); len(after) != len(before)+1 || after[len(after)-1].Action != "token-created" || after[len(after)-1].Detail != "audited · read" {
			t.Fatalf("its record must land with it: %+v", after)
		}
		if err := s.PutTokenAudited(Token{ID: "tok_4", Name: "audited", Prefix: "x", Hash: "h4", Scope: "read", Created: now}, Audit{At: now, Action: "token-created", Actor: "jross", Mechanism: "session", Detail: "clash"}); err != ErrConflict {
			t.Fatalf("a taken name is ErrConflict: %v", err)
		}
		if after, _ := s.ListAudit(""); len(after) != len(before)+1 {
			t.Fatalf("a refused token leaves no record: %+v", after)
		}
		if _, err := s.GetTokenByHash("h4"); err != ErrNotFound {
			t.Fatalf("a refused token does not exist: %v", err)
		}
		// A revocation and its record are one write: both land, or — for
		// a token that is not there — neither does.
		before, _ = s.ListAudit("")
		if err := s.DeleteTokenAudited("tok_3", Audit{At: now, Action: "token-revoked", Actor: "jross", Mechanism: "session", Detail: "audited"}); err != nil {
			t.Fatalf("revocation with its record: %v", err)
		}
		if _, err := s.GetTokenByHash("h3"); err != ErrNotFound {
			t.Fatalf("the revoked token must be gone: %v", err)
		}
		if after, _ := s.ListAudit(""); len(after) != len(before)+1 || after[len(after)-1].Action != "token-revoked" || after[len(after)-1].Detail != "audited" {
			t.Fatalf("its record must land with it: %+v", after)
		}
		if err := s.DeleteTokenAudited("tok_3", Audit{At: now, Action: "token-revoked", Actor: "jross", Mechanism: "session", Detail: "again"}); err != ErrNotFound {
			t.Fatalf("revoking a token that is not there is ErrNotFound: %v", err)
		}
		if after, _ := s.ListAudit(""); len(after) != len(before)+1 {
			t.Fatalf("a refused revocation leaves no record: %+v", after)
		}
		if err := s.DeleteToken("tok_1"); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteToken("tok_1"); err != ErrNotFound {
			t.Fatalf("double delete: %v", err)
		}
		if err := s.TouchToken("tok_1", now); err != ErrNotFound {
			t.Fatalf("touching a deleted token: %v", err)
		}
		if _, err := s.GetTokenByHash("h1"); err != ErrNotFound {
			t.Fatalf("a touch resurrected a revoked token: %v", err)
		}
		if list, _ := s.ListTokens(); len(list) != 1 {
			t.Fatalf("after delete: %+v", list)
		}

		for i, action := range []string{"operator-created", "login", "lockout"} {
			if err := s.AppendAudit(Audit{At: now.Add(time.Duration(i) * time.Second), Action: action, Actor: "jross", Mechanism: "session"}); err != nil {
				t.Fatal(err)
			}
		}
		_ = s.AppendAudit(Audit{At: now, Instance: "pii-lab", Action: "reveal", Actor: "alice", Mechanism: "session", Detail: "admin"})
		sys, _ := s.ListAudit("")
		if len(sys) != 7 || sys[0].Action != "logout" || sys[1].Action != "logout" || sys[2].Action != "token-created" || sys[3].Action != "token-revoked" || sys[4].Action != "operator-created" || sys[6].Action != "lockout" || sys[4].Seq >= sys[5].Seq {
			t.Fatalf("system audit: %+v", sys)
		}
		if inst, _ := s.ListAudit("pii-lab"); len(inst) != 1 || inst[0].Detail != "admin" {
			t.Fatalf("instance audit: %+v", inst)
		}

		if ls, err := s.GetLoginState("203.0.113.9"); err != nil || ls != nil {
			t.Fatalf("no login state expected: %+v %v", ls, err)
		}
		lock := now.Add(15 * time.Minute)
		if err := s.PutLoginState(LoginState{Source: "203.0.113.9", Failures: 5, LastFailure: now, LockedUntil: &lock}); err != nil {
			t.Fatal(err)
		}
		ls, _ := s.GetLoginState("203.0.113.9")
		if ls == nil || ls.Failures != 5 || !ls.LastFailure.Equal(now) || ls.LockedUntil == nil || !ls.LockedUntil.Equal(lock) {
			t.Fatalf("login state: %+v", ls)
		}
		_ = s.PutLoginState(LoginState{Source: "198.51.100.4", Failures: 1, LastFailure: now})
		if locked, _ := s.ListLockedSources(); len(locked) != 1 || locked[0].Source != "203.0.113.9" {
			t.Fatalf("locked sources: %+v", locked)
		}
		if err := s.PutLoginState(LoginState{Source: "203.0.113.9"}); err != nil {
			t.Fatal(err)
		}
		if ls, _ := s.GetLoginState("203.0.113.9"); ls.Failures != 0 || ls.LockedUntil != nil || !ls.LastFailure.IsZero() {
			t.Fatalf("cleared login state: %+v", ls)
		}
		// A throttle count and its records are one write: the state and
		// every record land together, in order.
		beforeLS, _ := s.ListAudit("")
		if err := s.PutLoginStateAudited(LoginState{Source: "198.51.100.4", Failures: 5, LastFailure: now, LockedUntil: &lock},
			Audit{At: now, Action: "login-failed", Actor: "jross", Mechanism: "session", Detail: "198.51.100.4 · failure 5"},
			Audit{At: now, Action: "lockout", Actor: "jross", Mechanism: "session", Detail: "198.51.100.4 · 5 failures"}); err != nil {
			t.Fatalf("login state with its records: %v", err)
		}
		if ls, _ := s.GetLoginState("198.51.100.4"); ls == nil || ls.Failures != 5 || ls.LockedUntil == nil || !ls.LockedUntil.Equal(lock) {
			t.Fatalf("the audited state must land: %+v", ls)
		}
		if after, _ := s.ListAudit(""); len(after) != len(beforeLS)+2 || after[len(after)-2].Action != "login-failed" || after[len(after)-1].Action != "lockout" {
			t.Fatalf("its records must land with it, in order: %+v", after)
		}
		// A session and its record are one write.
		beforeSess, _ := s.ListAudit("")
		if err := s.PutSessionAudited(Session{ID: "s-audited", Subject: "jross", Mechanism: "session", CSRF: "c9", Created: now, LastSeen: now, Expires: now.Add(time.Hour)},
			Audit{At: now, Action: "login", Actor: "jross", Mechanism: "session", Detail: "203.0.113.9"}); err != nil {
			t.Fatalf("session with its record: %v", err)
		}
		if got, err := s.GetSession("s-audited"); err != nil || got.Subject != "jross" {
			t.Fatalf("the audited session must land: %+v %v", got, err)
		}
		if after, _ := s.ListAudit(""); len(after) != len(beforeSess)+1 || after[len(after)-1].Action != "login" {
			t.Fatalf("its record must land with it: %+v", after)
		}
	})

	t.Run("instance access credentials", func(t *testing.T) {
		s := open(t)
		now := time.Now().UTC().Truncate(time.Second)
		if err := s.PutInstance(Instance{Name: "class", Template: "t", Mode: "delivery", Source: "/s", Created: now, Updated: now}); err != nil {
			t.Fatal(err)
		}
		acc := Access{ID: "ac-1", Instance: "class", Name: "alice", Prefix: "abcd", Hash: "h-alice", Created: now, Expires: now.Add(8 * time.Hour)}
		before, _ := s.ListAudit("class")
		if err := s.PutAccessAudited(acc, genOf(t, s, "class"), Audit{At: now, Instance: "class", Action: "access-issue", Actor: "operator", Mechanism: "socket", Detail: "alice"}); err != nil {
			t.Fatalf("access with its record: %v", err)
		}
		if after, _ := s.ListAudit("class"); len(after) != len(before)+1 || after[len(after)-1].Action != "access-issue" {
			t.Fatalf("the record lands with the credential: %+v", after)
		}
		// The hash is the lookup; a credential is never stored in the clear.
		got, err := s.GetAccessByHash("h-alice")
		if err != nil || got == nil || got.Name != "alice" || got.Instance != "class" || !got.Expires.Equal(acc.Expires) {
			t.Fatalf("by hash: %+v %v", got, err)
		}
		if _, err := s.GetAccessByHash("h-nobody"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("an unknown hash is not found, got %v", err)
		}
		// A second credential of the same hash is a conflict, and records nothing.
		beforeDup, _ := s.ListAudit("class")
		if err := s.PutAccessAudited(Access{ID: "ac-2", Instance: "class", Name: "bob", Prefix: "efgh", Hash: "h-alice", Created: now, Expires: now.Add(time.Hour)}, genOf(t, s, "class"),
			Audit{At: now, Instance: "class", Action: "access-issue", Actor: "operator", Detail: "bob"}); !errors.Is(err, ErrConflict) {
			t.Fatalf("a taken hash is a conflict, got %v", err)
		}
		if afterDup, _ := s.ListAudit("class"); len(afterDup) != len(beforeDup) {
			t.Fatalf("a refused credential records nothing: %+v", afterDup)
		}
		if err := s.PutAccessAudited(Access{ID: "ac-2", Instance: "class", Name: "bob", Prefix: "efgh", Hash: "h-bob", Created: now.Add(time.Second), Expires: now.Add(time.Hour)}, genOf(t, s, "class"),
			Audit{At: now, Instance: "class", Action: "access-issue", Actor: "operator", Detail: "bob"}); err != nil {
			t.Fatal(err)
		}
		list, err := s.ListAccess("class")
		if err != nil || len(list) != 2 || list[0].Name != "alice" || list[1].Name != "bob" {
			t.Fatalf("oldest first: %+v %v", list, err)
		}
		if other, _ := s.ListAccess("elsewhere"); len(other) != 0 {
			t.Fatalf("another instance's credentials: %+v", other)
		}
		// A use is recorded, and a credential that is gone is never
		// re-created — both now properties of the join, which is the
		// only thing that records a use: see "a join is one write".
		// Revocation is immediate and audited; a second one finds nothing.
		beforeRev, _ := s.ListAudit("class")
		if err := s.DeleteAccessAudited("class", "ac-1", Audit{At: now, Instance: "class", Action: "access-revoke", Actor: "operator", Detail: "alice"}); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if _, err := s.GetAccessByHash("h-alice"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a revoked credential is gone at once: %v", err)
		}
		if afterRev, _ := s.ListAudit("class"); len(afterRev) != len(beforeRev)+1 || afterRev[len(afterRev)-1].Action != "access-revoke" {
			t.Fatalf("the record lands with the revocation: %+v", afterRev)
		}
		if err := s.DeleteAccessAudited("class", "ac-1", Audit{At: now, Instance: "class", Action: "access-revoke"}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("revoking twice: %v", err)
		}
		if err := s.DeleteAccessAudited("elsewhere", "ac-2", Audit{At: now, Instance: "elsewhere", Action: "access-revoke"}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("another instance may not revoke this one's credential: %v", err)
		}
		// The instance's destruction takes its credentials with it.
		if err := s.DeleteInstance("class"); err != nil {
			t.Fatal(err)
		}
		if left, _ := s.ListAccess("class"); len(left) != 0 {
			t.Fatalf("a destroyed instance left %d credentials", len(left))
		}
		if _, err := s.GetAccessByHash("h-bob"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a destroyed instance's credential is still joinable: %v", err)
		}
		// And no credential may be issued for a lab that is gone. A
		// destroy committing between an operator's check and the write
		// would otherwise leave one joinable by name — and valid again
		// the moment an instance of that name exists.
		gone := Access{ID: "ac-3", Instance: "class", Name: "carol", Prefix: "efgh", Hash: "h-carol", Created: now, Expires: now.Add(time.Hour)}
		beforeGone, _ := s.ListAudit("class")
		const goneGen = 0 // the generation of the instance the fixture destroyed
		if err := s.PutAccessAudited(gone, goneGen, Audit{At: now, Instance: "class", Action: "access-issue", Actor: "operator", Detail: "carol"}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("issuing access for a destroyed instance: %v", err)
		}
		if _, err := s.GetAccessByHash("h-carol"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("the refused credential was stored anyway: %v", err)
		}
		if afterGone, _ := s.ListAudit("class"); len(afterGone) != len(beforeGone) {
			t.Fatalf("the refused issue left a record: %d then %d", len(beforeGone), len(afterGone))
		}

		// And no credential may be issued for a *generation* that is
		// gone. A destroy alone is caught above by the name test; a
		// destroy followed by a create of the same name is not — the
		// name exists again, so the insert would attach the credential
		// and its record to the replacement, and the link issued for the
		// lab that is gone would open the one that took its place.
		reborn := Instance{Name: "class", Template: "t", Mode: "delivery", Source: "/s",
			Created: now.Add(time.Minute), Updated: now.Add(time.Minute), AuditFrom: 99}
		if err := s.PutInstance(reborn); err != nil {
			t.Fatal(err)
		}
		stale := Access{ID: "ac-4", Instance: "class", Name: "dave", Prefix: "ijkl", Hash: "h-dave", Created: now, Expires: now.Add(time.Hour)}
		beforeReborn, _ := s.ListAudit("class")
		if err := s.PutAccessAudited(stale, goneGen, Audit{At: now, Instance: "class", Action: "access-issue", Actor: "operator", Detail: "dave"}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a credential issued for the destroyed generation reached the one that replaced it: %v", err)
		}
		if _, err := s.GetAccessByHash("h-dave"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("the refused credential was stored anyway: %v", err)
		}
		if afterReborn, _ := s.ListAudit("class"); len(afterReborn) != len(beforeReborn) {
			t.Fatalf("the refused issue left a record: %d then %d", len(beforeReborn), len(afterReborn))
		}
		// The new generation issues its own, on its own generation.
		fresh := Access{ID: "ac-5", Instance: "class", Name: "erin", Prefix: "mnop", Hash: "h-erin", Created: now, Expires: now.Add(time.Hour)}
		if err := s.PutAccessAudited(fresh, genOf(t, s, "class"), Audit{At: now, Instance: "class", Action: "access-issue", Actor: "operator", Detail: "erin"}); err != nil {
			t.Fatalf("the replacement must be able to issue its own credential: %v", err)
		}
		// And the credential remembers which generation it is for, so
		// the session a join opens can inherit it rather than resolve
		// the instance a second time.
		issued, ierr := s.GetAccessByHash("h-erin")
		if ierr != nil {
			t.Fatalf("reading back the credential: %v", ierr)
		}
		if issued.Gen != genOf(t, s, "class") {
			t.Fatalf("the credential carries generation %d, not the one it was issued for", issued.Gen)
		}
	})

	t.Run("an instance records where its audit rows begin", func(t *testing.T) {
		s := open(t)
		now := time.Now().UTC().Truncate(time.Second)
		if seq, err := s.LatestAuditSeq(); err != nil || seq != 0 {
			t.Fatalf("an empty stream is sequence zero: %d %v", seq, err)
		}
		if err := s.AppendAudit(Audit{At: now, Instance: "class", Action: "reveal", Actor: "alice"}); err != nil {
			t.Fatal(err)
		}
		first, err := s.LatestAuditSeq()
		if err != nil || first == 0 {
			t.Fatalf("a row moves the mark: %d %v", first, err)
		}
		// The mark is carried on the instance, so a second generation of
		// the same name knows which rows are not its own.
		if err := s.PutInstance(Instance{Name: "class", Template: "t", Mode: "delivery", Source: "/s",
			Created: now, Updated: now, AuditFrom: first}); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetInstance("class")
		if err != nil || got == nil || got.AuditFrom != first {
			t.Fatalf("the mark did not survive the round trip: %+v %v", got, err)
		}
		// And it is the sequence, which only grows.
		if err := s.AppendAudit(Audit{At: now.Add(-time.Hour), Instance: "class", Action: "join", Actor: "bob"}); err != nil {
			t.Fatal(err)
		}
		second, err := s.LatestAuditSeq()
		if err != nil || second <= first {
			t.Fatalf("a backdated row still takes the next sequence: %d then %d (%v)", first, second, err)
		}
	})

	t.Run("a join is one write", func(t *testing.T) {
		s := open(t)
		now := time.Now().UTC().Truncate(time.Second)
		if err := s.PutInstance(Instance{Name: "class", Template: "t", Mode: "delivery", Source: "/s", Created: now, Updated: now}); err != nil {
			t.Fatal(err)
		}
		acc := Access{ID: "ac-1", Instance: "class", Name: "alice", Prefix: "abcd", Hash: "h-alice", Created: now, Expires: now.Add(8 * time.Hour)}
		if err := s.PutAccessAudited(acc, genOf(t, s, "class"), Audit{At: now, Instance: "class", Action: "access-issue", Actor: "operator"}); err != nil {
			t.Fatal(err)
		}
		sess := Session{ID: "js-1", Subject: "alice", Mechanism: "instance-access", Instance: "class", CSRF: "c1",
			Created: now, LastSeen: now, Expires: now.Add(time.Hour)}
		rec := Audit{At: now, Instance: "class", Action: "join", Actor: "alice", Mechanism: "instance-access"}
		// A join writes into two streams: the lab's, which its attendees
		// read, and the system's, which only the local socket does. Both
		// land with the session or neither does.
		sys := Audit{At: now, Action: "join", Actor: "alice", Mechanism: "instance-access", Detail: "class · ac-1 · 198.51.100.7"}
		before, _ := s.ListAudit("class")
		beforeSys, _ := s.ListAudit("")
		if err := s.JoinAccessAudited("ac-1", now, sess, rec, sys); err != nil {
			t.Fatalf("a live credential opens a session: %v", err)
		}
		got, err := s.GetSession("js-1")
		if err != nil || got == nil || got.Instance != "class" {
			t.Fatalf("the session the join opened: %+v %v", got, err)
		}
		if after, _ := s.ListAudit("class"); len(after) != len(before)+1 || after[len(after)-1].Action != "join" {
			t.Fatalf("the record lands with the session: %+v", after)
		}
		if after, _ := s.ListAudit(""); len(after) != len(beforeSys)+1 || after[len(after)-1].Detail != sys.Detail {
			t.Fatalf("the operator's record lands with it: %+v", after)
		}
		if used, _ := s.GetAccessByHash("h-alice"); used == nil || used.LastUsed == nil {
			t.Fatalf("the use was not recorded: %+v", used)
		}

		// A revocation the operator has been told succeeded must not be
		// followed by a session the same link opens. Recording the use
		// after the session left exactly that window.
		if err := s.DeleteAccessAudited("class", "ac-1", Audit{At: now, Instance: "class", Action: "access-revoke"}); err != nil {
			t.Fatal(err)
		}
		revoked := Session{ID: "js-2", Subject: "alice", Mechanism: "instance-access", Instance: "class", CSRF: "c2",
			Created: now, LastSeen: now, Expires: now.Add(time.Hour)}
		beforeRevoked, _ := s.ListAudit("class")
		beforeRevokedSys, _ := s.ListAudit("")
		if err := s.JoinAccessAudited("ac-1", now, revoked, rec, sys); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a revoked credential opened a session: %v", err)
		}
		if after, _ := s.ListAudit(""); len(after) != len(beforeRevokedSys) {
			t.Fatalf("the refused join wrote to the system stream anyway: %+v", after)
		}
		if got, err := s.GetSession("js-2"); err == nil && got != nil {
			t.Fatalf("the refused join stored a session anyway: %+v", got)
		}
		if after, _ := s.ListAudit("class"); len(after) != len(beforeRevoked) {
			t.Fatalf("the refused join left a record: %d then %d", len(beforeRevoked), len(after))
		}
	})
}
