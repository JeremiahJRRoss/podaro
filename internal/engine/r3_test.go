// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The reconciliation plan's R3: installed state survives the retirement.
// An instance an earlier build created from a template the owner has
// since retired keeps its containers, data, secrets and evidence; the
// engine never reconciles, resumes, repairs, restarts or stops it; every
// operation that would run the lab answers PDR-E215; status, the evidence
// and the reports read; destroy — the operator's act — removes it. The
// retired name is read from the embedded manifest, so nothing here spells
// one.

func retiredName(t *testing.T) string {
	t.Helper()
	m := podaro.Retirement()
	if len(m.Scenarios) == 0 {
		t.Fatal("the embedded manifest lists no retired template")
	}
	return m.Scenarios[0].Name
}

const zeroDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// earlierBuildInstance records an instance of a retired template the way
// an earlier build left it — it cannot be made through Create, which this
// release refuses: its row at ready, two services whose containers carry
// its labels (one running, one stopped, as a reboot leaves a container),
// a result row, and two evidence entries.
func earlierBuildInstance(t *testing.T, h *harness, name, template string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	inst := state.Instance{Name: name, Template: template, Version: "1.0.0", Mode: state.ModeDelivery,
		Source: filepath.Join(h.dir, "instances", name, "template"), Created: now, Updated: now,
		Stage: state.StageReady, Reached: state.StageReady}
	if err := h.store.PutInstance(inst); err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{runtime.LabelInstance: name, runtime.LabelTemplate: template, runtime.LabelManaged: "true"}
	if err := h.fake.EnsureNetwork(ctx, networkName(name), labels, false); err != nil {
		t.Fatal(err)
	}
	image := "example/earlier-build@" + zeroDigest // never pulled from anywhere: the fake records it
	if err := h.fake.Pull(ctx, image); err != nil {
		t.Fatal(err)
	}
	for _, svc := range []string{"index", "search"} {
		spec := runtime.ContainerSpec{Name: containerName(name, svc), Image: image, Network: networkName(name), Alias: svc, Publish: []int{8080},
			Labels: map[string]string{runtime.LabelInstance: name, runtime.LabelService: svc, runtime.LabelTemplate: template, runtime.LabelManaged: "true"}}
		id, err := h.fake.Create(ctx, spec)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.fake.Start(ctx, spec.Name); err != nil {
			t.Fatal(err)
		}
		st, err := h.fake.Inspect(ctx, spec.Name)
		if err != nil || st == nil {
			t.Fatalf("inspect %s: %v", spec.Name, err)
		}
		started := st.StartedAt
		if err := h.store.PutService(state.Service{Instance: name, Name: svc, Image: image, Container: spec.Name, ContainerID: id,
			Stage: state.StageReady, Ports: st.Ports, StartedAt: &started, HealthyAt: &now, RanImage: image}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.fake.Stop(ctx, containerName(name, "search"), 0); err != nil {
		t.Fatal(err)
	}
	if err := h.store.PutCheckpointResult(state.CheckpointResult{Instance: name, ID: "events-arrived", Class: "baseline", Adapter: "http", Status: "pass", At: now, Message: "recorded by an earlier build"}); err != nil {
		t.Fatal(err)
	}
	j := evidence.Open(filepath.Join(h.dir, "instances", name, "evidence"))
	for _, e := range []evidence.Entry{
		{Type: evidence.TypeLifecycle, Instance: name, Lifecycle: &evidence.Lifecycle{Event: "ready", Stage: "ready", Detail: "recorded by an earlier build"}},
		{Type: evidence.TypeCheckpoint, Instance: name, Checkpoint: &state.CheckpointResult{Instance: name, ID: "events-arrived", Class: "baseline", Adapter: "http", Status: "pass", At: now}},
	} {
		if _, err := j.Append(e); err != nil {
			t.Fatal(err)
		}
	}
}

// containerFacts is what a container is, for "left exactly as it was".
type containerFacts struct {
	id      string
	running bool
	started time.Time
}

func containersOf(t *testing.T, h *harness, instance string) map[string]containerFacts {
	t.Helper()
	ctx := context.Background()
	objs, err := h.fake.Objects(ctx, instance)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]containerFacts{}
	for _, c := range objs.Containers {
		st, err := h.fake.Inspect(ctx, c)
		if err != nil || st == nil {
			t.Fatalf("inspect %s: %v", c, err)
		}
		out[c] = containerFacts{id: st.ID, running: st.Running, started: st.StartedAt}
	}
	return out
}

// evidenceFiles is an instance's journal as bytes, by file name.
func evidenceFiles(t *testing.T, h *harness, instance string) map[string]string {
	t.Helper()
	dir := filepath.Join(h.dir, "instances", instance, "evidence")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(raw)
	}
	return out
}

// logRecorder keeps what an engine logged.
type logRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *logRecorder) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}

func (r *logRecorder) matching(sub ...string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, l := range r.lines {
		all := true
		for _, s := range sub {
			all = all && strings.Contains(l, s)
		}
		if all {
			out = append(out, l)
		}
	}
	return out
}

// restart stops the engine, opens a new one on the same store and world
// — a restarted process — and starts it with its log recorded.
func restart(t *testing.T, h *harness) *logRecorder {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := h.eng.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	h.open()
	rec := &logRecorder{}
	h.eng.opts.Logf = rec.logf
	if err := h.eng.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	return rec
}

// Start leaves an instance of a retired template exactly as it finds it:
// no reconcile job although a container of it is stopped, no job an
// earlier engine left for it resumed, no runtime call — the running
// container keeps running, the stopped one stays stopped — one PDR-W103
// line per start, and one evidence entry and one mark, ever. A supported
// instance beside it, in the same state, is reconciled as always.
func TestStartLeavesAnInstanceOfARetiredTemplateAsItFindsIt(t *testing.T) {
	retired := retiredName(t)
	h := newHarness(t)
	ctx := context.Background()

	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "control"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("control create: %s", outcomeOf(h, job.ID))
	}
	earlierBuildInstance(t, h, "old-lab", retired)
	now := time.Now().UTC()
	stale := state.Job{ID: "job_left_by_an_earlier_engine", Kind: "verify", Instance: "old-lab", State: state.JobQueued, Stage: "queued", Started: now}
	if err := h.store.PutJob(stale); err != nil {
		t.Fatal(err)
	}
	// The control's container stops, as the retired instance's second one
	// did: a start owes the control a reconcile, and owes old-lab nothing.
	if err := h.fake.Stop(ctx, containerName("control", "web"), 0); err != nil {
		t.Fatal(err)
	}
	before := containersOf(t, h, "old-lab")
	if len(before) != 2 {
		t.Fatalf("the earlier build's containers: %v", before)
	}
	evidenceBefore := evidenceFiles(t, h, "old-lab")

	rec := restart(t, h)

	// The control is reconciled; old-lab is not.
	var reconciled *state.Job
	jobs, err := h.store.ListJobs("control")
	if err != nil {
		t.Fatal(err)
	}
	for i := range jobs {
		if jobs[i].Kind == "reconcile" {
			reconciled = &jobs[i]
		}
	}
	if reconciled == nil {
		t.Fatalf("the supported instance was not reconciled; its jobs: %+v", jobs)
	}
	if j := h.wait(reconciled.ID); j.State != state.JobSucceeded {
		t.Fatalf("control reconcile: %s", outcomeOf(h, reconciled.ID))
	}
	jobs, err = h.store.ListJobs("old-lab")
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range jobs {
		if j.Kind == "reconcile" {
			t.Fatalf("an instance of a retired template got a reconcile job: %+v", j)
		}
		if j.ID != stale.ID {
			t.Fatalf("a job appeared for the retired instance: %+v", j)
		}
	}
	// The job the earlier engine left is declined, not resumed.
	got, err := h.store.GetJob(stale.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != state.JobFailed || got.Error == nil || got.Error.Code != pdr.CodeInstanceUnsupported {
		t.Fatalf("the stale job: %+v %+v, want failed with %s", got, got.Error, pdr.CodeInstanceUnsupported)
	}
	if len(rec.matching("resuming", "old-lab")) != 0 {
		t.Fatalf("a job of the retired instance was resumed: %v", rec.matching("resuming", "old-lab"))
	}
	// Its containers: untouched, the running one running, the stopped one stopped.
	if after := containersOf(t, h, "old-lab"); !sameContainers(before, after) {
		t.Fatalf("the retired instance's containers changed:\nbefore %+v\nafter  %+v", before, after)
	}
	// One W103 line, naming it.
	if w := rec.matching(pdr.CodeRetiredPresent, "old-lab"); len(w) != 1 {
		t.Fatalf("want one %s line for old-lab, got %d: %v", pdr.CodeRetiredPresent, len(w), rec.lines)
	}
	if len(rec.matching("reconciling old-lab")) != 0 {
		t.Fatalf("the retired instance was reconciled: %v", rec.lines)
	}
	// Its evidence: what was there, byte for byte, and one entry more.
	unsupportedEntry := checkEvidenceGrewByOne(t, h, evidenceBefore)
	if reason, err := h.store.Unsupported("old-lab"); err != nil || reason != unsupportedReason {
		t.Fatalf("the mark: %q %v", reason, err)
	}

	// A second start says it again in its log, and nowhere else.
	rec = restart(t, h)
	if w := rec.matching(pdr.CodeRetiredPresent, "old-lab"); len(w) != 1 {
		t.Fatalf("the second start: want one %s line, got %v", pdr.CodeRetiredPresent, rec.lines)
	}
	files := evidenceFiles(t, h, "old-lab")
	if len(files) != len(evidenceBefore)+1 || files[unsupportedEntry] == "" {
		t.Fatalf("the second start wrote evidence again: %d entries, want %d", len(files), len(evidenceBefore)+1)
	}
	if after := containersOf(t, h, "old-lab"); !sameContainers(before, after) {
		t.Fatalf("the second start changed the retired instance's containers:\nbefore %+v\nafter  %+v", before, after)
	}
}

func sameContainers(a, b map[string]containerFacts) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || v.id != w.id || v.running != w.running || !v.started.Equal(w.started) {
			return false
		}
	}
	return true
}

// checkEvidenceGrewByOne asserts the journal kept every earlier file
// byte for byte and gained exactly one lifecycle entry, the unsupported
// one, and returns that entry's file name.
func checkEvidenceGrewByOne(t *testing.T, h *harness, before map[string]string) string {
	t.Helper()
	after := evidenceFiles(t, h, "old-lab")
	for name, raw := range before {
		if after[name] != raw {
			t.Fatalf("evidence %s changed", name)
		}
	}
	if len(after) != len(before)+1 {
		t.Fatalf("want one new evidence entry, got %d", len(after)-len(before))
	}
	for name := range after {
		if _, ok := before[name]; ok {
			continue
		}
		e, err := evidence.Open(filepath.Join(h.dir, "instances", "old-lab", "evidence")).Get(strings.TrimSuffix(name, ".json"))
		if err != nil {
			t.Fatal(err)
		}
		if e.Lifecycle == nil || e.Lifecycle.Event != "unsupported" || e.Lifecycle.Code != pdr.CodeRetiredPresent || e.Lifecycle.Detail != unsupportedDetail {
			t.Fatalf("the new entry: %+v %+v", e, e.Lifecycle)
		}
		return name
	}
	return ""
}

// Everything that would run the lab answers PDR-E215 before anything is
// recorded — no audit row, no job — and before any runtime call; what
// reads the record still works; destroy removes what the instance's
// labels name and nothing else.
func TestAnInstanceOfARetiredTemplateIsReadAndDestroyedButNeverRun(t *testing.T) {
	retired := retiredName(t)
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "control"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("control create: %s", outcomeOf(h, job.ID))
	}
	earlierBuildInstance(t, h, "old-lab", retired)
	restart(t, h)
	before := containersOf(t, h, "old-lab")
	audit, _ := h.store.ListAudit("old-lab")
	jobs, _ := h.store.ListJobs("old-lab")

	refused := map[string]error{}
	_, refused["verify"] = h.eng.VerifyAs(ctx, "old-lab", "", Socket)
	_, refused["seed"] = h.eng.SeedAs(ctx, "old-lab", "any", Socket)
	_, refused["reset"] = h.eng.ResetAs(ctx, "old-lab", Socket)
	_, refused["reset plan"] = h.eng.ResetPlanFor("old-lab")
	_, refused["checkpoint run"] = h.eng.RunCheckpoint(ctx, "old-lab", "events-arrived", Socket)
	_, refused["attest"] = h.eng.Attest(ctx, "old-lab", "events-arrived", "", Socket)
	_, refused["progress"] = h.eng.PutProgress("old-lab", "any", state.Progress{}, Socket)
	_, refused["checkpoints"] = h.eng.Checkpoints("old-lab", Socket)
	_, refused["playbooks"] = h.eng.Playbooks("old-lab", Socket)
	_, refused["playbook"] = h.eng.Playbook("old-lab", "any", Socket)
	_, refused["progress read"] = h.eng.Progress("old-lab", "any", Socket)
	_, refused["step seeds"] = h.eng.StepSeeds("old-lab", Socket)
	_, refused["secrets"] = h.eng.Secrets("old-lab", Socket)
	_, refused["reveal"] = h.eng.Reveal(ctx, "old-lab", "any", Socket)
	_, refused["logs"] = h.eng.Logs(ctx, "old-lab", "index", LogOptions{}, Socket)
	for op, err := range refused {
		if code(err) != pdr.CodeInstanceUnsupported {
			t.Errorf("%s: %v, want %s", op, err, pdr.CodeInstanceUnsupported)
		}
	}
	if after, _ := h.store.ListAudit("old-lab"); len(after) != len(audit) {
		t.Errorf("a refusal wrote the audit stream: %+v", after[len(audit):])
	}
	if after, _ := h.store.ListJobs("old-lab"); len(after) != len(jobs) {
		t.Errorf("a refusal recorded a job: %+v", after)
	}
	if after := containersOf(t, h, "old-lab"); !sameContainers(before, after) {
		t.Fatalf("a refusal touched the containers:\nbefore %+v\nafter  %+v", before, after)
	}

	// What reads the record works.
	v, err := h.eng.View("old-lab", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if v.Unsupported != unsupportedReason || v.Ladder.Label != "unsupported · "+unsupportedReason || v.Ladder.Stage != string(state.StageReady) {
		t.Fatalf("the view: unsupported %q, ladder %+v", v.Unsupported, v.Ladder)
	}
	if cv, err := h.eng.View("control", Socket); err != nil || cv.Unsupported != "" || strings.Contains(cv.Ladder.Label, "unsupported") {
		t.Fatalf("a supported instance's view: %+v %v", cv, err)
	}
	entries, err := h.eng.Evidence("old-lab", EvidenceFilter{}, Socket)
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	if len(entries) != 3 { // the earlier build's two and the unsupported one
		t.Fatalf("evidence: %d entries, want 3: %+v", len(entries), entries)
	}
	if _, err := h.eng.EvidenceEntry("old-lab", entries[0].ID, Socket); err != nil {
		t.Fatalf("an evidence entry: %v", err)
	}
	junit, err := h.eng.JUnit("old-lab", Socket)
	if err != nil || !strings.Contains(string(junit), "events-arrived") {
		t.Fatalf("the JUnit report must carry the recorded result: %v\n%s", err, junit)
	}
	report, err := h.eng.Report("old-lab", Socket)
	if err != nil || !strings.Contains(string(report), "events-arrived") {
		t.Fatalf("the HTML report must carry the recorded result: %v", err)
	}

	// Destroy is the operator's act, and it works: what the labels name
	// goes — the running container and the stopped one, the network, the
	// rows, the directory — and nothing else does.
	controlBefore := containersOf(t, h, "control")
	dj, err := h.eng.Destroy(ctx, "old-lab", "old-lab")
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(dj.ID); j.State != state.JobSucceeded {
		t.Fatalf("destroy: %s", outcomeOf(h, dj.ID))
	}
	if objs, _ := h.fake.Objects(ctx, "old-lab"); len(objs.Containers) != 0 || len(objs.Networks) != 0 {
		t.Fatalf("destroy left the retired instance's objects: %+v", objs)
	}
	if _, err := h.store.GetInstance("old-lab"); err != state.ErrNotFound {
		t.Fatalf("destroy left the instance row: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "instances", "old-lab")); !os.IsNotExist(err) {
		t.Fatalf("destroy left the instance directory: %v", err)
	}
	if after := containersOf(t, h, "control"); !sameContainers(controlBefore, after) {
		t.Fatalf("destroying the retired instance touched another:\nbefore %+v\nafter  %+v", controlBefore, after)
	}
}

// A directory whose lab.yaml kept a retired template's name — a copy
// whose content names nothing retired — validates, and is still not
// created: an instance recorded under that name would be one this
// release does not operate. PDR-E107, and nothing recorded or run.
func TestADirectoryThatKeptARetiredNameIsNotCreated(t *testing.T) {
	retired := retiredName(t)
	h := newHarness(t)
	dir := filepath.Join(t.TempDir(), "copy")
	if err := copyTree(fixture, dir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	renamed := strings.Replace(string(raw), "name: hello-nginx", "name: "+retired, 1)
	if renamed == string(raw) {
		t.Fatal("the fixture's metadata.name moved; update this test")
	}
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(renamed), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = h.eng.Create(context.Background(), CreateRequest{Path: dir, Name: "copy"})
	if code(err) != pdr.CodeTemplateRetired {
		t.Fatalf("up of a directory declaring a retired name: %v, want %s", err, pdr.CodeTemplateRetired)
	}
	if list, _ := h.store.ListInstances(); len(list) != 0 {
		t.Fatalf("a refused create recorded instances: %+v", list)
	}
	if objs, _ := h.fake.Objects(context.Background(), "copy"); !objs.Empty() {
		t.Fatalf("a refused create made runtime objects: %+v", objs)
	}
}
