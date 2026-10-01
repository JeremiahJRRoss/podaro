// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

var fixture = filepath.Join("..", "..", "hack", "fixtures", "hello-nginx")

type harness struct {
	t     *testing.T
	store state.Store
	world string
	dir   string
	fake  *runtime.Fake
	eng   *Engine
}

// newHarness wires a memory store, a fake runtime with a 200ms start
// delay, and an engine polling every 50ms.
func newHarness(t *testing.T) *harness {
	t.Helper()
	t.Setenv(runtime.EnvFakeReadyDelay, "200ms")
	dir := t.TempDir()
	h := &harness{t: t, store: state.NewMemory(), world: filepath.Join(dir, "world.json"), dir: dir}
	h.open()
	// The engine is stopped before the directory it writes into is
	// removed. `verify`, `attest` and `reset` admit a job and launch it,
	// so work outlives the test body that started it, and `t.TempDir`'s
	// own cleanup then races a checkpoint writing its evidence —
	// "unlinkat …/instances/<name>/evidence: directory not empty", which
	// is a real unfinished write and not a flaky filesystem. Registered
	// after `t.TempDir`, so it runs before it (cleanups are LIFO), and
	// `Shutdown` is idempotent for the tests that call it themselves.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := h.eng.Shutdown(ctx); err != nil {
			t.Errorf("the engine did not stop before its directory was removed: %v", err)
		}
		h.fake.Close()
	})
	return h
}

// open (re)creates the runtime and engine on the same store and world —
// a restarted engine process.
func (h *harness) open() {
	h.t.Helper()
	if h.fake != nil {
		h.fake.Close()
	}
	f, err := runtime.NewFake(h.world)
	if err != nil {
		h.t.Fatal(err)
	}
	h.fake = f
	h.eng = New(Options{Store: h.store, Runtime: f, StateDir: h.dir, CatalogDir: filepath.Join("..", "..", "scenarios"), PollInterval: 50 * time.Millisecond})
}

func (h *harness) wait(id string) *state.Job {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	j, err := h.eng.Wait(ctx, id)
	if err != nil {
		h.t.Fatalf("wait %s: %v", id, err)
	}
	return j
}

// outcomeOf is a job's recorded state, for a failure message that has to
// say what happened rather than only that something did.
func outcomeOf(h *harness, id string) string {
	rec, err := h.eng.Job(id, Socket)
	if err != nil || rec == nil {
		return "no record: " + fmt.Sprint(err)
	}
	out := string(rec.State) + "/" + rec.Stage
	if rec.Error != nil {
		out += " · " + rec.Error.Code + " " + rec.Error.Message
	}
	return out
}

// errText flattens a job's error envelope for substring assertions.
func errText(j *state.Job) string {
	if j == nil || j.Error == nil {
		return ""
	}
	raw, _ := json.Marshal(j.Error)
	return string(raw)
}

func code(err error) string {
	var pe *pdr.Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func TestCreateReachesHealthyAndDestroyLeavesNothing(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	// One exclusive job per instance (API §4): while create is queued or
	// running, any other job on t1 is PDR-E201.
	if _, err := h.eng.Destroy(ctx, "t1", "t1"); code(err) != pdr.CodeInstanceBusy {
		t.Errorf("destroy during create: want PDR-E201, got %v", err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create job: %+v", j)
	}
	inst, _ := h.store.GetInstance("t1")
	if inst.Stage != state.StageReady || inst.Mode != state.ModeAuthoring {
		t.Fatalf("instance: %+v", inst)
	}
	svcs, _ := h.store.ListServices("t1")
	if len(svcs) != 1 || svcs[0].Stage != state.StageReady || svcs[0].Ports[80] == 0 || svcs[0].HealthyAt == nil {
		t.Fatalf("service: %+v", svcs)
	}
	if svcs[0].Container != "pdr-t1-web" {
		t.Errorf("container name %s", svcs[0].Container)
	}
	events, _ := h.store.ListEvents(job.ID)
	var steps []string
	for _, ev := range events {
		steps = append(steps, ev.Step+":"+ev.Status)
	}
	want := "network:ok,network:ok,secrets:ok,pull:ok,create:ok,alive:ok,healthy:ok,init:skipped,connected:ok,seeded:ok,verified:ok,ready:ok,job:succeeded"
	if got := strings.Join(steps, ","); got != want {
		t.Errorf("journal = %s, want %s", got, want)
	}

	// Exclusive job and duplicate name semantics.
	if _, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "t1"}); code(err) != pdr.CodeInstanceExists {
		t.Errorf("duplicate create: %v", err)
	}
	if _, err := h.eng.Destroy(ctx, "t1", "nope"); code(err) != pdr.CodeDestroyConfirm {
		t.Errorf("wrong confirm: %v", err)
	}
	if _, err := h.eng.Destroy(ctx, "missing", "missing"); code(err) != pdr.CodeInstanceNotFound {
		t.Errorf("missing instance: %v", err)
	}
	dj, err := h.eng.Destroy(ctx, "t1", "t1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.eng.Destroy(ctx, "t1", "t1"); code(err) != pdr.CodeInstanceBusy && code(err) != pdr.CodeInstanceNotFound {
		t.Errorf("second destroy while busy: %v", err)
	}
	if j := h.wait(dj.ID); j.State != state.JobSucceeded {
		t.Fatalf("destroy job: %+v", j)
	}
	if objs, _ := h.fake.Objects(ctx, "t1"); !objs.Empty() {
		t.Errorf("runtime objects remain: %+v", objs)
	}
	if _, err := h.store.GetInstance("t1"); err != state.ErrNotFound {
		t.Errorf("instance survives destroy: %v", err)
	}
}

// Create the fixture twice → identical names, network, labels (ports are
// ephemeral by design).
func TestCreateTwiceIsIdentical(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	shape := func() string {
		job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "twin"})
		if err != nil {
			t.Fatal(err)
		}
		h.wait(job.ID)
		objs, _ := h.fake.Objects(ctx, "twin")
		svcs, _ := h.store.ListServices("twin")
		s := strings.Join(objs.Containers, ",") + "|" + strings.Join(objs.Networks, ",") + "|" + svcs[0].Image + "|" + string(svcs[0].Stage)
		dj, _ := h.eng.Destroy(ctx, "twin", "twin")
		h.wait(dj.ID)
		return s
	}
	a, b := shape(), shape()
	if a != b || !strings.HasPrefix(a, "pdr-twin-web|pdr-twin,pdr-twin_int|") {
		t.Fatalf("shapes differ or wrong:\n%s\n%s", a, b)
	}
}

// A create job interrupted after its containers were created but before
// they started (an engine killed mid-job) resumes on Start and completes.
func TestInterruptedCreateResumesOnStart(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// Drive the runtime by hand to the state a crash would leave: instance
	// and services recorded, network + container created, job "running"
	// at the start step, container never started.
	now := time.Now().UTC()
	image := "docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609"
	_ = h.store.PutInstance(state.Instance{Name: "crash", Template: "hello-nginx", Version: "0.1.0", Mode: state.ModeAuthoring, Source: mustAbs(t, fixture), Created: now, Updated: now})
	_ = h.store.PutService(state.Service{Instance: "crash", Name: "web", Image: image, Container: "pdr-crash-web", Typical: "5s", Budget: "1m"})
	_ = h.store.PutJob(state.Job{ID: "job_crash", Kind: "create", Instance: "crash", State: state.JobRunning, Stage: "starting web", Started: now})
	labels := map[string]string{runtime.LabelInstance: "crash", runtime.LabelManaged: "true"}
	_ = h.fake.Pull(ctx, image)
	_ = h.fake.EnsureNetwork(ctx, "pdr-crash", labels, false)
	svcLabels := map[string]string{runtime.LabelInstance: "crash", runtime.LabelManaged: "true", runtime.LabelService: "web"}
	if _, err := h.fake.Create(ctx, runtime.ContainerSpec{Name: "pdr-crash-web", Image: image, Network: "pdr-crash", Labels: svcLabels, Publish: []int{80}}); err != nil {
		t.Fatal(err)
	}
	// "Restart" the engine.
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if j := h.wait("job_crash"); j.State != state.JobSucceeded {
		t.Fatalf("resumed job: %+v", j)
	}
	inst, _ := h.store.GetInstance("crash")
	if inst.Stage != state.StageReady {
		t.Fatalf("resumed instance stage %s", inst.Stage)
	}
	events, _ := h.store.ListEvents("job_crash")
	if len(events) == 0 || events[len(events)-1].Status != "succeeded" {
		t.Errorf("journal: %+v", events)
	}
}

// A host reboot stops every container; the next engine start reconciles
// the instance back to its recorded stage and says so in a journal.
func TestRebootIsReconciledOnStart(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "rb"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	h.fake.Close()
	if err := runtime.Reboot(h.world); err != nil {
		t.Fatal(err)
	}
	h.open()
	if st, _ := h.fake.Inspect(ctx, "pdr-rb-web"); st.Running {
		t.Fatal("reboot should have stopped the container")
	}
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ := h.store.ListJobs("rb")
	if len(jobs) != 2 || jobs[0].Kind != "reconcile" {
		t.Fatalf("expected a reconcile job, got %+v", jobs)
	}
	if j := h.wait(jobs[0].ID); j.State != state.JobSucceeded {
		t.Fatalf("reconcile job: %+v", j)
	}
	inst, _ := h.store.GetInstance("rb")
	if inst.Stage != state.StageReady {
		t.Fatalf("after reconcile: stage %s", inst.Stage)
	}
	if st, _ := h.fake.Inspect(ctx, "pdr-rb-web"); !st.Running {
		t.Fatal("container not restarted")
	}
	// Nothing to do on a healthy instance: no new job.
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if jobs, _ := h.store.ListJobs("rb"); len(jobs) != 2 {
		t.Errorf("idle reconcile created jobs: %+v", jobs)
	}
}

func TestReadinessBudgetFailsTheJob(t *testing.T) {
	h := newHarness(t)
	t.Setenv(runtime.EnvFakeReadyDelay, "10s")
	h.open()
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool { return false }
	dir := t.TempDir()
	writeFixture(t, dir, "budget: 200ms")
	job, err := h.eng.Create(context.Background(), CreateRequest{Path: dir, Name: "slow"})
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(job.ID)
	if j.State != state.JobFailed || !strings.Contains(errText(j), pdr.CodeReadinessBudget) {
		t.Fatalf("job: %+v", j)
	}
	inst, _ := h.store.GetInstance("slow")
	if inst.Stage != state.StageAlive {
		t.Errorf("ladder should stop at alive, got %s", inst.Stage)
	}
}

func TestLicenseGateAndCatalogDelivery(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.opts.Library = lab.DirLibrary(filepath.Join("..", "lab", "testdata", "modules"))
	aliases := filepath.Join("..", "lab", "testdata", "valid-aliases")
	_, err := h.eng.Create(ctx, CreateRequest{Path: aliases, Name: "lic"})
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != pdr.CodeLicenseRequired || len(pe.Details) != 1 || pe.Details[0].License != "custom-terms" || pe.Details[0].URL == "" || pe.Details[0].Path != "" {
		t.Fatalf("expected the 428 gate, got %v", err)
	}
	lic, err := h.eng.Create(ctx, CreateRequest{Path: aliases, Name: "lic", AcceptLicenses: []string{"custom-terms"}})
	if err != nil {
		t.Fatalf("accepted licenses should pass the gate: %v", err)
	}
	h.wait(lic.ID) // the job reads the library; swap it only once it is over

	// A catalog template is a delivery instance pinned to a snapshot (the
	// shipped templates' secrets and files are rendered at create since
	// plan S6 — TestSmallTemplateReachesReady walks that whole path).
	h.eng.opts.Library = lab.EmbeddedLibrary()
	if _, err := h.eng.Create(ctx, CreateRequest{Template: "nope", Name: "d1"}); code(err) != pdr.CodeTemplateNotFound {
		t.Errorf("unknown template: %v", err)
	}
	catalog := t.TempDir()
	if err := copyTree(fixture, filepath.Join(catalog, "hello-nginx")); err != nil {
		t.Fatal(err)
	}
	h.eng.opts.CatalogDir = catalog
	job, err := h.eng.Create(ctx, CreateRequest{Template: "hello-nginx", Name: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	inst, _ := h.store.GetInstance("d1")
	if inst.Mode != state.ModeDelivery || !strings.HasSuffix(inst.Source, filepath.Join("instances", "d1", "template")) {
		t.Errorf("delivery instance: %+v", inst)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("delivery create: %+v", j)
	}
	if _, err := h.eng.Create(ctx, CreateRequest{Template: "hello-nginx", Mode: "sideways"}); code(err) != pdr.CodeCreateRequest {
		t.Errorf("bad mode: %v", err)
	}
}

// The composed configuration reaches the runtime: env through a 0600
// file under the instance, command as the entrypoint, args as the
// command — as written, never on argv.
func TestEffectiveConfigReachesTheRuntime(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: configured, version: 1.0.0 }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    env: { GREETING: "hello there", PORT: "80" }
    command: ["nginx", "-g", "daemon off;"]
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
`
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "cfg"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	st, _ := h.fake.Inspect(ctx, "pdr-cfg-web")
	spec := h.fake.Spec("pdr-cfg-web")
	if st == nil || spec == nil {
		t.Fatal("container missing")
	}
	if strings.Join(spec.Command, " ") != "nginx -g daemon off;" || len(spec.Entrypoint) != 0 {
		t.Fatalf("inline command must become the image command: %+v", spec)
	}
	envPath := filepath.Join(h.dir, "instances", "cfg", "env", "web.env")
	if spec.EnvFile != envPath {
		t.Fatalf("env file: %q", spec.EnvFile)
	}
	fi, err := os.Stat(envPath)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("env file mode: %v %v", fi, err)
	}
	raw, _ := os.ReadFile(envPath)
	if string(raw) != "GREETING=hello there\nPORT=80\n" {
		t.Fatalf("env file content: %q", raw)
	}
	// A secret reference is rendered at create (plan S6): the env file
	// carries the generated value, the secret store holds the same value
	// at 0600, and the placeholder appears nowhere.
	body = `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: needy, version: 1.0.0 }
secrets:
  token: { kind: token }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    env: { TOKEN: "${secret:token}" }
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
`
	needy := t.TempDir()
	_ = os.WriteFile(filepath.Join(needy, "lab.yaml"), []byte(body), 0o644)
	job, err = h.eng.Create(ctx, CreateRequest{Path: needy, Name: "needy"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("a template with a secret creates: %+v", j)
	}
	secretPath := filepath.Join(h.dir, "instances", "needy", "secrets", "token")
	value, err := os.ReadFile(secretPath)
	if err != nil || len(value) != 64 {
		t.Fatalf("secret file: %q %v", value, err)
	}
	if fi, _ := os.Stat(secretPath); fi.Mode().Perm() != 0o600 {
		t.Fatalf("secret file mode %o", fi.Mode().Perm())
	}
	raw, _ = os.ReadFile(filepath.Join(h.dir, "instances", "needy", "env", "web.env"))
	if string(raw) != "TOKEN="+string(value)+"\n" || strings.Contains(string(raw), "${secret:") {
		t.Fatalf("env must carry the rendered value: %q", raw)
	}
	// A value an env file cannot express fails the job, named.
	body = strings.Replace(body, `env: { TOKEN: "${secret:token}" }`, `env: { TOKEN: "${secret:token}", MULTI: "a\nb" }`, 1)
	multi := t.TempDir()
	_ = os.WriteFile(filepath.Join(multi, "lab.yaml"), []byte(body), 0o644)
	job, err = h.eng.Create(ctx, CreateRequest{Path: multi, Name: "multi"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed || !strings.Contains(errText(j), "multi-line") {
		t.Fatalf("a multi-line env value fails the job, named: %+v", j)
	}
}

// Resume needs the whole identity: name, version, profile, mode, and the
// tracked directory for authoring instances.
func TestResumeRequiresSameIdentity(t *testing.T) {
	h := newHarness(t)
	t.Setenv(runtime.EnvFakeReadyDelay, "10s")
	h.open()
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool { return false }
	ctx := context.Background()
	write := func(dir, version string) {
		t.Helper()
		body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: slow-nginx, version: ` + version + ` }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 200ms }
`
		if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dirA, dirB := t.TempDir(), t.TempDir()
	write(dirA, "1.0.0")
	write(dirB, "1.0.0")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dirA, Name: "id"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed {
		t.Fatalf("first create should fail: %+v", j)
	}
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool { return true }
	if _, err := h.eng.Create(ctx, CreateRequest{Path: dirB, Name: "id"}); code(err) != pdr.CodeInstanceExists {
		t.Fatalf("another directory with the same metadata must be E200: %v", err)
	}
	write(dirA, "2.0.0")
	if _, err := h.eng.Create(ctx, CreateRequest{Path: dirA, Name: "id"}); code(err) != pdr.CodeInstanceExists {
		t.Fatalf("another version must be E200: %v", err)
	}
	catalog := t.TempDir()
	write(filepath.Join(catalog), "1.0.0")
	_ = os.MkdirAll(filepath.Join(catalog, "slow-nginx"), 0o755)
	write(filepath.Join(catalog, "slow-nginx"), "1.0.0")
	h.eng.opts.CatalogDir = catalog
	if _, err := h.eng.Create(ctx, CreateRequest{Template: "slow-nginx", Name: "id"}); code(err) != pdr.CodeInstanceExists {
		t.Fatalf("a delivery create of an authoring instance must be E200: %v", err)
	}
	write(dirA, "1.0.0")
	job2, err := h.eng.Create(ctx, CreateRequest{Path: dirA, Name: "id"})
	if err != nil {
		t.Fatalf("same identity must resume: %v", err)
	}
	if j := h.wait(job2.ID); j.State != state.JobSucceeded {
		t.Fatalf("resume: %+v", j)
	}
}

// Destroy removes only what is provably the instance's: a foreign
// container or network under the predictable name stops it, named.
func TestDestroyRefusesForeignObjects(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, _ := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "own"})
	h.wait(job.ID)
	// Someone removed Podaro's container and reused the name.
	_ = h.fake.Remove(ctx, "pdr-own-web")
	image := "docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609"
	if _, err := h.fake.Create(ctx, runtime.ContainerSpec{Name: "pdr-own-web", Image: image, Labels: map[string]string{"com.example/owner": "else"}}); err != nil {
		t.Fatal(err)
	}
	d, err := h.eng.Destroy(ctx, "own", "own")
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(d.ID)
	if j.State != state.JobFailed || !strings.Contains(errText(j), "refusing to adopt") && !strings.Contains(errText(j), "destroy refused") {
		t.Fatalf("destroy must refuse the foreign container: %+v", j)
	}
	if st, _ := h.fake.Inspect(ctx, "pdr-own-web"); st == nil {
		t.Fatal("foreign container was removed")
	}
	if _, err := h.store.GetInstance("own"); err != nil {
		t.Fatal("instance state was deleted although the destroy failed")
	}
}

// Not being able to enumerate leftovers fails the destroy instead of
// deleting the instance's state on trust.
func TestDestroyFailsWhenLeftoversCannotBeListed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, _ := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "lo"})
	h.wait(job.ID)
	h.eng.opts.Runtime = &brokenObjects{Fake: h.fake}
	d, err := h.eng.Destroy(ctx, "lo", "lo")
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(d.ID)
	if j.State != state.JobFailed || !strings.Contains(errText(j), "list leftovers") {
		t.Fatalf("destroy must fail when leftovers cannot be listed: %+v", j)
	}
	if _, err := h.store.GetInstance("lo"); err != nil {
		t.Fatal("instance state deleted despite the enumeration failure")
	}
}

type brokenObjects struct{ *runtime.Fake }

func (b *brokenObjects) Objects(ctx context.Context, instance string) (runtime.Objects, error) {
	return runtime.Objects{}, errors.New("podman ps: transient failure")
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// writeFixture writes a one-service template like hello-nginx with the
// given readiness budget line (e.g. "budget: 200ms").
func writeFixture(t *testing.T, dir, budget string) {
	t.Helper()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: slow-nginx }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, ` + budget + ` }
`
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A failed create is resumed by the next `up` of the same lab (the error
// anatomy's "re-run to resume"); a healthy instance, another template, or
// another mode under the same name is E200.
func TestFailedCreateResumesOnNextUp(t *testing.T) {
	h := newHarness(t)
	t.Setenv(runtime.EnvFakeReadyDelay, "10s")
	h.open()
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool { return false }
	dir := t.TempDir()
	writeFixture(t, dir, "budget: 200ms")
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "slow"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed {
		t.Fatalf("first create should fail: %+v", j)
	}
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool { return true }
	if _, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "slow"}); code(err) != pdr.CodeInstanceExists {
		t.Fatalf("another template under the name must be E200: %v", err)
	}
	if _, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "slow", Mode: "delivery"}); code(err) != pdr.CodeInstanceExists {
		t.Fatalf("another mode under the name must be E200: %v", err)
	}
	job2, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "slow"})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if job2.ID == job.ID {
		t.Fatal("resume must be a new job")
	}
	if j := h.wait(job2.ID); j.State != state.JobSucceeded {
		t.Fatalf("resumed create: %+v", j)
	}
	inst, _ := h.store.GetInstance("slow")
	if inst.Stage != state.StageReady {
		t.Fatalf("stage after resume: %s", inst.Stage)
	}
	if _, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "slow"}); code(err) != pdr.CodeInstanceExists {
		t.Fatalf("healthy instance must be E200: %v", err)
	}
	if objs, _ := h.fake.Objects(ctx, "slow"); len(objs.Containers) != 1 || len(objs.Networks) != 2 {
		t.Fatalf("resume must reuse the same objects: %+v", objs)
	}
}

// A failed delivery create is retried from the instance's own snapshot and
// pinned modules, whatever the catalog holds by then — the entry may have
// been upgraded or removed, and the instance is immune to both (plan S4
// Review round 20). A new instance of the removed template, and another
// template under a taken name, still resolve against the catalog.
func TestFailedDeliveryCreateResumesFromItsSnapshot(t *testing.T) {
	h := newHarness(t)
	t.Setenv(runtime.EnvFakeReadyDelay, "10s")
	h.open()
	ctx := context.Background()
	catalog := t.TempDir()
	entry := filepath.Join(catalog, "slow-nginx")
	if err := os.MkdirAll(entry, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, entry, "budget: 200ms")
	version := func(v string) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(entry, "lab.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		body := regexp.MustCompile(`metadata: \{ name: slow-nginx[^}]*\}`).ReplaceAllString(string(raw), "metadata: { name: slow-nginx, version: "+v+" }")
		if body == string(raw) {
			t.Fatal("fixture changed; update the test")
		}
		if err := os.WriteFile(filepath.Join(entry, "lab.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	version("1.0.0")
	h.eng.opts.CatalogDir = catalog
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool { return false }
	for _, name := range []string{"bumped", "gone"} {
		job, err := h.eng.Create(ctx, CreateRequest{Template: "slow-nginx", Name: name})
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if j := h.wait(job.ID); j.State != state.JobFailed {
			t.Fatalf("first create of %s should fail: %+v", name, j)
		}
	}
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool { return true }
	resume := func(name string) {
		t.Helper()
		job, err := h.eng.Create(ctx, CreateRequest{Template: "slow-nginx", Name: name})
		if err != nil {
			t.Fatalf("resume %s: %v", name, err)
		}
		if j := h.wait(job.ID); j.State != state.JobSucceeded {
			t.Fatalf("resumed create of %s: %+v", name, j)
		}
		inst, err := h.store.GetInstance(name)
		if err != nil || inst.Stage != state.StageReady || inst.Version != "1.0.0" {
			t.Fatalf("%s after resume must be ready at the admitted version: %+v %v", name, inst, err)
		}
		if objs, _ := h.fake.Objects(ctx, name); len(objs.Containers) != 1 || len(objs.Networks) != 2 {
			t.Fatalf("resume of %s must reuse the same objects: %+v", name, objs)
		}
	}
	// The catalog moves on: the entry is upgraded ...
	version("2.0.0")
	resume("bumped")
	// ... and then removed altogether.
	if err := os.RemoveAll(entry); err != nil {
		t.Fatal(err)
	}
	resume("gone")
	if _, err := h.eng.Create(ctx, CreateRequest{Template: "slow-nginx", Name: "fresh"}); code(err) != pdr.CodeTemplateNotFound {
		t.Fatalf("a new instance of a removed template must be E207: %v", err)
	}
	if _, err := h.eng.Create(ctx, CreateRequest{Template: "other", Name: "gone"}); code(err) != pdr.CodeTemplateNotFound {
		t.Fatalf("another template under a taken name resolves against the catalog: %v", err)
	}
}

// A path-based delivery create (`up DIR --mode delivery`) that failed once
// durable resumes from its snapshot too: after the directory changed its
// version, and after it is gone. A directory that now declares another
// template is another lab, refused.
func TestFailedPathDeliveryCreateResumesFromItsSnapshot(t *testing.T) {
	h := newHarness(t)
	t.Setenv(runtime.EnvFakeReadyDelay, "10s")
	h.open()
	ctx := context.Background()
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool { return false }
	dirs := map[string]string{}
	rewrite := func(dir, old, new string) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, "lab.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		body := strings.Replace(string(raw), old, new, 1)
		if body == string(raw) {
			t.Fatalf("fixture changed; update the test: %q not found", old)
		}
		if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"bumped", "vanished", "renamed"} {
		dir := filepath.Join(t.TempDir(), "slow")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		writeFixture(t, dir, "budget: 200ms")
		rewrite(dir, "metadata: { name: slow-nginx }", "metadata: { name: slow-nginx, version: 1.0.0 }")
		dirs[name] = dir
		job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: name, Mode: "delivery"})
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if j := h.wait(job.ID); j.State != state.JobFailed {
			t.Fatalf("first create of %s should fail: %+v", name, j)
		}
	}
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool { return true }
	resume := func(name string) {
		t.Helper()
		job, err := h.eng.Create(ctx, CreateRequest{Path: dirs[name], Name: name, Mode: "delivery"})
		if err != nil {
			t.Fatalf("resume %s: %v", name, err)
		}
		if j := h.wait(job.ID); j.State != state.JobSucceeded {
			t.Fatalf("resumed create of %s: %+v", name, j)
		}
		inst, err := h.store.GetInstance(name)
		if err != nil || inst.Stage != state.StageReady || inst.Version != "1.0.0" || inst.Mode != state.ModeDelivery {
			t.Fatalf("%s after resume must be ready at the admitted version: %+v %v", name, inst, err)
		}
	}
	rewrite(dirs["bumped"], "version: 1.0.0", "version: 2.0.0")
	resume("bumped")
	if err := os.RemoveAll(dirs["vanished"]); err != nil {
		t.Fatal(err)
	}
	resume("vanished")
	rewrite(dirs["renamed"], "name: slow-nginx", "name: other-nginx")
	err := func() error {
		_, err := h.eng.Create(ctx, CreateRequest{Path: dirs["renamed"], Name: "renamed", Mode: "delivery"})
		return err
	}()
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != pdr.CodeInstanceExists || !strings.Contains(pe.Cause, "other-nginx") {
		t.Fatalf("a directory declaring another template is another lab: %v", err)
	}
	// Without --mode delivery the same directory is an authoring request:
	// modes never switch in place.
	if _, err := h.eng.Create(ctx, CreateRequest{Path: dirs["bumped"], Name: "bumped"}); code(err) != pdr.CodeInstanceExists {
		t.Fatalf("an authoring request against a delivery instance must be E200: %v", err)
	}
	// A missing directory with no instance behind it is still not a template.
	if _, err := h.eng.Create(ctx, CreateRequest{Path: dirs["vanished"], Name: "fresh", Mode: "delivery"}); code(err) != pdr.CodeTemplateNotFound {
		t.Fatalf("a missing directory for a new instance must be E207: %v", err)
	}
}

// Shutdown stops a job in flight at its checkpoint: the goroutine ends
// before the caller closes the store and runtime, the record stays
// running (no failure is invented), and the next engine resumes it.
func TestShutdownInterruptsJobsAtACheckpoint(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.opts.Probe = func(context.Context, string, int) bool { return false }
	job, err := h.eng.Create(ctx, CreateRequest{Path: readinessFixture(t, "30s", ""), Name: "stop"})
	if err != nil {
		t.Fatal(err)
	}
	parked := time.Now().Add(5 * time.Second)
	for {
		j, _ := h.store.GetJob(job.ID)
		if j != nil && strings.HasPrefix(j.Stage, "waiting for") {
			break
		}
		if time.Now().After(parked) {
			t.Fatalf("the job never reached its probe loop: %+v", j)
		}
		time.Sleep(20 * time.Millisecond)
	}
	sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	begin := time.Now()
	if err := h.eng.Shutdown(sctx); err != nil {
		t.Fatalf("shutdown must stop the job at its checkpoint: %v", err)
	}
	if time.Since(begin) > 2*time.Second {
		t.Fatalf("shutdown waited %s on a job that ignores cancellation", time.Since(begin))
	}
	if h.eng.isRunning(job.ID) {
		t.Fatal("the job goroutine must be gone before the dependencies close")
	}
	j, _ := h.store.GetJob(job.ID)
	if j == nil || j.State != state.JobRunning {
		t.Fatalf("an interrupted job keeps its running record: %+v", j)
	}
	events, _ := h.store.ListEvents(job.ID)
	interrupted := false
	for _, ev := range events {
		if ev.Step == "job" && ev.Status == "interrupted" {
			interrupted = true
		}
		if ev.Step == "job" && ev.Status == "failed" {
			t.Fatalf("no failure is invented for a stopped engine: %+v", events)
		}
	}
	if !interrupted {
		t.Fatalf("the journal must say the engine stopped: %+v", events)
	}
	if svcs, _ := h.store.ListServices("stop"); len(svcs) != 1 || svcs[0].Error != "" {
		t.Fatalf("an interrupted step is not the service's error: %+v", svcs)
	}
	// The next engine resumes it.
	h.open()
	h.eng.opts.Probe = func(context.Context, string, int) bool { return true }
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("the resumed job: %+v", j)
	}
	if inst, _ := h.store.GetInstance("stop"); inst == nil || inst.Stage != state.StageReady {
		t.Fatalf("instance after resume: %+v", inst)
	}
}

// A recorded healthy is kept by a resumed job only inside the budget that
// applies now: a budget shortened while the engine was down below the time
// the service took is a deadline the old green fell after, so the resumed
// job re-judges it (and misses); one lengthened still covers it (plan S4
// Review round 23).
func TestResumedJobRejudgesAShortenedBudget(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dirs := map[string]string{}
	for _, name := range []string{"short", "long"} {
		dir := readinessFixture(t, "5s", "")
		dirs[name] = dir
		job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: name})
		if err != nil {
			t.Fatal(err)
		}
		if j := h.wait(job.ID); j.State != state.JobSucceeded {
			t.Fatalf("create %s: %+v", name, j)
		}
		// The engine died after the service was recorded healthy but before
		// the job's own record landed.
		j, _ := h.store.GetJob(job.ID)
		j.State, j.Stage, j.Finished = state.JobRunning, "waiting for web (typically 5s)", nil
		_ = h.store.PutJob(*j)
	}
	rebudget := func(dir, to string) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, "lab.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		edited := strings.Replace(string(raw), "budget: 5s }", "budget: "+to+" }", 1)
		if edited == string(raw) {
			t.Fatalf("fixture budget line changed; update the test: %s", raw)
		}
		if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The fake takes 200ms to answer: a 1ms budget is one the recorded
	// healthy fell after; 10s still covers it.
	rebudget(dirs["short"], "1ms")
	rebudget(dirs["long"], "10s")
	h.open()
	h.eng.opts.Probe = func(context.Context, string, int) bool { return true }
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ := h.store.ListJobs("short")
	if j := h.wait(jobs[0].ID); j.State != state.JobFailed || !strings.Contains(errText(j), pdr.CodeReadinessBudget) || !strings.Contains(errText(j), "1ms") {
		t.Fatalf("a healthy proven after the budget that applies now must be re-judged and miss: %+v", j)
	}
	jobs, _ = h.store.ListJobs("long")
	if j := h.wait(jobs[0].ID); j.State != state.JobSucceeded {
		t.Fatalf("a lengthened budget still covers the recorded healthy: %+v", j)
	}
	events, _ := h.store.ListEvents(jobs[0].ID)
	kept := false
	for _, ev := range events {
		if ev.Step == "healthy" && strings.Contains(ev.Detail, "already recorded healthy") {
			kept = true
		}
	}
	if !kept {
		t.Fatalf("the journal must say the readiness was kept: %+v", events)
	}
}

// A recorded healthy is kept by a resumed job only under the probe
// contract it was proven with: an authoring job re-reads its directory on
// resume, and a probe edited while the engine was down is re-judged.
func TestResumedJobReprobesChangedReadiness(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := readinessFixture(t, "5s", "")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "rr"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	// The engine died after the service was recorded healthy but before
	// the job's own record landed ...
	j, _ := h.store.GetJob(job.ID)
	j.State, j.Stage, j.Finished = state.JobRunning, "waiting for web (typically 5s)", nil
	_ = h.store.PutJob(*j)
	// ... and the author changed the probe while it was down.
	raw, err := os.ReadFile(filepath.Join(dir, "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(raw), "path: /,", "path: /ready,", 1)
	if edited == string(raw) {
		t.Fatalf("fixture probe line changed; update the test: %s", raw)
	}
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	h.open()
	var mu sync.Mutex
	var probed []string
	h.eng.opts.Probe = func(_ context.Context, url string, _ int) bool {
		mu.Lock()
		probed = append(probed, url)
		mu.Unlock()
		return true
	}
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("resumed job: %+v", j)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(probed) == 0 || !strings.HasSuffix(probed[len(probed)-1], "/ready") {
		t.Fatalf("the changed probe must be run: %v", probed)
	}
	events, _ := h.store.ListEvents(job.ID)
	for _, ev := range events {
		if ev.Step == "healthy" && strings.Contains(ev.Detail, "already recorded healthy") {
			t.Fatalf("a healthy proven under the old probe must not be kept: %+v", events)
		}
	}
	if svcs, _ := h.store.ListServices("rr"); len(svcs) != 1 || svcs[0].Stage != state.StageReady || svcs[0].Readiness == "" {
		t.Fatalf("healthy under the new contract, recorded with it: %+v", svcs)
	}
}

// A create request is one source: template and path are alternatives
// (API §7.1), and a request naming both is refused with PDR-E212 before
// anything is planned or recorded.
func TestCreateRefusesBothTemplateAndPath(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, err := h.eng.Create(ctx, CreateRequest{Template: "hello-nginx", Path: fixture, Name: "both"})
	if code(err) != pdr.CodeCreateRequest {
		t.Fatalf("both sources must be refused with E212: %v", err)
	}
	if _, err := h.store.GetInstance("both"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("nothing may be recorded: %v", err)
	}
	if jobs, _ := h.store.ListJobs("both"); len(jobs) != 0 {
		t.Fatalf("no job may be recorded: %+v", jobs)
	}
}

// A generated name that is already taken is a collision, never the
// instance the caller meant: the create draws again and never resumes or
// refuses a lab nobody asked about.
func TestGeneratedNamesAvoidCollisions(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	suffixes := []string{"aaaaaaaa", "aaaaaaaa", "aaaaaaaa", "bbbbbbbb"}
	orig := nameSuffix
	t.Cleanup(func() { nameSuffix = orig })
	nameSuffix = func() string {
		s := suffixes[0]
		if len(suffixes) > 1 {
			suffixes = suffixes[1:]
		}
		return s
	}
	first, err := h.eng.Create(ctx, CreateRequest{Path: fixture})
	if err != nil {
		t.Fatal(err)
	}
	if first.Instance != "hello-nginx-aaaaaaaa" {
		t.Fatalf("generated name: %s", first.Instance)
	}
	h.wait(first.ID)
	second, err := h.eng.Create(ctx, CreateRequest{Path: fixture})
	if err != nil {
		t.Fatalf("a collision must be retried, not refused: %v", err)
	}
	if second.Instance != "hello-nginx-bbbbbbbb" {
		t.Fatalf("the colliding draws must be skipped: %s", second.Instance)
	}
	if j := h.wait(second.ID); j.State != state.JobSucceeded {
		t.Fatalf("second create: %+v", j)
	}
	if jobs, _ := h.store.ListJobs("hello-nginx-aaaaaaaa"); len(jobs) != 1 {
		t.Fatalf("the first instance must be untouched by the collision: %+v", jobs)
	}
	// Names stay DNS labels of at most 24 characters whatever the template is called.
	if n := generateName("a-very-long-template-name-indeed"); len(n) > 24 || !nameRe.MatchString(n) {
		t.Fatalf("generated name %q breaks the label rule", n)
	}
}

// A request that names no source, or a mode that is neither authoring nor
// delivery, is a malformed create request (PDR-E212) — never a missing
// template or a bad name.
func TestMalformedCreateRequestsAreE212(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.eng.Create(ctx, CreateRequest{}); code(err) != pdr.CodeCreateRequest {
		t.Fatalf("no source must be E212: %v", err)
	}
	if _, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "modey", Mode: "weird"}); code(err) != pdr.CodeCreateRequest {
		t.Fatalf("an unknown mode must be E212: %v", err)
	}
	if _, err := h.store.GetInstance("modey"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("nothing may be recorded: %v", err)
	}
}

// The exclusive slot survives concurrent handlers: of N simultaneous
// destroys exactly one is accepted; of N simultaneous creates under one
// name exactly one instance and job exist.
func TestExclusiveSlotUnderConcurrency(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	const n = 12
	type result struct {
		job *state.Job
		err error
	}
	results := make(chan result, n)
	for i := 0; i < n; i++ {
		go func() {
			job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "cc"})
			results <- result{job, err}
		}()
	}
	var created *state.Job
	for i := 0; i < n; i++ {
		r := <-results
		if r.err == nil {
			if created != nil {
				t.Fatalf("two creates accepted: %s and %s", created.ID, r.job.ID)
			}
			created = r.job
		} else if code(r.err) != pdr.CodeInstanceExists {
			t.Fatalf("unexpected error: %v", r.err)
		}
	}
	if created == nil {
		t.Fatal("no create accepted")
	}
	if jobs, _ := h.store.ListJobs("cc"); len(jobs) != 1 {
		t.Fatalf("jobs after concurrent create: %+v", jobs)
	}
	h.wait(created.ID)

	for i := 0; i < n; i++ {
		go func() {
			job, err := h.eng.Destroy(ctx, "cc", "cc")
			results <- result{job, err}
		}()
	}
	var destroyed *state.Job
	for i := 0; i < n; i++ {
		r := <-results
		if r.err == nil {
			if destroyed != nil {
				// Two acceptances are two different bugs, and the message
				// must say which: a hole in the exclusive slot, or a first
				// destroy that failed — which a second may legitimately
				// retry (the repair path in Destroy). Without the first
				// job's own record, a failure here is unactionable.
				t.Fatalf("two destroys accepted: %s (%s) and %s (%s)",
					destroyed.ID, outcomeOf(h, destroyed.ID), r.job.ID, outcomeOf(h, r.job.ID))
			}
			destroyed = r.job
		} else if code(r.err) != pdr.CodeInstanceBusy && code(r.err) != pdr.CodeInstanceNotFound {
			t.Fatalf("unexpected error: %v", r.err)
		}
	}
	if destroyed == nil {
		t.Fatal("no destroy accepted")
	}
	h.wait(destroyed.ID)
}

// No readiness declared → the ladder stops at alive: nothing is probed on
// a guess, the job still succeeds.
func TestNoReadinessStopsAtAlive(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: bare, version: 1.0.0 }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
`
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "bare"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	inst, _ := h.store.GetInstance("bare")
	if inst.Stage != state.StageAlive {
		t.Fatalf("stage %q, want alive", inst.Stage)
	}
	events, _ := h.store.ListEvents(job.ID)
	var skipped bool
	for _, ev := range events {
		if ev.Step == "healthy" && ev.Status == "skipped" {
			skipped = true
		}
	}
	if !skipped {
		t.Fatalf("journal lacks the skipped-healthy line: %+v", events)
	}
}

// A retried create after the author changed the service replaces the
// stale container instead of resuming it.
func TestRetryReplacesChangedContainer(t *testing.T) {
	h := newHarness(t)
	t.Setenv(runtime.EnvFakeReadyDelay, "10s")
	h.open()
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool { return false }
	ctx := context.Background()
	dir := t.TempDir()
	write := func(greeting string) {
		body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: retry, version: 1.0.0 }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    env: { GREETING: "` + greeting + `" }
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 200ms }
`
		if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("first")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "retry"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed {
		t.Fatalf("first create should fail: %+v", j)
	}
	first := h.fake.Spec("pdr-retry-web")
	firstID, _ := h.fake.Inspect(ctx, "pdr-retry-web")
	write("second")
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool { return true }
	job2, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "retry"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job2.ID); j.State != state.JobSucceeded {
		t.Fatalf("retry: %+v", j)
	}
	second := h.fake.Spec("pdr-retry-web")
	secondID, _ := h.fake.Inspect(ctx, "pdr-retry-web")
	if first.Labels[runtime.LabelSpec] == second.Labels[runtime.LabelSpec] || firstID.ID == secondID.ID {
		t.Fatal("changed env must replace the container")
	}
	raw, _ := os.ReadFile(second.EnvFile)
	if string(raw) != "GREETING=second\n" {
		t.Fatalf("env after retry: %q", raw)
	}
	svcs, _ := h.store.ListServices("retry")
	if svcs[0].ContainerID != secondID.ID {
		t.Fatalf("state carries the old container id")
	}
}

// The leftover sweep applies the ownership rule too: a foreign object
// wearing the instance label stops the destroy, named.
func TestDestroySweepRefusesForeignLabeledObjects(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, _ := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "sw"})
	h.wait(job.ID)
	image := "docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609"
	if _, err := h.fake.Create(ctx, runtime.ContainerSpec{Name: "pdr-sw-extra", Image: image, Labels: map[string]string{runtime.LabelInstance: "sw"}}); err != nil {
		t.Fatal(err)
	}
	d, err := h.eng.Destroy(ctx, "sw", "sw")
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(d.ID); j.State != state.JobFailed || !strings.Contains(errText(j), "destroy refused") {
		t.Fatalf("sweep must refuse the foreign container: %+v", j)
	}
	if st, _ := h.fake.Inspect(ctx, "pdr-sw-extra"); st == nil {
		t.Fatal("foreign container removed by the sweep")
	}
	if _, err := h.store.GetInstance("sw"); err != nil {
		t.Fatal("state deleted despite the refusal")
	}
}

// Accepting a EULA injects its environment (spec 0003 §7).
func TestAcceptedEULAEnvReachesTheContainer(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: licensed, version: 1.0.0 }
licenses: [acme-terms]
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    env: { PLAIN: "1" }
    eula: { id: acme-terms, url: "https://example.com/terms", env: { ACCEPT_ACME_TERMS: "yes" } }
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
`
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644)
	if _, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "lic2"}); code(err) != pdr.CodeLicenseRequired {
		t.Fatalf("gate: %v", err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "lic2", AcceptLicenses: []string{"acme-terms"}})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	raw, _ := os.ReadFile(h.fake.Spec("pdr-lic2-web").EnvFile)
	if string(raw) != "ACCEPT_ACME_TERMS=yes\nPLAIN=1\n" {
		t.Fatalf("env: %q", raw)
	}
}

// A retry refreshes plan-derived service facts (image, readiness timing)
// and removes services the template no longer declares.
func TestRetryRefreshesPlanAndRemovesStaleServices(t *testing.T) {
	h := newHarness(t)
	t.Setenv(runtime.EnvFakeReadyDelay, "10s")
	h.open()
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool { return false }
	ctx := context.Background()
	dir := t.TempDir()
	const imgA = "docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609"
	const imgB = "docker.io/library/nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	write := func(image string, extra bool, budget string) {
		t.Helper()
		body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: shifting, version: 1.0.0 }
services:
  web:
    image: ` + image + `
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: ` + budget + ` }
`
		if extra {
			body += `  extra:
    image: ` + imgA + `
    endpoints: [ { purpose: ui, port: 80 } ]
`
		}
		if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(imgA, true, "200ms")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "shift"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed {
		t.Fatalf("first create should fail: %+v", j)
	}
	if st, _ := h.fake.Inspect(ctx, "pdr-shift-extra"); st == nil {
		t.Fatal("extra service should exist after the first attempt")
	}
	// The author changes the image, the budget, and drops the extra service.
	write(imgB, false, "5s")
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool { return true }
	job2, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "shift"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job2.ID); j.State != state.JobSucceeded {
		t.Fatalf("retry: %+v", j)
	}
	svcs, _ := h.store.ListServices("shift")
	if len(svcs) != 1 || svcs[0].Name != "web" || svcs[0].Image != imgB || svcs[0].Budget != "5s" {
		t.Fatalf("services after retry: %+v", svcs)
	}
	if st, _ := h.fake.Inspect(ctx, "pdr-shift-extra"); st != nil {
		t.Fatal("stale service container survived the retry")
	}
	if spec := h.fake.Spec("pdr-shift-web"); spec == nil || spec.Image != imgB {
		t.Fatalf("container not recreated from the new image: %+v", spec)
	}
	// A stale service whose container is foreign stops the retry, named:
	// a leftover row from an earlier attempt, its container replaced by
	// someone else's, and a failed job so a retry is allowed.
	_ = h.store.PutService(state.Service{Instance: "shift", Name: "extra", Image: imgA, Container: "pdr-shift-extra"})
	if _, err := h.fake.Create(ctx, runtime.ContainerSpec{Name: "pdr-shift-extra", Image: imgA, Labels: map[string]string{"com.example/owner": "else"}}); err != nil {
		t.Fatal(err)
	}
	_ = h.store.PutJob(state.Job{ID: "job_failed_shift", Kind: "create", Instance: "shift", State: state.JobFailed, Stage: "failed", Started: time.Now()})
	job4, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "shift"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job4.ID); j.State != state.JobFailed || !strings.Contains(errText(j), "refused") {
		t.Fatalf("foreign stale container must stop the retry: %+v", j)
	}
	if st, _ := h.fake.Inspect(ctx, "pdr-shift-extra"); st == nil {
		t.Fatal("foreign container was removed")
	}
}

// An instance recorded without any job (a crash between the two writes)
// is recovered by the next up; a job without an instance fails harmlessly
// and leaves the name free.
func TestCrashWindowsAroundCreateAreRecoverable(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	abs := mustAbs(t, fixture)
	_ = h.store.PutInstance(state.Instance{Name: "orphan", Template: "hello-nginx", Version: "0.1.0", Mode: state.ModeAuthoring, Source: abs, Created: now, Updated: now})
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "orphan"})
	if err != nil {
		t.Fatalf("job-less instance must be resumable: %v", err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("recovered create: %+v", j)
	}
	// Job first: a queued create whose instance was never written.
	_ = h.store.PutJob(state.Job{ID: "job_ghost", Kind: "create", Instance: "ghost", State: state.JobQueued, Stage: "queued", Started: now})
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if j := h.wait("job_ghost"); j.State != state.JobFailed || !strings.Contains(errText(j), "PDR-E202") {
		t.Fatalf("ghost job: %+v", j)
	}
	again, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "ghost"})
	if err != nil {
		t.Fatalf("the name must stay free: %v", err)
	}
	if j := h.wait(again.ID); j.State != state.JobSucceeded {
		t.Fatalf("create after the ghost job: %+v", j)
	}
}

// Store faults are never read as "absent": create refuses to upsert and
// destroy refuses to declare victory.
func TestStoreFaultsAreNotAbsence(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, _ := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "sf"})
	h.wait(job.ID)
	faulty := &faultyStore{Store: h.store}
	h.eng.opts.Store = faulty
	faulty.set(func(f *faultyStore) { f.fail = true })
	if _, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "sf"}); err == nil || !strings.Contains(err.Error(), "look up instance") {
		t.Fatalf("create on a store fault: %v", err)
	}
	if _, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "other"}); err == nil {
		t.Fatal("create must not proceed on a store fault")
	}
	if _, err := h.eng.Destroy(ctx, "sf", "sf"); err == nil || code(err) == pdr.CodeInstanceNotFound || !strings.Contains(err.Error(), "look up instance") {
		t.Fatalf("destroy admission on a store fault must not answer absence: %v", err)
	}
	if _, err := h.eng.View("sf", Socket); err == nil || code(err) == pdr.CodeInstanceNotFound || !strings.Contains(err.Error(), "look up instance") {
		t.Fatalf("status on a store fault must not answer absence: %v", err)
	}
	faulty.set(func(f *faultyStore) { f.failGetJob = true })
	if _, err := h.eng.Job(job.ID, Socket); err == nil || code(err) == pdr.CodeInstanceNotFound || !strings.Contains(err.Error(), "look up job") {
		t.Fatalf("job lookup on a store fault must not answer absence: %v", err)
	}
	faulty.set(func(f *faultyStore) { f.failGetJob = false })
	if _, err := h.eng.Job("job_nope", Socket); code(err) != pdr.CodeInstanceNotFound {
		t.Fatalf("a missing job is still not found: %v", err)
	}
	faulty.set(func(f *faultyStore) { f.fail = false })
	// The destroy job's own lookup — the second of the instance from here,
	// after the admission's — waits until the fault is armed, so the job
	// cannot finish in the millisecond before the flip (the local gate of round 44 saw it do exactly that under the race detector's load; the order the test asserts is now the order that runs).
	var lookups atomic.Int32
	armed := make(chan struct{})
	faulty.set(func(f *faultyStore) {
		f.onGetInstance = func(name string) {
			if name == "sf" && lookups.Add(1) == 2 {
				<-armed
			}
		}
	})
	d, err := h.eng.Destroy(ctx, "sf", "sf")
	if err != nil {
		t.Fatal(err)
	}
	faulty.set(func(f *faultyStore) { f.fail = true })
	close(armed)
	if j := h.wait(d.ID); j.State != state.JobFailed || !strings.Contains(errText(j), "look up instance") {
		t.Fatalf("destroy on a store fault must fail: %+v", j)
	}
	faulty.set(func(f *faultyStore) { f.fail = false })
	if st, _ := h.fake.Inspect(ctx, "pdr-sf-web"); st == nil {
		t.Fatal("destroy removed containers despite the fault")
	}
	if _, err := h.store.GetInstance("sf"); err != nil {
		t.Fatal("instance deleted despite the fault")
	}
}

// faultyStore injects transient faults; flags are set through set() so a
// test may flip them while a job goroutine is reading.
type faultyStore struct {
	state.Store
	mu              sync.Mutex
	fail            bool // GetInstance faults
	failActive      bool // ActiveJob faults
	failPutInstance bool // PutInstance faults
	// failPutInstanceIf faults the instance writes it returns true for.
	failPutInstanceIf func(state.Instance) bool
	failListServices  bool // ListServices faults
	failListResults   bool // ListCheckpointResults faults
	failLatestSeq     bool // LatestAuditSeq faults
	// failListResultsFrom faults ListCheckpointResults from the nth call
	// on (1 is the first). A reconcile reads the results more than once,
	// so a test that wants the *evaluation's* read has to say which.
	failListResultsFrom int
	listResults         int
	failListJobs        bool // ListJobs faults
	failGetJob          bool // GetJob faults
	// failAppendEvent faults the journal writes it returns true for.
	failAppendEvent func(state.Event) bool
	// failPutJob faults the writes it returns true for.
	failPutJob func(state.Job) bool
	// failPutService faults the service writes it returns true for.
	failPutService func(state.Service) bool
	// onGetInstance runs before each instance lookup (tests that park a
	// caller inside its lookup).
	onGetInstance func(name string)
	// onActiveJob and onDeleteInstance run before those calls (tests that
	// park a caller between an admission's two reads, or a job before
	// its last step).
	onActiveJob      func(name string)
	onDeleteInstance func(name string)
}

var errLocked = errors.New("database is locked (transient)")

func (f *faultyStore) set(fn func(f *faultyStore)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *faultyStore) faults(fn func(f *faultyStore) bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fn(f)
}

func (f *faultyStore) GetInstance(name string) (*state.Instance, error) {
	f.mu.Lock()
	hook := f.onGetInstance
	f.mu.Unlock()
	if hook != nil {
		hook(name)
	}
	if f.faults(func(f *faultyStore) bool { return f.fail }) {
		return nil, errLocked
	}
	return f.Store.GetInstance(name)
}

func (f *faultyStore) DeleteInstance(name string) error {
	f.mu.Lock()
	hook := f.onDeleteInstance
	f.mu.Unlock()
	if hook != nil {
		hook(name)
	}
	return f.Store.DeleteInstance(name)
}

func (f *faultyStore) ActiveJob(name string) (*state.Job, error) {
	f.mu.Lock()
	hook := f.onActiveJob
	f.mu.Unlock()
	if hook != nil {
		hook(name)
	}
	if f.faults(func(f *faultyStore) bool { return f.failActive }) {
		return nil, errLocked
	}
	return f.Store.ActiveJob(name)
}

func (f *faultyStore) PutInstance(inst state.Instance) error {
	if f.faults(func(f *faultyStore) bool {
		return f.failPutInstance || (f.failPutInstanceIf != nil && f.failPutInstanceIf(inst))
	}) {
		return errLocked
	}
	return f.Store.PutInstance(inst)
}

func (f *faultyStore) AppendEvent(ev state.Event) error {
	if f.faults(func(f *faultyStore) bool { return f.failAppendEvent != nil && f.failAppendEvent(ev) }) {
		return errLocked
	}
	return f.Store.AppendEvent(ev)
}

func (f *faultyStore) GetJob(id string) (*state.Job, error) {
	if f.faults(func(f *faultyStore) bool { return f.failGetJob }) {
		return nil, errLocked
	}
	return f.Store.GetJob(id)
}

func (f *faultyStore) ListJobs(instance string) ([]state.Job, error) {
	if f.faults(func(f *faultyStore) bool { return f.failListJobs }) {
		return nil, errLocked
	}
	return f.Store.ListJobs(instance)
}

func (f *faultyStore) ListServices(instance string) ([]state.Service, error) {
	if f.faults(func(f *faultyStore) bool { return f.failListServices }) {
		return nil, errLocked
	}
	return f.Store.ListServices(instance)
}

func (f *faultyStore) LatestAuditSeq() (int64, error) {
	if f.faults(func(f *faultyStore) bool { return f.failLatestSeq }) {
		return 0, errLocked
	}
	return f.Store.LatestAuditSeq()
}

func (f *faultyStore) ListCheckpointResults(instance string) ([]state.CheckpointResult, error) {
	if f.faults(func(f *faultyStore) bool {
		f.listResults++
		return f.failListResults || (f.failListResultsFrom > 0 && f.listResults >= f.failListResultsFrom)
	}) {
		return nil, errLocked
	}
	return f.Store.ListCheckpointResults(instance)
}

func (f *faultyStore) PutService(svc state.Service) error {
	if f.faults(func(f *faultyStore) bool { return f.failPutService != nil && f.failPutService(svc) }) {
		return errLocked
	}
	return f.Store.PutService(svc)
}

func (f *faultyStore) PutJob(j state.Job) error {
	if f.faults(func(f *faultyStore) bool { return f.failPutJob != nil && f.failPutJob(j) }) {
		return errLocked
	}
	return f.Store.PutJob(j)
}

// A store that refuses the queued→running write stops the job before any
// runtime mutation; the failure is recorded and the name resumes.
func TestRunningTransitionFailureNeverTouchesTheRuntime(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	faulty := &faultyStore{Store: h.store, failPutJob: func(j state.Job) bool { return j.State == state.JobRunning }}
	h.eng.opts.Store = faulty
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "rt"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed || !strings.Contains(errText(j), "record job") {
		t.Fatalf("job must fail on the running write: %+v", j)
	}
	if st, _ := h.fake.Inspect(ctx, "pdr-rt-web"); st != nil {
		t.Fatal("a container was created without a durable running record")
	}
	if _, ok, _ := h.fake.InspectNetwork(ctx, "pdr-rt"); ok {
		t.Fatal("a network was created without a durable running record")
	}
	faulty.set(func(f *faultyStore) { f.failPutJob = nil })
	again, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "rt"})
	if err != nil {
		t.Fatalf("the failed create must resume: %v", err)
	}
	if j := h.wait(again.ID); j.State != state.JobSucceeded {
		t.Fatalf("resumed create: %+v", j)
	}
}

// A terminal write the store keeps refusing does not hold the slot: the
// engine reports the outcome it knows, refuses the next job while the
// store still faults, and lands the record once it can.
func TestLostTerminalWriteFreesTheSlot(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.finishRetry = time.Millisecond
	faulty := &faultyStore{Store: h.store, failPutJob: func(j state.Job) bool { return j.Finished != nil }}
	h.eng.opts.Store = faulty
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "lw"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("the engine knows the outcome: %+v", j)
	}
	if j, _ := h.store.GetJob(job.ID); j == nil || !j.Active() {
		t.Fatalf("precondition: the store still holds the job as active: %+v", j)
	}
	if v, _ := h.eng.View("lw", Socket); v.Ladder.InProgress {
		t.Fatal("the view must not show a finished job as in progress")
	}
	if _, err := h.eng.Destroy(ctx, "lw", "lw"); err == nil || !strings.Contains(err.Error(), "record job") {
		t.Fatalf("destroy must refuse while the record cannot land, never run beside a phantom: %v", err)
	}
	if active, _ := h.store.ActiveJob("lw"); active == nil || active.ID != job.ID {
		t.Fatalf("no destroy job may be recorded on the fault: %+v", active)
	}
	faulty.set(func(f *faultyStore) { f.failPutJob = nil })
	d, err := h.eng.Destroy(ctx, "lw", "lw")
	if err != nil {
		t.Fatalf("destroy once the store recovers: %v", err)
	}
	if j, _ := h.store.GetJob(job.ID); j == nil || j.State != state.JobSucceeded {
		t.Fatalf("the create record must land before the slot is reused: %+v", j)
	}
	if j := h.wait(d.ID); j.State != state.JobSucceeded {
		t.Fatalf("destroy: %+v", j)
	}
}

// A queued job whose instance write failed is retired before the name is
// reused — on the retry itself, not only on restart — so a later restart
// never launches it against the replacement instance.
func TestOrphanJobIsRetiredBeforeNameReuse(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	faulty := &faultyStore{Store: h.store, failPutInstance: true, failPutJob: func(j state.Job) bool { return j.State == state.JobFailed }}
	h.eng.opts.Store = faulty
	if _, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "orph"}); err == nil || !strings.Contains(err.Error(), "record instance") {
		t.Fatalf("create on an instance-write fault: %v", err)
	}
	orphan, _ := h.store.ActiveJob("orph")
	if orphan == nil || orphan.State != state.JobQueued {
		t.Fatalf("precondition: the orphan job stays queued in the store: %+v", orphan)
	}
	faulty.set(func(f *faultyStore) { f.failPutInstance, f.failPutJob = false, nil })
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "orph"})
	if err != nil {
		t.Fatalf("the name is free after the orphan is retired: %v", err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create after retirement: %+v", j)
	}
	if j, _ := h.store.GetJob(orphan.ID); j == nil || j.State != state.JobFailed || !strings.Contains(errText(j), "never driven") {
		t.Fatalf("the orphan must be retired as failed: %+v", j)
	}
	// A restart launches nothing for the orphan: the exclusive slot holds.
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ := h.store.ListJobs("orph")
	for _, j := range jobs {
		if j.Active() {
			t.Fatalf("a restart must not revive the orphan: %+v", j)
		}
	}
	if len(jobs) != 2 {
		t.Fatalf("exactly the orphan and the create: %d jobs", len(jobs))
	}
	// When the abandonment write itself lands, no orphan is left at all.
	h.eng.opts.Store = faulty
	faulty.set(func(f *faultyStore) { f.failPutInstance = true })
	if _, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "orph2"}); err == nil {
		t.Fatal("create must fail on the instance write")
	}
	if active, _ := h.store.ActiveJob("orph2"); active != nil {
		t.Fatalf("an abandoned job is failed at once: %+v", active)
	}
}

// The exclusive-slot lookup propagates store faults: a job is never
// started beside one the engine could not see.
func TestSlotLookupFaultsPropagate(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, _ := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "sl"})
	h.wait(job.ID)
	faulty := &faultyStore{Store: h.store, failActive: true}
	h.eng.opts.Store = faulty
	if _, err := h.eng.Destroy(ctx, "sl", "sl"); err == nil || !strings.Contains(err.Error(), "look up the active job") {
		t.Fatalf("destroy on a slot-lookup fault: %v", err)
	}
	if _, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "sl"}); err == nil || !strings.Contains(err.Error(), "look up the active job") {
		t.Fatalf("resume on a slot-lookup fault: %v", err)
	}
	if _, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "sl2"}); err == nil || !strings.Contains(err.Error(), "look up the active job") {
		t.Fatalf("create on a slot-lookup fault: %v", err)
	}
	jobs, _ := h.store.ListJobs("")
	if len(jobs) != 1 {
		t.Fatalf("no job may be recorded on a fault: %d", len(jobs))
	}
	if st, _ := h.fake.Inspect(ctx, "pdr-sl-web"); st == nil {
		t.Fatal("destroy ran despite the fault")
	}
}

// A service that stopped at alive with the job over renders as alive,
// never as initializing with a growing clock.
func TestTerminalAliveRendersAsAlive(t *testing.T) {
	started := time.Now().Add(-time.Hour)
	svc := state.Service{Name: "web", Stage: state.StageAlive, StartedAt: &started}
	if v := serviceView(svc, false, time.Now()); v.Word != "alive" || v.Context != "no readiness declared" {
		t.Fatalf("terminal alive: %+v", v)
	}
	if v := serviceView(svc, true, time.Now()); v.Word != "initializing" || !strings.HasPrefix(v.Context, "elapsed ") {
		t.Fatalf("active alive: %+v", v)
	}
	svc.Typical, svc.Budget = "5s", "1m"
	if v := serviceView(svc, false, time.Now()); v.Word != "alive" || v.Context != "" {
		t.Fatalf("terminal alive with readiness: %+v", v)
	}
}

// A container that exits (or vanishes) right after start is a failed
// step, named — never recorded as alive, never a succeeded job, and never
// a panic.
func TestContainerMustStayRunningAfterStart(t *testing.T) {
	for _, vanish := range []bool{false, true} {
		h := newHarness(t)
		ctx := context.Background()
		h.eng.opts.Runtime = &exitsAfterStart{Fake: h.fake, vanish: vanish}
		job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "ex"})
		if err != nil {
			t.Fatal(err)
		}
		j := h.wait(job.ID)
		want := "exited right after start"
		if vanish {
			want = "disappeared right after start"
		}
		if j.State != state.JobFailed || !strings.Contains(errText(j), want) {
			t.Fatalf("vanish=%v: %+v", vanish, j)
		}
		svcs, _ := h.store.ListServices("ex")
		if len(svcs) != 1 || svcs[0].Stage == state.StageAlive || svcs[0].Stage == state.StageHealthy {
			t.Fatalf("vanish=%v: the service must not be recorded alive: %+v", vanish, svcs)
		}
		if v, _ := h.eng.View("ex", Socket); v.Ladder.Stage == string(state.StageAlive) || v.Ladder.Stage == string(state.StageHealthy) {
			t.Fatalf("vanish=%v: ladder %+v", vanish, v.Ladder)
		}
		// With a runtime that keeps its containers up, the same name resumes.
		h.eng.opts.Runtime = h.fake
		again, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "ex"})
		if err != nil {
			t.Fatalf("vanish=%v: resume: %v", vanish, err)
		}
		if j := h.wait(again.ID); j.State != state.JobSucceeded {
			t.Fatalf("vanish=%v: resumed create: %+v", vanish, j)
		}
	}
}

// exitsAfterStart is a runtime whose containers stop (or disappear) the
// moment they are started.
type exitsAfterStart struct {
	*runtime.Fake
	vanish bool
}

func (r *exitsAfterStart) Start(ctx context.Context, name string) error {
	if err := r.Fake.Start(ctx, name); err != nil {
		return err
	}
	if r.vanish {
		return r.Fake.Remove(ctx, name)
	}
	return r.Fake.Stop(ctx, name, 0)
}

// A stage write the store refuses fails the step: a succeeded job with a
// stale stage would never be repaired, since neither up nor reconcile
// revisits a healthy lab. The failed create resumes to healthy.
func TestStageWriteFailureFailsTheJob(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	faulty := &faultyStore{Store: h.store, failPutService: func(s state.Service) bool { return s.Stage == state.StageHealthy }}
	h.eng.opts.Store = faulty
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "hw"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed || !strings.Contains(errText(j), "record healthy") {
		t.Fatalf("the healthy write fault must fail the job: %+v", j)
	}
	if v, _ := h.eng.View("hw", Socket); v.Ladder.Stage == string(state.StageHealthy) {
		t.Fatalf("a lab whose healthy write was refused is not healthy: %+v", v.Ladder)
	}
	faulty.set(func(f *faultyStore) { f.failPutService = nil })
	again, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "hw"})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if j := h.wait(again.ID); j.State != state.JobSucceeded {
		t.Fatalf("resumed create: %+v", j)
	}
	if v, _ := h.eng.View("hw", Socket); v.Ladder.Stage != string(state.StageReady) {
		t.Fatalf("after the resume: %+v", v.Ladder)
	}
}

// The instance-stage refresh is part of the step: a refused write fails
// the job instead of leaving a succeeded job over a stale ladder.
func TestStageRefreshFailureFailsTheJob(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	faulty := &faultyStore{Store: h.store, failPutInstanceIf: func(i state.Instance) bool { return i.Stage == state.StageHealthy }}
	h.eng.opts.Store = faulty
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "sr"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed || !strings.Contains(errText(j), "record stage") {
		t.Fatalf("the stage write fault must fail the job: %+v", j)
	}
	faulty.set(func(f *faultyStore) { f.failPutInstanceIf = nil })
	again, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "sr"})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if j := h.wait(again.ID); j.State != state.JobSucceeded {
		t.Fatalf("resumed create: %+v", j)
	}
	if inst, _ := h.store.GetInstance("sr"); inst.Stage != state.StageReady {
		t.Fatalf("after the resume: %+v", inst.Stage)
	}
}

// A declared probe whose port the runtime never bound on the host is a
// runtime failure — not the no-readiness case, never a silent alive.
func TestDeclaredProbeWithoutBindingFails(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.opts.Runtime = &noBinding{Fake: h.fake}
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "nb"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed || !strings.Contains(errText(j), "no host binding") || !strings.Contains(errText(j), pdr.CodeRuntimeFailed) {
		t.Fatalf("a declared probe without a binding must fail: %+v", j)
	}
	if svcs, _ := h.store.ListServices("nb"); len(svcs) != 1 || svcs[0].Stage == state.StageHealthy {
		t.Fatalf("never healthy without the probe: %+v", svcs)
	}
}

// noBinding is a runtime that publishes nothing on the host.
type noBinding struct{ *runtime.Fake }

func (r *noBinding) Inspect(ctx context.Context, name string) (*runtime.ContainerState, error) {
	st, err := r.Fake.Inspect(ctx, name)
	if st != nil {
		st.Ports = map[int]int{}
	}
	return st, err
}

// On restart, a running container under the lab's name that is not ours
// does not count as the lab running: the instance is reconciled, and the
// reconcile fails, named, at adoption.
func TestStartReconcilesForeignRunningContainer(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "fr"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	st, _ := h.fake.Inspect(ctx, "pdr-fr-web")
	image := st.Image
	h.open() // the engine is down
	_ = h.fake.Remove(ctx, "pdr-fr-web")
	if _, err := h.fake.Create(ctx, runtime.ContainerSpec{Name: "pdr-fr-web", Image: image, Labels: map[string]string{"com.example/owner": "else"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.fake.Start(ctx, "pdr-fr-web"); err != nil {
		t.Fatal(err)
	}
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ := h.store.ListJobs("fr")
	if len(jobs) == 0 || jobs[0].Kind != "reconcile" {
		t.Fatalf("a foreign running container must trigger reconcile: %+v", jobs)
	}
	if j := h.wait(jobs[0].ID); j.State != state.JobFailed || !strings.Contains(errText(j), "not managed by podaro") {
		t.Fatalf("reconcile must refuse the stranger, named: %+v", j)
	}
	if st, _ := h.fake.Inspect(ctx, "pdr-fr-web"); st == nil || !st.Running || st.Labels["com.example/owner"] != "else" {
		t.Fatal("the foreign container must be left alone")
	}
}

// A service-table fault at startup fails the start: an instance whose
// services cannot be listed is not "nothing to do".
func TestStartFailsWhenServicesCannotBeListed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "ls"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	h.open()
	h.eng.opts.Store = &faultyStore{Store: h.store, failListServices: true}
	if err := h.eng.Start(ctx); err == nil || !strings.Contains(err.Error(), "list services") {
		t.Fatalf("start must fail on a service-list fault: %v", err)
	}
}

// The runner's own instance lookup is not absence either: a store fault
// fails the job naming the fault (PDR-E204), never as "no such instance".
func TestRunnerInstanceLookupFaultIsNotAbsence(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = h.store.PutInstance(state.Instance{Name: "rl", Template: "hello-nginx", Version: "0.1.0", Mode: state.ModeAuthoring, Source: mustAbs(t, fixture), Created: now, Updated: now})
	_ = h.store.PutJob(state.Job{ID: "job_rl", Kind: "create", Instance: "rl", State: state.JobQueued, Stage: "queued", Started: now})
	faulty := &faultyStore{Store: h.store, fail: true}
	h.eng.opts.Store = faulty
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	j := h.wait("job_rl")
	if j.State != state.JobFailed || !strings.Contains(errText(j), "look up instance") || strings.Contains(errText(j), pdr.CodeInstanceNotFound) {
		t.Fatalf("a lookup fault must not read as absence: %+v", j)
	}
	if _, err := h.store.GetInstance("rl"); err != nil {
		t.Fatal("the instance must stay recorded")
	}
	if st, _ := h.fake.Inspect(ctx, "pdr-rl-web"); st != nil {
		t.Fatal("nothing may be created after a failed lookup")
	}
}

// Status never renders a settled lab over a job history it could not
// read: the view fails with the store error.
func TestViewPropagatesJobListFaults(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "vj"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	h.eng.opts.Store = &faultyStore{Store: h.store, failListJobs: true}
	if _, err := h.eng.View("vj", Socket); err == nil || !strings.Contains(err.Error(), "list jobs") {
		t.Fatalf("view on a job-list fault: %v", err)
	}
	if _, err := h.eng.Views(); err == nil || !strings.Contains(err.Error(), "list jobs") {
		t.Fatalf("views on a job-list fault: %v", err)
	}
	if _, err := h.eng.Events(job.ID, Socket); err != nil {
		t.Fatalf("the journal itself is readable: %v", err)
	}
}

// readinessFixture copies the hello-nginx fixture with its readiness
// timing rewritten (the fixture declares typical 5s, budget 1m).
func readinessFixture(t *testing.T, budget, interval string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "hello-nginx")
	if err := copyTree(fixture, dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "lab.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	old := "typical: 5s, budget: 1m }"
	if !strings.Contains(string(raw), old) {
		t.Fatalf("fixture readiness line changed; update the test: %s", raw)
	}
	repl := "typical: 5s, budget: " + budget
	if interval != "" {
		repl += ", interval: " + interval
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), old, repl+" }", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A probe that only turns green after the budget is a miss: the job
// fails with the readiness-budget code, never a late healthy.
func TestLateProbeSuccessIsRejected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.opts.PollInterval = 100 * time.Millisecond
	var first time.Time
	h.eng.opts.Probe = func(context.Context, string, int) bool {
		if first.IsZero() {
			first = time.Now()
		}
		return time.Since(first) >= 180*time.Millisecond
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: readinessFixture(t, "150ms", ""), Name: "late"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed || !strings.Contains(errText(j), pdr.CodeReadinessBudget) {
		t.Fatalf("a late success must miss the budget: %+v", j)
	}
	if svcs, _ := h.store.ListServices("late"); len(svcs) != 1 || svcs[0].Stage == state.StageHealthy {
		t.Fatalf("never healthy after the budget: %+v", svcs)
	}
}

// The probe runs at the declared interval, not the engine-wide default.
func TestDeclaredIntervalPacesTheProbe(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.opts.PollInterval = 20 * time.Millisecond
	var mu sync.Mutex
	var calls []time.Time
	h.eng.opts.Probe = func(context.Context, string, int) bool {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, time.Now())
		return len(calls) >= 3
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: readinessFixture(t, "1m", "300ms"), Name: "pace"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 3 {
		t.Fatalf("probe calls: %d", len(calls))
	}
	for i := 1; i < len(calls); i++ {
		if gap := calls[i].Sub(calls[i-1]); gap < 240*time.Millisecond {
			t.Fatalf("probe %d came %v after the previous one; the declared interval is 300ms", i, gap)
		}
	}
}

// A Start that fails its own validation launches nothing: the queued job
// stays queued for the next start and the runtime is untouched.
func TestStartLaunchesNothingWhenValidationFails(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "sv"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	now := time.Now().UTC()
	_ = h.store.PutInstance(state.Instance{Name: "sv2", Template: "hello-nginx", Version: "0.1.0", Mode: state.ModeAuthoring, Source: mustAbs(t, fixture), Created: now, Updated: now})
	_ = h.store.PutJob(state.Job{ID: "job_sv2", Kind: "create", Instance: "sv2", State: state.JobQueued, Stage: "queued", Started: now})
	h.open()
	h.eng.opts.Store = &faultyStore{Store: h.store, failListServices: true}
	if err := h.eng.Start(ctx); err == nil {
		t.Fatal("start must fail on the service-list fault")
	}
	if h.eng.isRunning("job_sv2") {
		t.Fatal("a failed start must launch nothing")
	}
	if j, _ := h.store.GetJob("job_sv2"); j == nil || j.State != state.JobQueued {
		t.Fatalf("the job stays queued for the next start: %+v", j)
	}
	if _, ok, _ := h.fake.InspectNetwork(ctx, "pdr-sv2"); ok {
		t.Fatal("the runtime must be untouched by a failed start")
	}
}

// The job re-applies the admission gates to the plan it re-reads: a
// license the instance never accepted, or an unrenderable need, fails
// the job before any runtime mutation — with Create's own envelopes.
func TestJobGatesTheReloadedPlan(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.opts.Library = lab.DirLibrary(filepath.Join("..", "lab", "testdata", "modules"))
	now := time.Now().UTC()
	aliases := mustAbs(t, filepath.Join("..", "lab", "testdata", "valid-aliases"))
	aliasPlan, _, err := lab.MakePlan(lab.PlanOptions{Options: lab.Options{Path: aliases, Library: h.eng.opts.Library}})
	if err != nil {
		t.Fatal(err)
	}
	_ = h.store.PutInstance(state.Instance{Name: "lic2", Template: aliasPlan.Template.Name, Version: aliasPlan.Template.Version, Mode: state.ModeAuthoring, Source: aliases, Created: now, Updated: now})
	_ = h.store.PutJob(state.Job{ID: "job_lic2", Kind: "create", Instance: "lic2", State: state.JobQueued, Stage: "queued", Started: now})
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if j := h.wait("job_lic2"); j.State != state.JobFailed || !strings.Contains(errText(j), pdr.CodeLicenseRequired) {
		t.Fatalf("an unaccepted license must fail the job: %+v", j)
	}
	if _, ok, _ := h.fake.InspectNetwork(ctx, "pdr-lic2"); ok {
		t.Fatal("nothing may be created before the gate")
	}
	// Accepting on the retry records the licence and the job proceeds past the gate.
	again, err := h.eng.Create(ctx, CreateRequest{Path: aliases, Name: "lic2", AcceptLicenses: []string{"custom-terms"}})
	if err != nil {
		t.Fatalf("resume with the licence accepted: %v", err)
	}
	if j := h.wait(again.ID); strings.Contains(errText(j), pdr.CodeLicenseRequired) {
		t.Fatalf("the accepted licence must pass the job's gate: %+v", j)
	}
	if inst, _ := h.store.GetInstance("lic2"); len(inst.Licenses) != 1 || inst.Licenses[0] != "custom-terms" {
		t.Fatalf("the acceptance must be recorded on the instance: %+v", inst.Licenses)
	}
	// A plan with secrets and files is rendered by the job (plan S6): the
	// small template's create runs to ready against the fake's products.
	// (An authoring record: a delivery record would need its pinned module
	// library beside it, D56/D63.)
	h.eng.opts.Library = lab.EmbeddedLibrary()
	_ = h.store.PutInstance(state.Instance{Name: "gp", Template: "grafana-prometheus-intro", Version: "1.0.0", Mode: state.ModeAuthoring, Source: mustAbs(t, filepath.Join("..", "..", "scenarios", "grafana-prometheus-intro")), Created: now, Updated: now})
	_ = h.store.PutJob(state.Job{ID: "job_gp", Kind: "create", Instance: "gp", State: state.JobQueued, Stage: "queued", Started: now})
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if j := h.wait("job_gp"); j.State != state.JobSucceeded {
		t.Fatalf("a plan with secrets and files is rendered and runs: %+v", j)
	}
	if inst, _ := h.store.GetInstance("gp"); inst.Stage != state.StageReady {
		t.Fatalf("the small template reaches ready on the fake: %+v", inst)
	}
}

// A refused journal write stops the job: the step after it never runs,
// the job fails naming the fault, and the retry re-walks and re-journals.
func TestJournalFaultStopsTheJob(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	faulty := &faultyStore{Store: h.store, failAppendEvent: func(ev state.Event) bool { return ev.Step == "pull" }}
	h.eng.opts.Store = faulty
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "jf"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed || !strings.Contains(errText(j), "journal job") {
		t.Fatalf("a journal fault must fail the job: %+v", j)
	}
	if st, _ := h.fake.Inspect(ctx, "pdr-jf-web"); st != nil {
		t.Fatal("the step after the refused journal line must not run")
	}
	faulty.set(func(f *faultyStore) { f.failAppendEvent = nil })
	again, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "jf"})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if j := h.wait(again.ID); j.State != state.JobSucceeded {
		t.Fatalf("resumed create: %+v", j)
	}
	events, _ := h.store.ListEvents(again.ID)
	steps := map[string]bool{}
	for _, ev := range events {
		steps[ev.Step] = true
	}
	for _, want := range []string{"network", "pull", "create", "alive", "healthy", "job"} {
		if !steps[want] {
			t.Fatalf("the resumed job's journal must carry %q: %+v", want, events)
		}
	}
}

// A resumed job keeps the deadline its container already had: an engine
// restart mid-wait grants no second budget.
func TestResumedJobKeepsItsDeadline(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	block := make(chan struct{})
	h.eng.opts.Probe = func(context.Context, string, int) bool { <-block; return false }
	dir := readinessFixture(t, "300ms", "")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "rd"})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		svcs, _ := h.store.ListServices("rd")
		if len(svcs) == 1 && svcs[0].Stage == state.StageAlive {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("service never reached alive: %+v", svcs)
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(400 * time.Millisecond) // past the 300ms budget, while the first engine is stuck in its probe
	h.open()                           // the engine restarts; the first one's goroutine stays parked in the probe
	h.eng.opts.Probe = func(context.Context, string, int) bool { return true }
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed || !strings.Contains(errText(j), pdr.CodeReadinessBudget) {
		t.Fatalf("the resumed job must keep its deadline: %+v", j)
	}
	close(block)
}

// A tracked directory whose metadata now names another template or
// version is not this instance's lab: the job refuses before any runtime
// mutation, and says what changed.
func TestJobRefusesAChangedIdentity(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = h.store.PutInstance(state.Instance{Name: "idc", Template: "hello-nginx", Version: "9.9.9", Mode: state.ModeAuthoring, Source: mustAbs(t, fixture), Created: now, Updated: now})
	_ = h.store.PutJob(state.Job{ID: "job_idc", Kind: "create", Instance: "idc", State: state.JobQueued, Stage: "queued", Started: now})
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	j := h.wait("job_idc")
	if j.State != state.JobFailed || !strings.Contains(errText(j), "now declares template hello-nginx@0.1.0") || !strings.Contains(errText(j), "9.9.9") {
		t.Fatalf("a changed identity must fail the job, named: %+v", j)
	}
	if _, ok, _ := h.fake.InspectNetwork(ctx, "pdr-idc"); ok {
		t.Fatal("nothing may be created for a lab that is not this instance's")
	}
}

// The probe cadence: the declared interval wins; a readiness block that
// declares none falls to the schema default (5s), which is also what a
// bare engine uses; Options.PollInterval only overrides that fallback.
func TestProbeIntervalDefaults(t *testing.T) {
	if got := probeInterval(&lab.Readiness{Interval: "300ms"}, 50*time.Millisecond); got != 300*time.Millisecond {
		t.Fatalf("declared interval: %v", got)
	}
	if got := probeInterval(&lab.Readiness{}, 50*time.Millisecond); got != 50*time.Millisecond {
		t.Fatalf("engine fallback: %v", got)
	}
	if got := probeInterval(&lab.Readiness{}, 0); got != DefaultProbeInterval || DefaultProbeInterval != 5*time.Second {
		t.Fatalf("schema default: %v", got)
	}
	if eng := New(Options{}); eng.opts.PollInterval != DefaultProbeInterval {
		t.Fatalf("a bare engine probes at the schema default, got %v", eng.opts.PollInterval)
	}
}

// An acceptance is recorded only for terms the plan presented: an id the
// plan does not declare is not stored, so a template that grows a
// license under that id later is gated, not waved through.
func TestOnlyPresentedLicensesAreRecorded(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "np", AcceptLicenses: []string{"custom-terms"}})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	if inst, _ := h.store.GetInstance("np"); len(inst.Licenses) != 0 {
		t.Fatalf("a license the plan never presented must not be recorded: %+v", inst.Licenses)
	}
	h.eng.opts.Library = lab.DirLibrary(filepath.Join("..", "lab", "testdata", "modules"))
	aliases := filepath.Join("..", "lab", "testdata", "valid-aliases")
	job, err = h.eng.Create(ctx, CreateRequest{Path: aliases, Name: "pp", AcceptLicenses: []string{"bogus", "custom-terms"}})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	if inst, _ := h.store.GetInstance("pp"); len(inst.Licenses) != 1 || inst.Licenses[0] != "custom-terms" {
		t.Fatalf("only the presented license is recorded: %+v", inst.Licenses)
	}
}

// The identity check comes before the gates: a directory that changed
// both its identity and its needs is refused for the identity, never
// with a request to accept terms for a lab this instance may not run.
func TestIdentityIsCheckedBeforeTheGates(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	// An authoring record: a delivery record would need its pinned module
	// library beside it (D56/D63); the check under test is mode-independent.
	_ = h.store.PutInstance(state.Instance{Name: "idg", Template: "grafana-prometheus-intro", Version: "0.0.0-other", Mode: state.ModeAuthoring, Source: mustAbs(t, filepath.Join("..", "..", "scenarios", "grafana-prometheus-intro")), Created: now, Updated: now})
	_ = h.store.PutJob(state.Job{ID: "job_idg", Kind: "create", Instance: "idg", State: state.JobQueued, Stage: "queued", Started: now})
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	j := h.wait("job_idg")
	if j.State != state.JobFailed || !strings.Contains(errText(j), "now declares template") || strings.Contains(errText(j), "plan step S6") {
		t.Fatalf("identity first: %+v", j)
	}
}

// The probe never sleeps past the deadline: a cadence longer than the
// remaining budget still settles the job when the budget expires.
func TestProbeSleepIsCappedAtTheDeadline(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.opts.Probe = func(context.Context, string, int) bool { return false }
	start := time.Now()
	job, err := h.eng.Create(ctx, CreateRequest{Path: readinessFixture(t, "150ms", "5s"), Name: "cap"})
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(job.ID)
	if j.State != state.JobFailed || !strings.Contains(errText(j), pdr.CodeReadinessBudget) {
		t.Fatalf("budget miss: %+v", j)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the job must settle at the budget, not after the 5s cadence: took %v", took)
	}
}

// Each probe attempt is bounded by the readiness deadline: a probe that
// connects and then stalls cannot hold the job past its budget.
func TestProbeAttemptIsBoundedByTheDeadline(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.opts.Probe = func(ctx context.Context, _ string, _ int) bool { <-ctx.Done(); return false }
	start := time.Now()
	job, err := h.eng.Create(ctx, CreateRequest{Path: readinessFixture(t, "150ms", "50ms"), Name: "stall"})
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(job.ID)
	if j.State != state.JobFailed || !strings.Contains(errText(j), pdr.CodeReadinessBudget) {
		t.Fatalf("budget miss: %+v", j)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("a stalled probe must not outlive the budget: took %v", took)
	}
}

// A destroy that removed the instance but could not land its own record
// is repaired by destroying again; a name that never existed stays not
// found, and the confirmation ceremony still applies.
func TestFailedDestroyIsRecoverable(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "rd2"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	faulty := &faultyStore{Store: h.store, failAppendEvent: func(ev state.Event) bool { return ev.Step == "state" }}
	h.eng.opts.Store = faulty
	d, err := h.eng.Destroy(ctx, "rd2", "rd2")
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(d.ID); j.State != state.JobFailed || !strings.Contains(errText(j), "journal job") {
		t.Fatalf("the refused journal line fails the destroy: %+v", j)
	}
	if _, err := h.store.GetInstance("rd2"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("the instance is already gone: %v", err)
	}
	faulty.set(func(f *faultyStore) { f.failAppendEvent = nil })
	if _, err := h.eng.Destroy(ctx, "rd2", "wrong"); code(err) != pdr.CodeDestroyConfirm {
		t.Fatalf("the ceremony still applies to a repair: %v", err)
	}
	again, err := h.eng.Destroy(ctx, "rd2", "rd2")
	if err != nil {
		t.Fatalf("a failed destroy must be repairable: %v", err)
	}
	if j := h.wait(again.ID); j.State != state.JobSucceeded {
		t.Fatalf("the repair lands the record: %+v", j)
	}
	if _, err := h.eng.Destroy(ctx, "rd2", "rd2"); code(err) != pdr.CodeInstanceNotFound {
		t.Fatalf("once repaired, the name is simply gone: %v", err)
	}
	if _, err := h.eng.Destroy(ctx, "never", "never"); code(err) != pdr.CodeInstanceNotFound {
		t.Fatalf("a name that never existed: %v", err)
	}
}

// A resumed job does not re-judge a readiness the store already records
// as proven on the same, still-running container: an earlier service's
// expired budget never fails a job whose later service kept it active.
func TestResumedJobKeepsRecordedHealth(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: readinessFixture(t, "300ms", ""), Name: "kh"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	// The engine died after the service was recorded healthy but before
	// the job's own record landed: the job reads running on restart.
	j, _ := h.store.GetJob(job.ID)
	j.State, j.Stage, j.Finished = state.JobRunning, "waiting for web (typically 5s)", nil
	_ = h.store.PutJob(*j)
	time.Sleep(400 * time.Millisecond) // well past the 300ms budget
	h.open()
	h.eng.opts.Probe = func(context.Context, string, int) bool { return false } // a re-probe would fail
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("a recorded healthy must survive the resume: %+v", j)
	}
	events, _ := h.store.ListEvents(job.ID)
	kept := false
	for _, ev := range events {
		if ev.Step == "healthy" && strings.Contains(ev.Detail, "already recorded healthy") {
			kept = true
		}
	}
	if !kept {
		t.Fatalf("the journal must say the readiness was kept, not re-probed: %+v", events)
	}
	if svcs, _ := h.store.ListServices("kh"); len(svcs) != 1 || svcs[0].Stage != state.StageReady {
		t.Fatalf("still ready (the kept healthy carried it up): %+v", svcs)
	}
}

// The destroy repair consults the engine's known outcome: a failed
// destroy whose terminal write the store refused (still "running" on
// disk) is repairable in the same process.
func TestDestroyRepairConsultsTheKnownOutcome(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.finishRetry = time.Millisecond
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "rd3"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	faulty := &faultyStore{Store: h.store,
		failAppendEvent: func(ev state.Event) bool { return ev.Step == "state" },
		failPutJob:      func(j state.Job) bool { return j.Finished != nil }}
	h.eng.opts.Store = faulty
	d, err := h.eng.Destroy(ctx, "rd3", "rd3")
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(d.ID); j.State != state.JobFailed {
		t.Fatalf("the engine knows the destroy failed: %+v", j)
	}
	if j, _ := h.store.GetJob(d.ID); j == nil || !j.Active() {
		t.Fatalf("precondition: the store still holds the destroy as active: %+v", j)
	}
	faulty.set(func(f *faultyStore) { f.failAppendEvent, f.failPutJob = nil, nil })
	again, err := h.eng.Destroy(ctx, "rd3", "rd3")
	if err != nil {
		t.Fatalf("the repair must be admitted from the known outcome: %v", err)
	}
	if j := h.wait(again.ID); j.State != state.JobSucceeded {
		t.Fatalf("the repair lands the record: %+v", j)
	}
	if j, _ := h.store.GetJob(d.ID); j == nil || j.State != state.JobFailed {
		t.Fatalf("the first destroy's record lands too: %+v", j)
	}
}

// Destroy's admission — the lookup, the repair decision (D53) and the
// slot — is one critical section: a repair for a name whose instance is
// gone cannot observe that state, yield to a create of the same name, and
// then destroy the replacement.
func TestDestroyAdmissionIsOneCriticalSection(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.finishRetry = time.Millisecond
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "rc"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	// A destroy that removed the instance but could not land its journal:
	// a failed destroy over a lab already gone — D53's repair case.
	faulty := &faultyStore{Store: h.store, failAppendEvent: func(ev state.Event) bool { return ev.Step == "state" }}
	h.eng.opts.Store = faulty
	d, err := h.eng.Destroy(ctx, "rc", "rc")
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(d.ID); j.State != state.JobFailed {
		t.Fatalf("precondition: a failed destroy over a gone instance: %+v", j)
	}
	// The repair destroy parks inside its lookup while a create of the
	// same name arrives.
	inLookup, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	faulty.set(func(f *faultyStore) {
		f.failAppendEvent = nil
		f.onGetInstance = func(string) { once.Do(func() { close(inLookup); <-release }) }
	})
	type result struct {
		job *state.Job
		err error
	}
	destroyDone := make(chan result, 1)
	go func() {
		j, err := h.eng.Destroy(ctx, "rc", "rc")
		destroyDone <- result{j, err}
	}()
	<-inLookup
	createDone := make(chan result, 1)
	go func() {
		j, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "rc"})
		createDone <- result{j, err}
	}()
	select {
	case r := <-createDone:
		t.Fatalf("the create must wait for the destroy's admission, not run inside its lookup: %+v %v", r.job, r.err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	repair := <-destroyDone
	if repair.err != nil {
		t.Fatalf("the repair must be admitted: %v", repair.err)
	}
	// The create, admitted after the repair, either meets the repair in
	// flight (busy) or a free name — never a replacement the repair then
	// destroys.
	created := <-createDone
	if created.err != nil && code(created.err) != pdr.CodeInstanceBusy {
		t.Fatalf("create after the repair's admission: %v", created.err)
	}
	if j := h.wait(repair.job.ID); j.State != state.JobSucceeded {
		t.Fatalf("the repair lands: %+v", j)
	}
	if created.err == nil {
		if j := h.wait(created.job.ID); j.State != state.JobSucceeded {
			t.Fatalf("the replacement create: %+v", j)
		}
		if inst, err := h.store.GetInstance("rc"); err != nil || inst.Stage != state.StageReady {
			t.Fatalf("the replacement must survive the repair: %+v %v", inst, err)
		}
	}
}

// A managed container the service table never recorded is swept before
// the network goes, so the non-forced network removal never fails on it
// and the destroy leaves nothing.
func TestDestroySweepsOrphansBeforeTheNetwork(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "orp"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	st, _ := h.fake.Inspect(ctx, "pdr-orp-web")
	labels := map[string]string{runtime.LabelManaged: "true", runtime.LabelInstance: "orp", runtime.LabelService: "extra"}
	if _, err := h.fake.Create(ctx, runtime.ContainerSpec{Name: "pdr-orp-extra", Image: st.Image, Network: "pdr-orp", Labels: labels}); err != nil {
		t.Fatal(err)
	}
	if err := h.fake.Start(ctx, "pdr-orp-extra"); err != nil {
		t.Fatal(err)
	}
	d, err := h.eng.Destroy(ctx, "orp", "orp")
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(d.ID); j.State != state.JobSucceeded {
		t.Fatalf("destroy with an orphan attached: %+v", j)
	}
	if objs, _ := h.fake.Objects(ctx, "orp"); !objs.Empty() {
		t.Fatalf("leftovers: %+v", objs)
	}
	events, _ := h.store.ListEvents(d.ID)
	sweep, network := -1, -1
	for i, ev := range events {
		if ev.Step == "sweep" && strings.Contains(ev.Detail, "pdr-orp-extra") && sweep < 0 {
			sweep = i
		}
		if ev.Step == "network" && ev.Status == "ok" {
			network = i
		}
	}
	if sweep < 0 || network < 0 || sweep > network {
		t.Fatalf("the orphan must be swept before the network: sweep=%d network=%d %+v", sweep, network, events)
	}
}

// A delivery snapshot is built beside its destination and moved into
// place: a snapshot left by a failed admission is never copied over.
func TestDeliverySnapshotIsRebuiltClean(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	catalog := t.TempDir()
	if err := copyTree(fixture, filepath.Join(catalog, "hello-nginx")); err != nil {
		t.Fatal(err)
	}
	h.eng.opts.CatalogDir = catalog
	stale := filepath.Join(h.dir, "instances", "dl", "template")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "stale-playbook.yaml"), []byte("left by a failed admission\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Template: "hello-nginx", Name: "dl"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("delivery create: %+v", j)
	}
	if _, err := os.Stat(filepath.Join(stale, "stale-playbook.yaml")); !os.IsNotExist(err) {
		t.Fatal("the stale file must not survive into the new snapshot")
	}
	if _, err := os.Stat(filepath.Join(stale, "lab.yaml")); err != nil {
		t.Fatalf("the snapshot must carry the template: %v", err)
	}
	if _, err := os.Stat(stale + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("no build directory may be left behind")
	}
}

// A recorded healthy is kept only by the job that recorded it: a new
// attempt after a failure re-probes, so a changed probe or a service gone
// unhealthy while running is judged afresh.
func TestNewJobReprobesRecordedHealth(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := readinessFixture(t, "300ms", "")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "rp"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	// The first job is over; pretend it failed on a later step so the
	// name resumes, and make the service unhealthy from now on.
	j, _ := h.store.GetJob(job.ID)
	j.State, j.Stage = state.JobFailed, "failed"
	_ = h.store.PutJob(*j)
	h.eng.opts.Probe = func(context.Context, string, int) bool { return false }
	again, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "rp"})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if j := h.wait(again.ID); j.State != state.JobFailed || !strings.Contains(errText(j), pdr.CodeReadinessBudget) {
		t.Fatalf("a new job must re-probe, not reuse the old green: %+v", j)
	}
	events, _ := h.store.ListEvents(again.ID)
	for _, ev := range events {
		if strings.Contains(ev.Detail, "already recorded healthy") {
			t.Fatalf("the old record must not be reused by a new job: %+v", events)
		}
	}
}

// A path-based template forced to delivery whose directory contains the
// state directory is refused: the snapshot would be copied into itself.
func TestSnapshotRefusesASourceContainingTheStateDir(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := copyTree(fixture, h.dir); err != nil { // lab.yaml now sits at the state directory's root
		t.Fatal(err)
	}
	_, err := h.eng.Create(ctx, CreateRequest{Path: h.dir, Name: "self", Mode: "delivery"})
	if err == nil || !strings.Contains(err.Error(), "contains the state directory") {
		t.Fatalf("a source containing the state directory must be refused: %v", err)
	}
	if _, err := h.store.GetInstance("self"); !errors.Is(err, state.ErrNotFound) {
		t.Fatal("nothing may be recorded")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "instances", "self")); !os.IsNotExist(err) {
		t.Fatal("no instance directory may be created")
	}
}

// A stale service's row outlives its own removal's journal line: a
// refused line fails the job with the row still there, and the retry
// re-walks the removal and journals it.
func TestStaleServiceRowOutlivesItsJournalLine(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "sr2"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	// A service the template no longer declares: a row and a managed container.
	st, _ := h.fake.Inspect(ctx, "pdr-sr2-web")
	labels := map[string]string{runtime.LabelManaged: "true", runtime.LabelInstance: "sr2", runtime.LabelService: "ghost"}
	if _, err := h.fake.Create(ctx, runtime.ContainerSpec{Name: "pdr-sr2-ghost", Image: st.Image, Labels: labels}); err != nil {
		t.Fatal(err)
	}
	_ = h.store.PutService(state.Service{Instance: "sr2", Name: "ghost", Image: st.Image, Container: "pdr-sr2-ghost", Stage: state.StageAlive})
	j, _ := h.store.GetJob(job.ID)
	j.State, j.Stage = state.JobFailed, "failed" // let the name resume
	_ = h.store.PutJob(*j)
	faulty := &faultyStore{Store: h.store, failAppendEvent: func(ev state.Event) bool { return ev.Step == "remove" && ev.Status == "ok" }}
	h.eng.opts.Store = faulty
	retry, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "sr2"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(retry.ID); j.State != state.JobFailed || !strings.Contains(errText(j), "journal job") {
		t.Fatalf("the refused journal line fails the job: %+v", j)
	}
	svcs, _ := h.store.ListServices("sr2")
	found := false
	for _, s := range svcs {
		if s.Name == "ghost" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the row must outlive the refused journal line: %+v", svcs)
	}
	faulty.set(func(f *faultyStore) { f.failAppendEvent = nil })
	again, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "sr2"})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if j := h.wait(again.ID); j.State != state.JobSucceeded {
		t.Fatalf("resumed create: %+v", j)
	}
	svcs, _ = h.store.ListServices("sr2")
	if len(svcs) != 1 || svcs[0].Name != "web" {
		t.Fatalf("the stale row is gone after the retry: %+v", svcs)
	}
	events, _ := h.store.ListEvents(again.ID)
	journaled := false
	for _, ev := range events {
		if ev.Step == "remove" && ev.Service == "ghost" && ev.Status == "ok" {
			journaled = true
		}
	}
	if !journaled {
		t.Fatalf("the retry must journal the removal: %+v", events)
	}
	if st, _ := h.fake.Inspect(ctx, "pdr-sr2-ghost"); st != nil {
		t.Fatal("the stale container must be gone")
	}
}

// The overlap check compares physical paths: a state directory reached
// through a symlink that points inside the source is refused too.
func TestSnapshotRefusesASymlinkedStateDirInsideTheSource(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := copyTree(fixture, h.dir); err != nil { // lab.yaml at the state directory's root
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(h.dir, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	h.eng.opts.StateDir = link // lexically outside h.dir, physically inside it
	_, err := h.eng.Create(ctx, CreateRequest{Path: h.dir, Name: "sym", Mode: "delivery"})
	if err == nil || !strings.Contains(err.Error(), "contains the state directory") {
		t.Fatalf("a symlinked state directory inside the source must be refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "instances", "sym")); !os.IsNotExist(err) {
		t.Fatal("no instance directory may be created")
	}
}

// An admission that fails before the instance is durable removes the
// directory it created: uninstall counts every directory under
// instances/ as a live instance, and nothing else would know this one.
func TestFailedAdmissionLeavesNoInstanceDir(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	faulty := &faultyStore{Store: h.store, failPutJob: func(j state.Job) bool { return j.State == state.JobQueued }}
	h.eng.opts.Store = faulty
	if _, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "nd"}); err == nil {
		t.Fatal("create must fail on the job write")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "instances", "nd")); !os.IsNotExist(err) {
		t.Fatal("an authoring admission that failed must leave no instance directory")
	}
	catalog := t.TempDir()
	if err := copyTree(fixture, filepath.Join(catalog, "hello-nginx")); err != nil {
		t.Fatal(err)
	}
	h.eng.opts.CatalogDir = catalog
	if _, err := h.eng.Create(ctx, CreateRequest{Template: "hello-nginx", Name: "nd2"}); err == nil {
		t.Fatal("create must fail on the job write")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "instances", "nd2")); !os.IsNotExist(err) {
		t.Fatal("a delivery admission that failed must leave no instance directory (nor its snapshot)")
	}
	// A directory that existed before the admission is not this admission's to remove.
	pre := filepath.Join(h.dir, "instances", "nd3")
	if err := os.MkdirAll(pre, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "nd3"}); err == nil {
		t.Fatal("create must fail on the job write")
	}
	if _, err := os.Stat(pre); err != nil {
		t.Fatal("a pre-existing directory must be left alone")
	}
}

// A delivery admission whose instance row is durable but whose service
// write is refused keeps the snapshot and the pinned modules: the recorded
// instance points at them, and the resume the failed job invites re-reads
// exactly that source. Cleanup stops once the instance is durable.
func TestFailedServiceWriteKeepsTheSnapshot(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	catalog := t.TempDir()
	if err := copyTree(fixture, filepath.Join(catalog, "hello-nginx")); err != nil {
		t.Fatal(err)
	}
	h.eng.opts.CatalogDir = catalog
	faulty := &faultyStore{Store: h.store, failPutService: func(state.Service) bool { return true }}
	h.eng.opts.Store = faulty
	if _, err := h.eng.Create(ctx, CreateRequest{Template: "hello-nginx", Name: "keep"}); err == nil {
		t.Fatal("create must fail on the service write")
	}
	inst, err := h.store.GetInstance("keep")
	if err != nil {
		t.Fatalf("the instance must be recorded: %v", err)
	}
	if _, err := os.Stat(filepath.Join(inst.Source, "lab.yaml")); err != nil {
		t.Fatalf("the snapshot the instance points at must survive a failed service write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "instances", "keep", "modules")); err != nil {
		t.Fatalf("the pinned modules must survive a failed service write: %v", err)
	}
	jobs, _ := h.store.ListJobs("keep")
	if len(jobs) != 1 || jobs[0].State != state.JobFailed {
		t.Fatalf("the abandoned job must be recorded as failed: %+v", jobs)
	}
	// The next `podaro up` resumes from the kept snapshot.
	faulty.set(func(f *faultyStore) { f.failPutService = nil })
	job, err := h.eng.Create(ctx, CreateRequest{Template: "hello-nginx", Name: "keep"})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("resumed create: %+v", j)
	}
	if got, _ := h.store.GetInstance("keep"); got.Stage != state.StageReady {
		t.Fatalf("stage after resume: %s", got.Stage)
	}
}

// A delivery snapshot pins the module definitions the plan resolved: a
// later binary with a changed module library reconciles the instance
// against what it was admitted with, not against the new library.
// moduleCatalog builds a catalog holding template "pin" (the fixture with
// its service replaced by the library module plain@1.0) and a copy of the
// test module library to serve it.
func moduleCatalog(t *testing.T) (catalog, lib string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixture, "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	var out []string
	skipping := false
	for _, l := range lines {
		if strings.HasPrefix(l, "  web:") {
			out = append(out, "  web: { use: modules/plain@1.0 }")
			skipping = true
			continue
		}
		if skipping && (strings.HasPrefix(l, "    ") || strings.TrimSpace(l) == "") {
			continue
		}
		skipping = false
		out = append(out, l)
	}
	body := strings.Replace(strings.Join(out, "\n"), "name: hello-nginx", "name: pin", 1)
	catalog = t.TempDir()
	if err := os.MkdirAll(filepath.Join(catalog, "pin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(catalog, "pin", "lab.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	lib = filepath.Join(t.TempDir(), "a")
	if err := copyTree(filepath.Join("..", "lab", "testdata", "modules"), lib); err != nil {
		t.Fatal(err)
	}
	return catalog, lib
}

// A delivery instance whose pinned module library is gone (a partial state
// restore) is damage, reported — never planned against the engine's
// library, whose same-named module may differ from what was admitted.
func TestMissingPinnedLibraryIsDamageNotFallback(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	catalog, libA := moduleCatalog(t)
	h.eng.opts.CatalogDir = catalog
	h.eng.opts.Library = lab.DirLibrary(libA)
	job, err := h.eng.Create(ctx, CreateRequest{Template: "pin", Name: "pin"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	before, _ := h.fake.Inspect(ctx, "pdr-pin-web")
	if before == nil {
		t.Fatal("no container")
	}
	// The pinned library is lost; the engine's library carries the same
	// module with another image.
	if err := os.RemoveAll(filepath.Join(h.dir, "instances", "pin", "modules")); err != nil {
		t.Fatal(err)
	}
	libB := filepath.Join(t.TempDir(), "b")
	if err := copyTree(libA, libB); err != nil {
		t.Fatal(err)
	}
	mod := filepath.Join(libB, "plain", "module.yaml")
	m, _ := os.ReadFile(mod)
	changed := strings.Replace(string(m), "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1)
	if changed == string(m) {
		t.Fatal("fixture module changed; update the test")
	}
	if err := os.WriteFile(mod, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	h.fake.Close()
	h.fake = nil
	if err := runtime.Reboot(h.world); err != nil {
		t.Fatal(err)
	}
	h.open()
	h.eng.opts.CatalogDir = catalog
	h.eng.opts.Library = lab.DirLibrary(libB)
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ := h.store.ListJobs("pin")
	if len(jobs) == 0 || jobs[0].Kind != "reconcile" {
		t.Fatalf("a reboot must reconcile: %+v", jobs)
	}
	j := h.wait(jobs[0].ID)
	if j.State != state.JobFailed || !strings.Contains(errText(j), "pinned module library of pin is missing") {
		t.Fatalf("the reconcile must report the missing pinned library, not plan against the engine's: %+v", j)
	}
	after, _ := h.fake.Inspect(ctx, "pdr-pin-web")
	if after == nil || after.Image != before.Image {
		t.Fatalf("nothing may be replaced: before=%q after=%+v", before.Image, after)
	}
	// The retry says the same, before anything is planned.
	if _, err := h.eng.Create(ctx, CreateRequest{Template: "pin", Name: "pin"}); code(err) != pdr.CodeRuntimeFailed || !strings.Contains(err.Error(), "pinned module library of pin is missing") {
		t.Fatalf("the retry must report the damage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "instances", "pin", "template", "lab.yaml")); err != nil {
		t.Fatalf("the snapshot must be untouched: %v", err)
	}
}

// A readiness block that declares no budget waits for the default — and
// the row, the journal and the failure name that default, never an empty
// budget.
func TestMissingBudgetIsReportedAsTheDefault(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "hello-nginx")
	if err := copyTree(fixture, dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "lab.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(string(raw), "typical: 5s, budget: 1m }", "typical: 5s }", 1)
	if body == string(raw) {
		t.Fatalf("fixture readiness line changed; update the test: %s", raw)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "nb"})
	if err != nil {
		t.Fatal(err)
	}
	if svcs, _ := h.store.ListServices("nb"); len(svcs) != 1 || svcs[0].Budget != DefaultReadinessBudget {
		t.Fatalf("the row must carry the effective budget from admission: %+v", svcs)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	if svcs, _ := h.store.ListServices("nb"); len(svcs) != 1 || svcs[0].Budget != DefaultReadinessBudget || svcs[0].Stage != state.StageReady {
		t.Fatalf("the row must keep the effective budget: %+v", svcs)
	}
	if got := budgetOf(&lab.PlanReadiness{Budget: "45s"}); got != "45s" {
		t.Fatalf("a declared budget wins: %s", got)
	}
}

func TestDeliverySnapshotPinsModules(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	catalog, libA := moduleCatalog(t)
	h.eng.opts.CatalogDir = catalog
	h.eng.opts.Library = lab.DirLibrary(libA)
	job, err := h.eng.Create(ctx, CreateRequest{Template: "pin", Name: "pin"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	before, _ := h.fake.Inspect(ctx, "pdr-pin-web")
	if before == nil {
		t.Fatal("no container")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "instances", "pin", "modules", "plain", "module.yaml")); err != nil {
		t.Fatalf("the module definition must be pinned with the snapshot: %v", err)
	}
	// Library B: the same module name and version, a different image.
	libB := filepath.Join(t.TempDir(), "b")
	if err := copyTree(libA, libB); err != nil {
		t.Fatal(err)
	}
	mod := filepath.Join(libB, "plain", "module.yaml")
	m, _ := os.ReadFile(mod)
	changed := strings.Replace(string(m), "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1)
	if changed == string(m) {
		t.Fatal("fixture module changed; update the test")
	}
	if err := os.WriteFile(mod, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	// The "upgraded" engine: the host reboots (the old engine and its
	// runtime are gone), then a new binary with library B reconciles.
	h.fake.Close()
	h.fake = nil
	if err := runtime.Reboot(h.world); err != nil {
		t.Fatal(err)
	}
	h.open()
	h.eng.opts.CatalogDir = catalog
	h.eng.opts.Library = lab.DirLibrary(libB)
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ := h.store.ListJobs("pin")
	if len(jobs) == 0 || jobs[0].Kind != "reconcile" {
		t.Fatalf("a reboot must reconcile: %+v", jobs)
	}
	if j := h.wait(jobs[0].ID); j.State != state.JobSucceeded {
		t.Fatalf("reconcile against the pinned modules: %+v", j)
	}
	after, _ := h.fake.Inspect(ctx, "pdr-pin-web")
	if after == nil || after.Image != before.Image || !strings.Contains(after.Image, "aaaaaaaa") {
		t.Fatalf("the instance must keep the admitted image: before=%q after=%+v", before.Image, after)
	}
}

// A delivery instance runs its snapshot, so the snapshot is what admission
// validates: the template is copied first and planned, gated and checked
// as that copy. A same-version edit of the catalog entry that lands after
// the plan — here at the admission's generated-name lookup, which follows
// the plan either way — must not reach the instance: the container runs
// the image the plan validated.
func TestDeliveryCreateValidatesItsSnapshotNotTheLiveSource(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	catalog := t.TempDir()
	entry := filepath.Join(catalog, "hello-nginx")
	if err := copyTree(fixture, entry); err != nil {
		t.Fatal(err)
	}
	h.eng.opts.CatalogDir = catalog
	admitted := "sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609"
	edited := "sha256:" + strings.Repeat("e", 64)
	var once sync.Once
	faulty := &faultyStore{Store: h.store, onGetInstance: func(string) {
		once.Do(func() {
			raw, err := os.ReadFile(filepath.Join(entry, "lab.yaml"))
			if err != nil {
				t.Error(err)
				return
			}
			body := strings.Replace(string(raw), admitted, edited, 1)
			if body == string(raw) {
				t.Error("fixture changed; update the test")
				return
			}
			if err := os.WriteFile(filepath.Join(entry, "lab.yaml"), []byte(body), 0o600); err != nil {
				t.Error(err)
			}
		})
	}}
	h.eng.opts.Store = faulty
	job, err := h.eng.Create(ctx, CreateRequest{Template: "hello-nginx"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	inst, err := h.store.GetInstance(job.Instance)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := os.ReadFile(filepath.Join(inst.Source, "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(snap), admitted) || strings.Contains(string(snap), edited) {
		t.Fatal("the snapshot must be the template admission validated, not the edit that landed after the plan")
	}
	st, _ := h.fake.Inspect(ctx, "pdr-"+job.Instance+"-web")
	if st == nil || !strings.Contains(st.Image, admitted) {
		t.Fatalf("the instance must run the image the plan validated: %+v", st)
	}
	if entries, _ := os.ReadDir(filepath.Join(h.dir, "staging")); len(entries) != 0 {
		t.Fatalf("staging must be empty after the admission: %v", entries)
	}
}

// The snapshot is staged outside instances/ until the job that names the
// instance is durable: at the admission's generated-name lookup (after
// the copy) the staged copy holds the template and instances/ holds
// nothing — a process that dies here leaves nothing uninstall would
// count — and an admission refused at its job write takes it away.
func TestSnapshotIsStagedOutsideInstancesUntilItsJobIsDurable(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	catalog := t.TempDir()
	if err := copyTree(fixture, filepath.Join(catalog, "hello-nginx")); err != nil {
		t.Fatal(err)
	}
	h.eng.opts.CatalogDir = catalog
	var once sync.Once
	var seen string
	faulty := &faultyStore{Store: h.store, onGetInstance: func(string) {
		once.Do(func() {
			staged, _ := os.ReadDir(filepath.Join(h.dir, "staging"))
			if len(staged) != 1 {
				seen = "staging must hold the one snapshot being admitted, holds " + strconv.Itoa(len(staged))
				return
			}
			if _, err := os.Stat(filepath.Join(h.dir, "staging", staged[0].Name(), "template", "lab.yaml")); err != nil {
				seen = "the staged snapshot must hold the template: " + err.Error()
				return
			}
			if inst, _ := os.ReadDir(filepath.Join(h.dir, "instances")); len(inst) != 0 {
				seen = "instances/ must hold nothing before the job is durable, holds " + inst[0].Name()
			}
		})
	}}
	h.eng.opts.Store = faulty
	job, err := h.eng.Create(ctx, CreateRequest{Template: "hello-nginx"})
	if err != nil {
		t.Fatal(err)
	}
	if seen != "" {
		t.Fatal(seen)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "instances", job.Instance, "template", "lab.yaml")); err != nil {
		t.Fatalf("the snapshot must be in place once the instance is durable: %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(h.dir, "staging")); len(entries) != 0 {
		t.Fatalf("staging must be empty after the admission: %v", entries)
	}
	faulty.set(func(f *faultyStore) { f.failPutJob = func(j state.Job) bool { return j.State == state.JobQueued } })
	if _, err := h.eng.Create(ctx, CreateRequest{Template: "hello-nginx"}); err == nil {
		t.Fatal("create must fail on the job write")
	}
	if entries, _ := os.ReadDir(filepath.Join(h.dir, "staging")); len(entries) != 0 {
		t.Fatalf("a refused admission must take its staged snapshot away: %v", entries)
	}
	if entries, _ := os.ReadDir(filepath.Join(h.dir, "instances")); len(entries) != 1 {
		t.Fatalf("instances/ must hold only the live instance: %v", entries)
	}
}

// What STATE_DIR/staging/ holds at start was left by a process that died
// mid-admission — no admission is in flight at start — and is swept: it
// was never an instance, and no record names it.
func TestStagedLeftoversAreSweptOnStart(t *testing.T) {
	h := newHarness(t)
	left := filepath.Join(h.dir, "staging", "snapshot-old")
	if err := os.MkdirAll(filepath.Join(left, "template"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(left, "template", "lab.yaml"), []byte("left by a crash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.eng.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(left); !os.IsNotExist(err) {
		t.Fatal("a staged leftover must be swept on start")
	}
}

// An admission writes its job first and its instance last: a create job
// with no instance behind it died between the two, and the directory it
// had moved into place — no record names it; status and destroy know
// nothing of it; uninstall would count it — goes with its failure,
// journaled.
func TestCreateJobWithoutAnInstanceRemovesItsDirectory(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ghost := filepath.Join(h.dir, "instances", "ghost")
	if err := os.MkdirAll(filepath.Join(ghost, "template"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ghost, "template", "lab.yaml"), []byte("moved into place before the crash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ghostID, err := newJobID()
	if err != nil {
		t.Fatal(err)
	}
	job := state.Job{ID: ghostID, Kind: "create", Instance: "ghost", State: state.JobQueued, Stage: "queued", Started: time.Now().UTC()}
	if err := h.store.PutJob(job); err != nil {
		t.Fatal(err)
	}
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed || !strings.Contains(errText(j), pdr.CodeInstanceNotFound) {
		t.Fatalf("the resumed job must fail with E202: %+v", j)
	}
	if _, err := os.Stat(ghost); !os.IsNotExist(err) {
		t.Fatal("the directory the interrupted admission left must be removed")
	}
	events, _ := h.store.ListEvents(job.ID)
	journaled := false
	for _, ev := range events {
		if strings.Contains(ev.Detail, "interrupted admission") {
			journaled = true
		}
	}
	if !journaled {
		t.Fatalf("the removal must be journaled: %+v", events)
	}
	// A recorded instance is never this rule's: its directory stays.
	kept, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "kept"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(kept.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "instances", "kept")); err != nil {
		t.Fatalf("a recorded instance's directory must stay: %v", err)
	}
}

// Hostnames are one DNS label each and both halves of
// <service>-<instance> may contain hyphens, so two labs can spell the
// same hostname (`web` on `a` and the instance `web-a`): the second is
// refused at admission with E206 naming the collision, nothing recorded.
func TestHostnameCollisionsAreRefusedAtCreate(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create a: %+v", j)
	}
	_, err = h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "web-a"})
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != pdr.CodeInstanceName || !strings.Contains(pe.Message, "web-a") || !strings.Contains(pe.Message, `instance "a"`) {
		t.Fatalf("an instance named like another's product vhost must be refused: %v", err)
	}
	if _, err := h.store.GetInstance("web-a"); !errors.Is(err, state.ErrNotFound) {
		t.Fatal("nothing may be recorded for the refused name")
	}
	// The other direction: the new instance's product vhost would be an
	// existing instance's console hostname.
	job, err = h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "web-x"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create web-x: %+v", j)
	}
	if _, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "x"}); code(err) != pdr.CodeInstanceName {
		t.Fatalf("an instance whose product vhost is another's console must be refused: %v", err)
	}
	// Unrelated names coexist.
	job, err = h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create b: %+v", j)
	}
}

// <service>-<instance> is one DNS label: a service name may be 63
// characters on its own, so the pair is checked — 63 fits, 64 is refused
// with E206 naming the label, nothing recorded.
func TestProductLabelsFitADNSLabel(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	long := strings.Repeat("s", 60)
	dir := t.TempDir()
	body := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: long-service }\nservices:\n  " + long + ":\n" +
		"    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n" +
		"    endpoints: [ { purpose: ui, port: 80 } ]\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "ab"}) // 60 + 1 + 2 = 63
	if err != nil {
		t.Fatalf("a label of exactly 63 characters must be admitted: %v", err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	_, err = h.eng.Create(ctx, CreateRequest{Path: dir, Name: "abc"}) // 64
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != pdr.CodeInstanceName || !strings.Contains(pe.Message, "64 characters") {
		t.Fatalf("a 64-character label must be refused naming its length: %v", err)
	}
	if _, err := h.store.GetInstance("abc"); !errors.Is(err, state.ErrNotFound) {
		t.Fatal("nothing may be recorded for the refused name")
	}
}

// diskFull is a store whose audit append for a destroy fails and, from
// that moment, every job write too — a disk that fills as the record is
// being written.
type diskFull struct {
	state.Store
	full bool
}

func (d *diskFull) AppendAudit(a state.Audit) error {
	if a.Action == "destroy" {
		d.full = true
		return errors.New("no space left on device")
	}
	return d.Store.AppendAudit(a)
}

func (d *diskFull) PutJob(j state.Job) error {
	if d.full {
		return errors.New("no space left on device")
	}
	return d.Store.PutJob(j)
}

// A destroy nobody could record never exists, resumable or not (API §2.5):
// the record precedes the job record, so when
// the disk fills as the record is written no job is left queued for the
// next start to resume — the instance survives the restart and the
// stream holds no destroy.
func TestAnUnauditedDestroyIsNeverResumable(t *testing.T) {
	h := newHarness(t)
	store := &diskFull{Store: h.store}
	h.store = store
	h.open()
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	if _, err := h.eng.Destroy(ctx, "d1", "d1"); code(err) != pdr.CodeRuntimeFailed {
		t.Fatalf("a destroy whose record cannot be written is refused with the fault: %v", err)
	}
	jobs, _ := h.store.ListJobs("d1")
	for _, j := range jobs {
		if j.Kind == "destroy" {
			t.Fatalf("a destroy job exists without its record: %+v", j)
		}
	}
	// The disk recovers and the engine restarts: nothing resumes a
	// destroy nobody recorded.
	store.full = false
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond) // long enough for a resumed destroy to have torn the instance down
	if _, err := h.store.GetInstance("d1"); err != nil {
		t.Fatalf("the instance must survive the restart: %v", err)
	}
	if active, _ := h.store.ActiveJob("d1"); active != nil {
		t.Fatalf("no destroy may be running: %+v", active)
	}
	audit, _ := h.store.ListAudit("")
	for _, a := range audit {
		if a.Action == "destroy" {
			t.Fatalf("no destroy record may exist: %+v", a)
		}
	}
}

// holdNetwork is a runtime whose EnsureNetwork for one instance blocks
// until released: the window between an attempt's gates and its runtime
// work, held open for a concurrent admission.
type holdNetwork struct {
	runtime.Runtime
	instance string
	hold     chan struct{}
	entered  chan struct{}
	once     sync.Once
}

func (h *holdNetwork) EnsureNetwork(ctx context.Context, name string, labels map[string]string, internal bool) error {
	if labels[runtime.LabelInstance] == h.instance {
		h.once.Do(func() { close(h.entered) })
		<-h.hold
	}
	return h.Runtime.EnsureNetwork(ctx, name, labels, internal)
}

// A hostname an attempt's plan gained since the instance was created is
// reserved before anything runs (API §7.1): the
// resumed attempt publishes the label under the admission lock, so a
// create for that label racing the attempt is refused rather than
// admitted against rows the attempt has not written yet.
func TestAddedHostnamesAreReservedBeforeAnythingRuns(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	src := filepath.Join(h.dir, "lab")
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(fixture, "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "lab.yaml"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: src, Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create x: %+v", j)
	}
	// The author adds a service with a ui endpoint: a new hostname, foo-x.
	added := "  foo:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    embed: iframe\n    readiness: { probe: { port: 80, path: /, expect_status: 200 }, typical: 5s, budget: 1m }\n    resources: { cpu: 500m, memory: 128MiB }\n"
	if err := os.WriteFile(filepath.Join(src, "lab.yaml"), append(raw, []byte(added)...), 0o600); err != nil {
		t.Fatal(err)
	}
	// The instance's create job resumes at the next start — the shape a
	// restart finds — and the attempt is held between its gates and its
	// runtime work.
	if err := h.store.PutJob(state.Job{ID: "job_resume", Kind: "create", Instance: "x", State: state.JobQueued, Stage: "queued", Started: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	h.open()
	hold := &holdNetwork{Runtime: h.fake, instance: "x", hold: make(chan struct{}), entered: make(chan struct{})}
	h.eng = New(Options{Store: h.store, Runtime: hold, StateDir: h.dir, CatalogDir: filepath.Join("..", "..", "scenarios"), PollInterval: 50 * time.Millisecond})
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-hold.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the resumed attempt never reached its runtime work")
	}
	_, err = h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "foo-x"})
	if code(err) != pdr.CodeInstanceName {
		close(hold.hold)
		t.Fatalf("a create for a label the resumed attempt claims must be refused: %v", err)
	}
	close(hold.hold)
	if j := h.wait("job_resume"); j.State != state.JobSucceeded {
		t.Fatalf("the resumed attempt: %+v", j)
	}
	services, _ := h.store.ListServices("x")
	found := false
	for _, s := range services {
		if s.Name == "foo" && s.UIPort == 80 {
			found = true
		}
	}
	if !found {
		t.Fatalf("the added service must be published: %+v", services)
	}
}

// holdRunning is a store that holds one instance's create worker at its
// first write — the job turning running — until released: the window
// between an admission's unlock and the worker's own lock, held open.
type holdRunning struct {
	state.Store
	instance string
	hold     chan struct{}
	entered  chan struct{}
	once     sync.Once
}

func (h *holdRunning) PutJob(j state.Job) error {
	if j.Instance == h.instance && j.Kind == "create" && j.State == state.JobRunning {
		h.once.Do(func() { close(h.entered) })
		<-h.hold
	}
	return h.Store.PutJob(j)
}

// A retry's plan is reserved at admission, before the attempt is
// launched (API §7.1): the labels a re-read plan
// gained are published under the admission lock, so a create for one of
// them that takes the lock right after the retry's admission — before
// the worker has run at all — is refused, not admitted against the rows
// of the old plan.
func TestARetryReservesAddedHostnamesAtAdmission(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	src := filepath.Join(h.dir, "lab")
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(fixture, "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "lab.yaml"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: src, Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create x: %+v", j)
	}
	// The last attempt failed, so the next `up` of the same source
	// resumes; meanwhile the author added a ui service: hostname foo-x.
	finished := time.Now().UTC()
	if err := h.store.PutJob(state.Job{ID: "job_failed", Kind: "create", Instance: "x", State: state.JobFailed, Stage: "failed", Started: finished, Finished: &finished}); err != nil {
		t.Fatal(err)
	}
	added := "  foo:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    embed: iframe\n    readiness: { probe: { port: 80, path: /, expect_status: 200 }, typical: 5s, budget: 1m }\n    resources: { cpu: 500m, memory: 128MiB }\n"
	if err := os.WriteFile(filepath.Join(src, "lab.yaml"), append(raw, []byte(added)...), 0o600); err != nil {
		t.Fatal(err)
	}
	hold := &holdRunning{Store: h.store, instance: "x", hold: make(chan struct{}), entered: make(chan struct{})}
	h.store = hold
	h.open()
	retry, err := h.eng.Create(ctx, CreateRequest{Path: src, Name: "x"})
	if err != nil {
		t.Fatalf("the retry must be admitted: %v", err)
	}
	select {
	case <-hold.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the retry's worker never started")
	}
	// The worker has done nothing yet; the label must already be taken.
	_, err = h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "foo-x"})
	if code(err) != pdr.CodeInstanceName {
		close(hold.hold)
		t.Fatalf("a create for a label the retry's plan claims must be refused at once: %v", err)
	}
	close(hold.hold)
	if j := h.wait(retry.ID); j.State != state.JobSucceeded {
		t.Fatalf("the retry: %+v", j)
	}
}

// holdRemove is a runtime that holds one container's removal until
// released: the window in which its host port is about to be freed.
type holdRemove struct {
	runtime.Runtime
	container, id string // the engine removes by the id its inspection saw (D150); the seam takes either
	hold          chan struct{}
	entered       chan struct{}
	once          sync.Once
}

func (h *holdRemove) Remove(ctx context.Context, name string) error {
	if name == h.container || name == h.id {
		h.once.Do(func() { close(h.entered) })
		<-h.hold
	}
	return h.Runtime.Remove(ctx, name)
}

// A service's route is withdrawn before its container goes:
// the row's published ports are forgotten first, so a host
// port the removal frees — and another lab's container may take at once
// — is never proxied under the old hostname; the row stays for the retry.
func TestARouteIsWithdrawnBeforeItsContainerGoes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	rows, _ := h.store.ListServices("x")
	if len(rows) != 1 || rows[0].Ports[80] == 0 {
		t.Fatalf("the service must have a published port: %+v", rows)
	}
	webSt, err := h.fake.Inspect(ctx, containerName("x", "web"))
	if err != nil || webSt == nil {
		t.Fatalf("web: %+v %v", webSt, err)
	}
	hold := &holdRemove{Runtime: h.fake, container: containerName("x", "web"), id: webSt.ID, hold: make(chan struct{}), entered: make(chan struct{})}
	h.eng = New(Options{Store: h.store, Runtime: hold, StateDir: h.dir, CatalogDir: filepath.Join("..", "..", "scenarios"), PollInterval: 50 * time.Millisecond})
	destroy, err := h.eng.Destroy(ctx, "x", "x")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-hold.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the destroy never reached the container")
	}
	rows, _ = h.store.ListServices("x")
	if len(rows) != 1 {
		t.Fatalf("the row must stay for the retry: %+v", rows)
	}
	if len(rows[0].Ports) != 0 {
		t.Fatalf("the route must be withdrawn before the container goes: %+v", rows[0].Ports)
	}
	close(hold.hold)
	if j := h.wait(destroy.ID); j.State != state.JobSucceeded {
		t.Fatalf("destroy: %+v", j)
	}
}

// A connection is resolved when it is opened, under the lock the
// withdrawal takes: a row read earlier never
// decides where a connection goes. A withdrawal waits for a connection
// being opened — it reaches the container that was there — and once it
// is through, no connection finds the route.
func TestAConnectionIsResolvedUnderTheWithdrawal(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	entered, hold := make(chan struct{}), make(chan struct{})
	var dialed string
	dial := func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = addr
		close(entered)
		<-hold
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	opened := make(chan error, 1)
	go func() {
		conn, err := h.eng.DialService(ctx, "x", "web", Socket, dial)
		if conn != nil {
			conn.Close()
		}
		opened <- err
	}()
	<-entered
	rows, _ := h.store.ListServices("x")
	if len(rows) != 1 || rows[0].Ports[80] == 0 {
		t.Fatalf("the service must have a published port: %+v", rows)
	}
	port, row := rows[0].Ports[80], rows[0]
	withdrawn := make(chan error, 1)
	go func() { withdrawn <- h.eng.withdrawRoute(&row) }()
	select {
	case err := <-withdrawn:
		t.Fatalf("the withdrawal must wait for the connection being opened: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(hold)
	if err := <-opened; err != nil {
		t.Fatalf("a connection opened before the withdrawal reaches the container that was there: %v", err)
	}
	if want := fmt.Sprintf("127.0.0.1:%d", port); dialed != want {
		t.Fatalf("dialed %s, want %s", dialed, want)
	}
	if err := <-withdrawn; err != nil {
		t.Fatal(err)
	}
	if _, err := h.eng.DialService(ctx, "x", "web", Socket, dial); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("after the withdrawal no connection finds the route: %v", err)
	}
	if after, _ := h.store.ListServices("x"); len(after) != 1 || len(after[0].Ports) != 0 {
		t.Fatalf("the row stays, its route gone: %+v", after)
	}
}

// holdCreate is a runtime that stops at the creation of one container —
// the moment a stale one is about to be replaced — until released.
type holdCreate struct {
	runtime.Runtime
	container string
	hold      chan struct{}
	entered   chan struct{}
	once      sync.Once
}

func (h *holdCreate) Create(ctx context.Context, spec runtime.ContainerSpec) (string, error) {
	if spec.Name == h.container {
		h.once.Do(func() { close(h.entered) })
		<-h.hold
	}
	return h.Runtime.Create(ctx, spec)
}

// A stale container's route is withdrawn before it is replaced:
// an authoring retry whose service changed lets the runtime
// replace the container — its host ports freed as it goes — so the row's
// ports are forgotten before Create is asked, and published again once
// the replacement's are read; the old hostname is never proxied to
// whatever takes the freed ports meanwhile.
func TestARouteIsWithdrawnBeforeAStaleContainerIsReplaced(t *testing.T) {
	h := newHarness(t)
	t.Setenv(runtime.EnvFakeReadyDelay, "10s")
	h.open()
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool { return false }
	ctx := context.Background()
	dir := t.TempDir()
	write := func(greeting string) {
		body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: retry, version: 1.0.0 }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    env: { GREETING: "` + greeting + `" }
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 200ms }
`
		if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("first")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "retry"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed {
		t.Fatalf("first create should fail at the probe: %+v", j)
	}
	rows, _ := h.store.ListServices("retry")
	if len(rows) != 1 || rows[0].Ports[80] == 0 {
		t.Fatalf("the service must be up with a published port: %+v", rows)
	}
	write("second")
	hold := &holdCreate{Runtime: h.fake, container: containerName("retry", "web"), hold: make(chan struct{}), entered: make(chan struct{})}
	h.eng = New(Options{Store: h.store, Runtime: hold, StateDir: h.dir, CatalogDir: filepath.Join("..", "..", "scenarios"), PollInterval: 50 * time.Millisecond})
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool { return true }
	retry, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "retry"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-hold.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the retry never reached the container's replacement")
	}
	rows, _ = h.store.ListServices("retry")
	if len(rows) != 1 {
		t.Fatalf("the row must stay: %+v", rows)
	}
	if len(rows[0].Ports) != 0 {
		t.Fatalf("the route must be withdrawn before the stale container is replaced: %+v", rows[0].Ports)
	}
	close(hold.hold)
	if j := h.wait(retry.ID); j.State != state.JobSucceeded {
		t.Fatalf("retry: %+v", j)
	}
	rows, _ = h.store.ListServices("retry")
	if len(rows) != 1 || rows[0].Ports[80] == 0 {
		t.Fatalf("the replacement's route must be published again: %+v", rows)
	}
}

// A service that crashed or was stopped outside a job is not proxied (S5
// Review round 19): the row's port is a claim, the runtime is the fact.
// A connection is opened only to a container that is running, ours, the
// one recorded, and still mapping the port the row holds; anything else
// withdraws the route at the first connection instead of following it
// to whatever holds the freed port by then.
func TestACrashedServiceIsNotProxied(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	dialed := 0
	dial := func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed++
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	if conn, err := h.eng.DialService(ctx, "x", "web", Socket, dial); err != nil || dialed != 1 {
		t.Fatalf("a running service is dialed: %v (dialed %d)", err, dialed)
	} else {
		conn.Close()
	}
	// The container stops outside any job — a crash, a hand-run stop —
	// and its host port is free for whoever comes next.
	if err := h.fake.Stop(ctx, containerName("x", "web"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := h.eng.DialService(ctx, "x", "web", Socket, dial); !errors.Is(err, ErrNoRoute) || dialed != 1 {
		t.Fatalf("a stopped service must not be dialed: %v (dialed %d)", err, dialed)
	}
	rows, _ := h.store.ListServices("x")
	if len(rows) != 1 || len(rows[0].Ports) != 0 {
		t.Fatalf("the dead route must be withdrawn: %+v", rows)
	}
}

// assertClosed proves the engine closed its end of a connection: the
// other end reads EOF, not a deadline.
func assertClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the connection must have been closed: %v", err)
	}
}

// A connection is bound to the container inspected: a host port is bound
// for as long as its container runs, so a connection is handed out only
// if the same run of the container is still running and mapping the
// port once it is open. One made as the container stopped — its port
// free for whatever lab comes next — or as it was started again is
// closed, not handed out, and the route judged again.
func TestAConnectionIsBoundToTheContainerInspected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	name := containerName("x", "web")
	// The container exits as the connection is made.
	a, b := net.Pipe()
	conn, err := h.eng.DialService(ctx, "x", "web", Socket, func(context.Context, string, string) (net.Conn, error) {
		if err := h.fake.Stop(ctx, name, 0); err != nil {
			t.Error(err)
		}
		return a, nil
	})
	if !errors.Is(err, ErrNoRoute) || conn != nil {
		t.Fatalf("a connection made as the container stopped must not be handed out: %v %v", conn, err)
	}
	assertClosed(t, b)
	rows, _ := h.store.ListServices("x")
	if len(rows) != 1 || len(rows[0].Ports) != 0 {
		t.Fatalf("the dead route must be withdrawn: %+v", rows)
	}
	// A job starts it again and publishes its route; a connection made
	// across another restart is another run's.
	if err := h.fake.Start(ctx, name); err != nil {
		t.Fatal(err)
	}
	st, err := h.fake.Inspect(ctx, name)
	if err != nil || st == nil || !st.Running {
		t.Fatalf("restart: %+v %v", st, err)
	}
	row := rows[0]
	row.ContainerID = st.ID
	if err := h.eng.publishRoute(&row, st.Ports); err != nil {
		t.Fatal(err)
	}
	a2, b2 := net.Pipe()
	conn, err = h.eng.DialService(ctx, "x", "web", Socket, func(context.Context, string, string) (net.Conn, error) {
		if err := h.fake.Stop(ctx, name, 0); err != nil {
			t.Error(err)
		}
		if err := h.fake.Start(ctx, name); err != nil {
			t.Error(err)
		}
		return a2, nil
	})
	if !errors.Is(err, ErrNoRoute) || conn != nil {
		t.Fatalf("a connection made across a restart must not be handed out: %v %v", conn, err)
	}
	assertClosed(t, b2)
	// The container is live again at the same port: its route stands and
	// the next connection reaches it.
	rows, _ = h.store.ListServices("x")
	if rows[0].Ports[rows[0].UIPort] == 0 || rows[0].Ports[rows[0].UIPort] != st.Ports[rows[0].UIPort] {
		t.Fatalf("a route live again must stand: %+v (published %v)", rows[0].Ports, st.Ports)
	}
	dialed := 0
	conn, err = h.eng.DialService(ctx, "x", "web", Socket, func(context.Context, string, string) (net.Conn, error) {
		dialed++
		c, d := net.Pipe()
		d.Close()
		return c, nil
	})
	if err != nil || dialed != 1 {
		t.Fatalf("the live container is reached: %v (dialed %d)", err, dialed)
	}
	conn.Close()
}

// A route changes only under the route lock, and a withdrawal judges the
// route again there: a job's publication of a container started again —
// at the same port, or at another when the freed one was taken — is
// never unpublished by a withdrawal that read the row before it (S5
// Review round 20).
func TestAWithdrawalNeverUnpublishesAReplacement(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	name := containerName("x", "web")
	for _, leg := range []struct {
		name     string
		samePort bool
	}{{"the same port", true}, {"another port", false}} {
		rows, _ := h.store.ListServices("x")
		row := rows[0]
		port := row.Ports[row.UIPort]
		if port == 0 {
			t.Fatalf("%s: no route to begin with: %+v", leg.name, row)
		}
		// The container stops outside any job: its route is dead.
		if err := h.fake.Stop(ctx, name, 0); err != nil {
			t.Fatal(err)
		}
		var hold net.Listener
		if !leg.samePort {
			// Someone else holds the freed port, so the restart lands on another.
			l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				t.Fatal(err)
			}
			hold = l
		}
		published := make(chan error, 1)
		var want map[int]int
		h.eng.afterStaleRouteRead = func() {
			h.eng.afterStaleRouteRead = nil
			// A job starts the container again and publishes its route.
			if err := h.fake.Start(ctx, name); err != nil {
				published <- err
				return
			}
			st, err := h.fake.Inspect(ctx, name)
			if err != nil || st == nil {
				published <- fmt.Errorf("inspect after restart: %+v %v", st, err)
				return
			}
			want = st.Ports
			fresh := row
			fresh.ContainerID = st.ID
			go func() { published <- h.eng.publishRoute(&fresh, st.Ports) }()
			time.Sleep(50 * time.Millisecond) // time enough for a publication that took no lock to land
		}
		if _, err := h.eng.DialService(ctx, "x", "web", Socket, func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("a dead route was dialed")
		}); !errors.Is(err, ErrNoRoute) {
			t.Fatalf("%s: the dead route must not be followed: %v", leg.name, err)
		}
		if err := <-published; err != nil {
			t.Fatal(err)
		}
		if hold != nil {
			hold.Close()
		}
		rows, _ = h.store.ListServices("x")
		got := rows[0].Ports[rows[0].UIPort]
		if got == 0 || got != want[rows[0].UIPort] {
			t.Fatalf("%s: the published route must stand: row %v, published %v", leg.name, rows[0].Ports, want)
		}
		if leg.samePort != (got == port) {
			t.Fatalf("%s: expected the port to be reused=%v: before %d, after %d", leg.name, leg.samePort, port, got)
		}
		// And it is followed now.
		dialed := ""
		conn, err := h.eng.DialService(ctx, "x", "web", Socket, func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = addr
			c, d := net.Pipe()
			d.Close()
			return c, nil
		})
		if err != nil || dialed != fmt.Sprintf("127.0.0.1:%d", got) {
			t.Fatalf("%s: the published route is followed: %v (dialed %q, want port %d)", leg.name, err, dialed, got)
		}
		conn.Close()
	}
}

// A job this engine launched is never retired as "recorded but never
// driven": one a shutdown interrupted keeps its running record — the
// next start resumes it — and holds its instance's exclusive slot
// meanwhile. Only a record no process here launched is driverless (S5,
// found by the local gate at round 21).
func TestAnInterruptedJobIsNotRetiredAsDriverless(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.opts.Probe = func(context.Context, string, int) bool { return false }
	job, err := h.eng.Create(ctx, CreateRequest{Path: readinessFixture(t, "30s", ""), Name: "stop"})
	if err != nil {
		t.Fatal(err)
	}
	parked := time.Now().Add(5 * time.Second)
	for {
		j, _ := h.store.GetJob(job.ID)
		if j != nil && strings.HasPrefix(j.Stage, "waiting for") {
			break
		}
		if time.Now().After(parked) {
			t.Fatalf("the job never reached its probe loop: %+v", j)
		}
		time.Sleep(20 * time.Millisecond)
	}
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := h.eng.Shutdown(sctx); err != nil {
		t.Fatal(err)
	}
	if h.eng.isRunning(job.ID) {
		t.Fatal("precondition: the goroutine is gone")
	}
	if j, _ := h.store.GetJob(job.ID); j == nil || j.State != state.JobRunning {
		t.Fatalf("precondition: the interrupted record stays running: %+v", j)
	}
	// Every admission on this engine finds the slot held, and none of
	// them retires the record.
	if _, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "stop"}); code(err) != pdr.CodeInstanceExists {
		t.Fatalf("a create must find the name taken: %v", err)
	}
	if j, _ := h.store.GetJob(job.ID); j == nil || j.State != state.JobRunning || strings.Contains(errText(j), "never driven") {
		t.Fatalf("the interrupted job must not be retired: %+v", j)
	}
	if _, err := h.eng.Destroy(ctx, "stop", "stop"); code(err) != pdr.CodeInstanceBusy {
		t.Fatalf("a destroy must find the slot held: %v", err)
	}
	if j, _ := h.store.GetJob(job.ID); j == nil || j.State != state.JobRunning {
		t.Fatalf("the interrupted job must still be resumable: %+v", j)
	}
	// The next engine — which launched nothing — resumes it, as before.
	h.open()
	h.eng.opts.Probe = func(context.Context, string, int) bool { return true }
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("the resumed job must finish: %+v", j)
	}
}

// A database written before S5 has no gateway facts on its service rows
// and a healthy instance is never reconciled, so the next start derives
// them from the snapshot plan: without it the lab's product hostnames
// would never be published and nothing could repair it in place (S5
// Review round 23).
func TestGatewayFactsAreBackfilledForOlderInstances(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	rows, _ := h.store.ListServices("x")
	if len(rows) != 1 || rows[0].UIPort == 0 {
		t.Fatalf("precondition: a fresh create records the ui facts: %+v", rows)
	}
	want := rows[0]
	// The rows as a schema-3 database left them: the columns exist with
	// their defaults, the routes stand.
	legacy := want
	legacy.UIPort, legacy.UIScheme, legacy.Embed = 0, "", ""
	if err := h.store.PutService(legacy); err != nil {
		t.Fatal(err)
	}
	// And the mark migration 4 leaves on every instance older than those
	// columns — what says the facts are owed, since the rows alone cannot
	// (round 27).
	if err := h.store.SetGatewayBackfill("x", true); err != nil {
		t.Fatal(err)
	}
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _ = h.store.ListServices("x")
	if len(rows) != 1 || rows[0].UIPort != want.UIPort || rows[0].UIScheme != want.UIScheme || rows[0].Embed != want.Embed {
		t.Fatalf("the gateway facts must be derived from the plan: %+v, want %d/%s/%s", rows, want.UIPort, want.UIScheme, want.Embed)
	}
	if rows[0].Ports[rows[0].UIPort] != want.Ports[want.UIPort] {
		t.Fatalf("the route it holds must stand: %+v, want %v", rows[0].Ports, want.Ports)
	}
	if rows[0].Stage != want.Stage {
		t.Fatalf("a healthy lab stays healthy: %s", rows[0].Stage)
	}
	if pending, err := h.store.GatewayBackfill("x"); err != nil || pending {
		t.Fatalf("the mark must be cleared once the facts are published: %v %v", pending, err)
	}
}

// rawEndpointLab writes a one-service lab whose endpoint is not a ui one
// and hands back its directory and a writer that re-declares that
// endpoint — the shape of a service that legitimately has no ui facts,
// and of an author changing one.
func rawEndpointLab(t *testing.T, budget string) (string, func(endpoint string)) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "raw-nginx")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir, func(endpoint string) {
		body := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\n" +
			"metadata: { name: raw-nginx, version: 0.1.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n" +
			"    endpoints: [ " + endpoint + " ]\n" +
			"    readiness: { probe: { port: 80, path: /, expect_status: 200 }, typical: 100ms, budget: " + budget + " }\n" +
			"    resources: { cpu: 500m, memory: 128MiB }\n"
		if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// twoRawServiceLab is rawEndpointLab with two services, api and web, so
// a case can fail the second row's write and see what the first left.
func twoRawServiceLab(t *testing.T, budget string) (string, func(endpoint string)) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "raw-two")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir, func(endpoint string) {
		one := func(name string) string {
			return "  " + name + ":\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n" +
				"    endpoints: [ " + endpoint + " ]\n" +
				"    readiness: { probe: { port: 80, path: /, expect_status: 200 }, typical: 100ms, budget: " + budget + " }\n" +
				"    resources: { cpu: 500m, memory: 128MiB }\n"
		}
		body := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\n" +
			"metadata: { name: raw-two, version: 0.1.0 }\nservices:\n" + one("api") + one("web")
		if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// A publication that fails part way through takes back the rows that
// landed: a row whose host port is already mapped is routed the moment
// it gains a ui port, and the job about to be abandoned would leave that
// route with nothing to complete or remove it.
func TestAPartialPublicationIsTakenBack(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir, lab := twoRawServiceLab(t, "200ms")
	lab("{ purpose: api, port: 80 }")
	h.eng.opts.Probe = func(context.Context, string, int) bool { return false }
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "part"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed {
		t.Fatalf("the create must fail at readiness: %+v", j)
	}
	rows, _ := h.store.ListServices("part")
	if len(rows) != 2 {
		t.Fatalf("precondition: two services: %+v", rows)
	}
	// The create stopped at the first service's budget, so api is the row
	// with a live mapping — the one a ui port would route at once.
	for _, svc := range rows {
		if svc.UIPort != 0 {
			t.Fatalf("precondition: no ui facts: %+v", svc)
		}
		if svc.Name == "api" && svc.Ports[80] == 0 {
			t.Fatalf("precondition: api holds a mapped port: %+v", svc)
		}
	}
	// The author turns both endpoints into ui ones and re-runs the lab;
	// the store refuses the second row's write, after the first landed.
	lab("{ purpose: ui, port: 80 }")
	faulty := &faultyStore{Store: h.store, failPutService: func(svc state.Service) bool { return svc.Name == "web" && svc.UIPort != 0 }}
	h.eng.opts.Store = faulty
	if _, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "part"}); err == nil {
		t.Fatal("a create whose service write fails must fail")
	}
	h.eng.opts.Store = h.store
	rows, _ = h.store.ListServices("part")
	for _, svc := range rows {
		if svc.UIPort != 0 || svc.UIScheme != "" {
			t.Fatalf("a half-published plan left a route behind: %+v", svc)
		}
		if svc.Name == "api" && svc.Ports[80] == 0 {
			t.Fatalf("api: the port it holds must stand: %+v", svc.Ports)
		}
	}
}

// A retry's job is recorded before the labels its plan claims are
// published: a route published with no durable job to drive it would
// stand with nothing to reconcile it — a row whose port is already
// mapped is live the moment it gains a ui port, and a later start finds
// the containers running and leaves them alone.
func TestARetrysRouteIsNeverPublishedWithoutItsJob(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir, lab := rawEndpointLab(t, "200ms")
	lab("{ purpose: api, port: 80 }")
	h.eng.opts.Probe = func(context.Context, string, int) bool { return false }
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "retry"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed {
		t.Fatalf("the create must fail at readiness: %+v", j)
	}
	rows, _ := h.store.ListServices("retry")
	if len(rows) != 1 || rows[0].UIPort != 0 || rows[0].Ports[80] == 0 {
		t.Fatalf("precondition: a mapped port and no ui facts: %+v", rows)
	}
	// The author turns that mapped endpoint into a ui one and re-runs the
	// lab; the store refuses the retry's job record.
	lab("{ purpose: ui, port: 80 }")
	faulty := &faultyStore{Store: h.store, failPutJob: func(j state.Job) bool { return j.State == state.JobQueued }}
	h.eng.opts.Store = faulty
	if _, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "retry"}); err == nil {
		t.Fatal("a create whose job cannot be recorded must fail")
	}
	h.eng.opts.Store = h.store
	rows, _ = h.store.ListServices("retry")
	if len(rows) != 1 || rows[0].UIPort != 0 || rows[0].UIScheme != "" {
		t.Fatalf("a route was published with no job to drive it: %+v", rows)
	}
}

// The mark is cleared by whoever publishes the facts, not only by the
// backfill: a start skips the backfill for an instance whose interrupted
// job it resumes, and that job publishes the plan's facts itself — so a
// mark left standing would have the next start derive them again, for an
// authoring instance from a working directory changed since.
func TestAResumedJobClearsTheBackfillMark(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir, lab := rawEndpointLab(t, "1m")
	lab("{ purpose: api, port: 80 }")
	h.eng.opts.Probe = func(context.Context, string, int) bool { return false }
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "res"})
	if err != nil {
		t.Fatal(err)
	}
	parked := time.Now().Add(5 * time.Second)
	for {
		j, _ := h.store.GetJob(job.ID)
		if j != nil && strings.HasPrefix(j.Stage, "waiting for") {
			break
		}
		if time.Now().After(parked) {
			t.Fatalf("the job never reached its probe loop: %+v", j)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Migration 4's mark, on an instance whose job was in flight when the
	// upgrade happened.
	if err := h.store.SetGatewayBackfill("res", true); err != nil {
		t.Fatal(err)
	}
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := h.eng.Shutdown(sctx); err != nil {
		t.Fatal(err)
	}
	if j, _ := h.store.GetJob(job.ID); j == nil || j.State != state.JobRunning {
		t.Fatalf("precondition: the interrupted record stays running: %+v", j)
	}
	h.open()
	h.eng.opts.Probe = func(context.Context, string, int) bool { return true }
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("the resumed job must finish: %+v", j)
	}
	if pending, err := h.store.GatewayBackfill("res"); err != nil || pending {
		t.Fatalf("the job that published the facts must clear the mark: %v %v", pending, err)
	}
	// And so the start after it derives nothing: the author's change to
	// the working directory reaches the rows only through a job.
	lab("{ purpose: ui, port: 80 }")
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _ := h.store.ListServices("res")
	if len(rows) != 1 || rows[0].UIPort != 0 || rows[0].UIScheme != "" || rows[0].Embed != "" {
		t.Fatalf("a start must publish no route a job never admitted: %+v", rows)
	}
}

// A service that legitimately declares no ui endpoint carries exactly
// the zeros a row the backfill never reached does, so nothing may be
// read from them: an instance created since those columns existed is
// never re-derived at a start, and an authoring instance whose working
// directory changed while the engine was down never has a product route
// published that no job ever admitted.
func TestAnInstanceWithoutUIEndpointsIsNotRederived(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir, lab := rawEndpointLab(t, "1m")
	lab("{ purpose: api, port: 80 }")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "raw"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	rows, _ := h.store.ListServices("raw")
	if len(rows) != 1 || rows[0].UIPort != 0 || rows[0].UIScheme != "" || rows[0].Embed != "" {
		t.Fatalf("precondition: a service with no ui endpoint carries no ui facts: %+v", rows)
	}
	// The working directory changes while the engine is down — the raw
	// endpoint becomes a ui one — and the next start must not act on it.
	lab("{ purpose: ui, port: 80 }")
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _ = h.store.ListServices("raw")
	if len(rows) != 1 || rows[0].UIPort != 0 || rows[0].UIScheme != "" || rows[0].Embed != "" {
		t.Fatalf("a start must publish no route a job never admitted: %+v", rows)
	}
}

// twoServiceFixture is the runtime fixture with a second inline service,
// for cases that need two rows on one instance.
func twoServiceFixture(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "hello-nginx")
	if err := copyTree(fixture, dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "lab.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	image := "docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609"
	if !strings.Contains(string(raw), image) {
		t.Fatalf("fixture image changed; update the test: %s", raw)
	}
	second := "\n  api:\n    image: " + image + "\n    endpoints: [ { purpose: ui, port: 80 } ]\n" +
		"    embed: newtab\n    readiness: { probe: { port: 80, path: /, expect_status: 200 }, typical: 5s, budget: 1m }\n" +
		"    resources: { cpu: 500m, memory: 128MiB }\n"
	if err := os.WriteFile(path, append(raw, []byte(second)...), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A backfill interrupted between two rows is finished at the next start:
// one row carrying the facts is not the instance being done, or the rest
// would keep their defaults for good.
func TestAnInterruptedGatewayBackfillIsFinished(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: twoServiceFixture(t), Name: "y"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	rows, _ := h.store.ListServices("y")
	if len(rows) != 2 {
		t.Fatalf("precondition: two services: %+v", rows)
	}
	want := map[string]state.Service{}
	for _, svc := range rows {
		if svc.UIPort == 0 {
			t.Fatalf("precondition: a fresh create records the ui facts: %+v", svc)
		}
		want[svc.Name] = svc
	}
	// A backfill that landed one row and stopped: the other keeps the
	// defaults a schema-3 database left it.
	half := want["web"]
	half.UIPort, half.UIScheme, half.Embed = 0, "", ""
	if err := h.store.PutService(half); err != nil {
		t.Fatal(err)
	}
	// An interrupted backfill is exactly one whose mark still stands: it
	// is cleared only once every row has been published (round 27).
	if err := h.store.SetGatewayBackfill("y", true); err != nil {
		t.Fatal(err)
	}
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _ = h.store.ListServices("y")
	for _, svc := range rows {
		w := want[svc.Name]
		if svc.UIPort != w.UIPort || svc.UIScheme != w.UIScheme || svc.Embed != w.Embed {
			t.Fatalf("every row must end with its facts: %+v, want %d/%s/%s", svc, w.UIPort, w.UIScheme, w.Embed)
		}
		if svc.Ports[svc.UIPort] != w.Ports[w.UIPort] {
			t.Fatalf("%s: the route it holds must stand: %+v", svc.Name, svc.Ports)
		}
	}
}

// A destroy's admission reads the exclusive slot before the instance: a
// job runs outside the admission lock, so a first destroy that finishes
// between the two reads — the instance looked up present, then gone with
// its job done — must not let a second destroy through on the slot it
// has just freed (the concurrency test caught it under the race detector).
// The second admission is parked at its slot read while
// the first destroy, parked before its last step, finishes.
func TestASecondDestroyIsRefusedWhenTheFirstFinishesMidAdmission(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "cc"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	faulty := &faultyStore{Store: h.store}
	h.eng.opts.Store = faulty
	firstAtDelete, releaseFirst := make(chan struct{}), make(chan struct{})
	var once1 sync.Once
	faulty.set(func(f *faultyStore) {
		f.onDeleteInstance = func(string) { once1.Do(func() { close(firstAtDelete); <-releaseFirst }) }
	})
	first, err := h.eng.Destroy(ctx, "cc", "cc")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstAtDelete:
	case <-time.After(10 * time.Second):
		t.Fatal("the first destroy never reached its last step")
	}
	secondAtSlot, releaseSecond := make(chan struct{}), make(chan struct{})
	var once2 sync.Once
	faulty.set(func(f *faultyStore) {
		f.onActiveJob = func(string) { once2.Do(func() { close(secondAtSlot); <-releaseSecond }) }
	})
	type outcome struct {
		job *state.Job
		err error
	}
	second := make(chan outcome, 1)
	go func() {
		j, err := h.eng.Destroy(ctx, "cc", "cc")
		second <- outcome{j, err}
	}()
	select {
	case <-secondAtSlot:
	case <-time.After(10 * time.Second):
		t.Fatal("the second destroy never reached its slot read")
	}
	close(releaseFirst)
	if j := h.wait(first.ID); j.State != state.JobSucceeded {
		t.Fatalf("the first destroy: %+v", j)
	}
	close(releaseSecond)
	var out outcome
	select {
	case out = <-second:
	case <-time.After(10 * time.Second):
		t.Fatal("the second destroy never answered")
	}
	if out.err == nil || code(out.err) != pdr.CodeInstanceNotFound {
		t.Fatalf("a second destroy admitted while the first finished must find no instance, not a free slot: job=%+v err=%v", out.job, out.err)
	}
	if jobs, _ := h.store.ListJobs("cc"); len(jobs) != 2 {
		t.Fatalf("exactly the create and the one destroy may exist: %+v", jobs)
	}
}
