// SPDX-License-Identifier: AGPL-3.0-only

// Package engine is the instance lifecycle (plan S4): create → the first
// rungs of the ready ladder, destroy, and reconcile-on-start, run as
// persistent, journaled, resumable jobs over a container runtime (API §4,
// §7; roadmap §9 Engine row). The HTTP door (internal/api) and the CLI
// are clients of this package.
package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/observe"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/secrets"
	"github.com/jeremiahjrross/podaro/internal/state"
	"gopkg.in/yaml.v3"
)

// Options configure an Engine.
type Options struct {
	Store   state.Store
	Runtime runtime.Runtime
	// Library resolves module references; nil means the embedded library.
	Library *lab.Library
	// StateDir holds instances/<name>/ (snapshots, env files, evidence)
	// and staging/ (a delivery snapshot while its create is admitted).
	StateDir string
	// CatalogDir holds installed templates by name (INSTALL §3: catalog/).
	CatalogDir string
	// PollInterval is the readiness probe cadence for services whose
	// readiness declares no interval; zero means the schema default
	// (DefaultProbeInterval, 5s). A declared interval always wins.
	PollInterval time.Duration
	// Probe overrides the HTTP readiness probe (tests).
	Probe func(ctx context.Context, url string, expect int) bool
	// Logf receives one line per journal event; nil discards.
	Logf func(format string, args ...any)
	// Address reports the gateway's domain and port once `podaro setup`
	// has run (User Manual §5 hostnames); "" before. nil means never.
	Address func() (domain string, port int)
	// Observe is the observability export (Manual §4, threat model
	// B10). A nil exporter — the default, and what an operator who
	// configured no destination gets — makes every call on it a no-op:
	// the engine holds no client and initiates no connection.
	Observe *observe.Exporter
}

// Engine runs instances.
type Engine struct {
	opts Options

	mu      sync.Mutex
	running map[string]chan struct{} // job id → closed when the job ends
	// unrecorded holds the terminal state of jobs whose final write the
	// store refused (after retries): the outcome is known here even
	// while the record still says active, so the slot is never held by a
	// job that is over, and a later lookup lands the write.
	unrecorded map[string]state.Job
	// driven holds the ids of the jobs this process launched and has not
	// landed a terminal record for. A record the store still shows
	// active whose goroutine is gone was "recorded but never driven"
	// only if this process never launched it (a predecessor's, or one
	// whose launch never happened): one it did launch and did not
	// finish stopped at a checkpoint the next start resumes, so its
	// record stands and its instance's slot stays held — retiring it
	// would invent a failure and let another job start against the lab
	// the resumed one is coming back to.
	driven map[string]struct{}
	// jobInstances maps a running job to its instance, so every journal
	// line, job error, and service error the job produces is passed
	// through that instance's redaction filter before it is persisted or
	// logged (invariant 6: a runtime error may echo a rendered command).
	jobInstances map[string]string
	// finishRetry is the base backoff of the terminal-write retries.
	finishRetry time.Duration
	// ctx is the context every launched job runs under; Shutdown cancels
	// it, so a job in flight stops at its next checkpoint instead of
	// outliving the store and runtime it works on.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// jobMu serializes the exclusive-slot reservation (API §4: one job per
	// instance): the active-job check and the job insert happen under it,
	// so concurrent handlers cannot both observe an idle instance.
	jobMu sync.Mutex
	// instLocks holds one mutex per instance for the writes that happen
	// outside the job slot and for destroy's removal of the instance's
	// state (guard.go); instMu guards the map.
	instMu    sync.Mutex
	instLocks map[string]*sync.Mutex
	// lastEval holds, per instance and checkpoint, the ticket of the
	// evaluation whose result stands as the latest (record): an evaluation
	// that began earlier is older whatever the order the two recorded in.
	// In memory only — an engine restart ends every evaluation in flight,
	// so nothing older survives one. evalMu guards the map.
	evalMu   sync.Mutex
	lastEval map[string]uint64
	// resetMark holds, per instance, the ticket at which its last reset cleared
	// the results: an evaluation or an attestation begun before it is the
	// older observation whatever the freshness marks say, so a result
	// delayed across a reset never survives it.
	// Guarded by evalMu.
	resetMark map[string]uint64
	// evalSeq issues the tickets those two maps compare. A wall clock
	// cannot order evaluations: a host clock corrected backwards gives a
	// later evaluation a smaller instant, so it reads as the older
	// observation and is discarded behind the result it should replace —
	// and an attestation begun before a reset can read as later than the
	// reset's own mark and survive it. A counter that only ever counts up
	// orders them by the one thing that matters, which came first in this
	// engine's life. It is per-process, as
	// both maps already are: across a restart neither holds anything, and
	// nothing is superseded.
	evalSeq atomic.Uint64
	// journals holds one evidence journal per instance for the engine's
	// lifetime: the journal keeps the state that makes ids monotonic
	// within a millisecond, so a fresh one per append lost it.
	// journalMu guards the map.
	journalMu sync.Mutex
	journals  map[string]*evidence.Journal
	// resumedJobs holds the seed and verify jobs Start resumed after a
	// restart: the only jobs that restore the lab before their own steps
	// (restored). Guarded by mu.
	resumedJobs map[string]bool
	// jobKinds maps a running job to its kind, jobInstances' twin: a
	// destroy's journal is filtered with the filter that can be built
	// (filterFor). Guarded by mu.
	jobKinds map[string]string
	// routeMu orders the gateway's connections against a route's
	// withdrawal: DialService resolves and opens a connection under its
	// read side; every write of a service row takes its write side —
	// a route is published (publishRoute) or withdrawn (withdrawRoute,
	// withdrawStaleRoute) only there, and any other write keeps the
	// route the row holds (putService). A connection opened before the
	// route went reaches the container that was there; one opened after
	// finds no route — a row read earlier never decides where a
	// connection goes, whatever holds the freed port by then — and a
	// withdrawal's read, check and write never interleave with a
	// publication.
	routeMu sync.RWMutex
	// afterStaleRouteRead is a test seam: called by withdrawStaleRoute
	// under routeMu, after the row is read and before it is judged.
	afterStaleRouteRead func()
}

// New builds an engine; Start resumes and reconciles.
func New(opts Options) *Engine {
	if opts.Library == nil {
		opts.Library = lab.EmbeddedLibrary()
	}
	if opts.PollInterval == 0 {
		opts.PollInterval = DefaultProbeInterval
	}
	if opts.Probe == nil {
		opts.Probe = httpProbe
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.Address == nil {
		opts.Address = func() (string, int) { return "", 0 }
	}
	// The journal seam is not installed here. It belongs where every
	// component is wired — `observe.Journal` in `engine serve` — because
	// wrapping the engine's own copy exported the engine's lines and no
	// one else's. `Observe` remains the engine's
	// own metrics and spans.
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{opts: opts, running: map[string]chan struct{}{}, unrecorded: map[string]state.Job{}, driven: map[string]struct{}{}, finishRetry: 50 * time.Millisecond, ctx: ctx, cancel: cancel}
}

// CreateRequest is API §7.1's body.
type CreateRequest struct {
	Template       string   `json:"template,omitempty"`
	Path           string   `json:"path,omitempty"`
	Name           string   `json:"name,omitempty"`
	Profile        string   `json:"profile,omitempty"`
	Mode           string   `json:"mode,omitempty"`
	AcceptLicenses []string `json:"accept_licenses,omitempty"`
	// Actor is who asked, for the audit stream (API §2.5): set by the
	// door that authenticated the caller, never from the body.
	Actor Actor `json:"-"`
}

// actor is the request's actor, the local door's when none was set.
func (r CreateRequest) actor() Actor {
	if r.Actor.Mechanism == "" {
		return Socket
	}
	return r.Actor
}

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,22}[a-z0-9])?$`)

// Create validates, plans, gates on licenses, records the instance, and
// starts its create job. It returns the job (API: 202) or an error whose
// code maps to 400/404/409/428.
func (e *Engine) Create(ctx context.Context, req CreateRequest) (*state.Job, error) {
	if req.Name != "" && !nameRe.MatchString(req.Name) {
		return nil, badName(req.Name)
	}
	// Admission is one critical section (API §4's exclusive slot): the
	// lookup that chooses the source, the plan, and the writes — so no
	// two handlers observe an idle name at once, and the source a retry
	// resolves to is the instance the writes then extend.
	e.jobMu.Lock()
	defer e.jobMu.Unlock()
	var existing *state.Instance
	if req.Name != "" {
		var err error
		if existing, err = e.lookup(req.Name); err != nil {
			return nil, err
		}
	}
	src, err := e.resolveSource(req, existing)
	if err != nil {
		return nil, err
	}
	mode := src.mode
	if req.Mode != "" {
		switch state.Mode(req.Mode) {
		case state.ModeAuthoring, state.ModeDelivery:
			mode = state.Mode(req.Mode)
		default:
			e := pdr.New(pdr.CodeCreateRequest, "mode %q is not authoring or delivery", req.Mode)
			e.Next = "--mode authoring | delivery (roadmap §3.1: fixed at create, never switched in place)"
			return nil, e
		}
	}
	// A delivery instance runs its snapshot, so the snapshot is what is
	// validated: the template is copied first and planned, gated and
	// checked as that copy — never as the live directory, which can be
	// edited between the plan and the copy (or during it) and would then
	// run what admission never saw. The copy is named after its source in
	// every message (the operator edits the source, not the copy). A retry
	// of a delivery instance plans from the snapshot it already has (D60).
	planDir, display := src.dir, ""
	var stage *staging
	if mode == state.ModeDelivery && !src.pinned {
		if stage, err = e.stageSnapshot(src.dir); err != nil {
			return nil, err
		}
		defer stage.discard() // whatever was not moved into the instance
		planDir, display = stage.template, src.dir
	}
	plan, _, err := lab.MakePlan(lab.PlanOptions{Options: lab.Options{Path: planDir, Library: src.library, Display: display}, Profile: req.Profile})
	if err != nil {
		return nil, err
	}
	if podaro.Retirement().Template(plan.Template.Name) {
		// A directory whose lab.yaml declares a retired template's name —
		// a copy that kept its metadata.name. Validation has already
		// refused one that names a retired adapter, generator or module
		// (PDR-E106); this one names none, but an instance recorded under
		// the name would be one this release does not operate (PDR-E215),
		// so nothing is recorded (the reconciliation plan's R3).
		pe := pdr.New(pdr.CodeTemplateRetired, "template %q is a name the owner retired on %s", plan.Template.Name, podaro.Retirement().RetiredOn)
		pe.Cause = "the directory's lab.yaml declares metadata.name " + plan.Template.Name + " · podaro explain " + pdr.CodeTemplateRetired
		pe.Next = "give the template a name of its own (metadata.name), then podaro up again"
		return nil, pe
	}
	if stage != nil {
		// The module definitions the plan resolved are pinned beside the
		// template: the instance keeps running exactly what was admitted,
		// whatever a later binary's embedded library says (invariant 4).
		if err := src.library.Pin(stage.modules, moduleNames(plan)); err != nil {
			pe := pdr.New(pdr.CodeRuntimeFailed, "cannot pin the modules of %s", plan.Template.Name)
			pe.Cause = err.Error()
			return nil, pe
		}
	}
	name := req.Name
	if name == "" {
		// A generated name that is already taken is a collision, never
		// the instance the caller meant: draw again (bounded) rather than
		// answer 409 for, or resume, a lab nobody asked about.
		for attempt := 0; ; attempt++ {
			name = generateName(plan.Template.Name)
			if existing, err = e.lookup(name); err != nil {
				return nil, err
			}
			if existing == nil {
				break
			}
			if attempt >= 8 {
				pe := pdr.New(pdr.CodeRuntimeFailed, "could not find an unused instance name for %s", plan.Template.Name)
				pe.Next = "podaro up … --name NAME"
				return nil, pe
			}
		}
	}
	if !nameRe.MatchString(name) {
		return nil, badName(name)
	}
	if err := e.licenseGate(plan, req.AcceptLicenses); err != nil {
		return nil, err
	}
	if err := e.hostnameGate(name, plan); err != nil {
		return nil, err
	}
	if existing == nil {
		// A job recorded for this name without an instance is the window
		// between the two writes (a crash, or a store that refused the
		// second): retire it before the name is reused, so no restart
		// ever launches it against the replacement instance.
		if err := e.retireOrphan(name); err != nil {
			return nil, err
		}
	} else {
		// A failed create leaves the instance recorded so `podaro up` again
		// resumes at the failed step (Manual §8; the error anatomy's own
		// next line) — provided nothing is running and it is the same lab.
		if err := e.resumable(existing, plan, req, src.dir, mode); err != nil {
			return nil, err
		}
		// The licenses accepted on this attempt join the instance's record:
		// the job re-applies the gate to the plan it re-reads (D48).
		if added := mergeLicenses(existing.Licenses, presented(plan, req.AcceptLicenses)); len(added) != len(existing.Licenses) {
			newly := newIDs(existing.Licenses, added)
			existing.Licenses = added
			existing.Updated = time.Now().UTC()
			if err := e.opts.Store.PutInstance(*existing); err != nil {
				return nil, storeErr("record instance "+name, err)
			}
			if err := e.recordAcceptances(existing, newly, req.actor()); err != nil {
				return nil, err
			}
		}
		// The attempt is recorded before the labels its plan claims are
		// published, as a fresh create's is: a publication that outlived
		// the process with no durable job to drive it would leave a
		// product route standing that nothing admitted — a route on a row
		// whose port is already mapped is live at once, and a later start
		// finds the containers running and never reconciles it.
		// Both writes happen under the one admission lock, so
		// the order costs nothing.
		jobID, err := e.freshJobID()
		if err != nil {
			return nil, err
		}
		job := state.Job{ID: jobID, Kind: "create", Instance: name, Gen: existing.AuditFrom, State: state.JobQueued, Stage: "queued", Started: time.Now().UTC()}
		if err := e.opts.Store.PutJob(job); err != nil {
			return nil, storeErr("record job", err)
		}
		// The labels this attempt's plan claims are published here, under
		// the admission lock and before the attempt is launched (API
		// §7.1): a plan that gained a hostname since the last attempt is
		// reserved before any other admission can pass its gate against
		// the rows of the old plan — the worker re-applies the gate, but
		// the reservation must not wait for it.
		if err := e.publishPlanned(name, plan); err != nil {
			// The job never runs: it is failed here, so the name is not
			// left busy by a reservation that did not happen.
			e.abandon(job, err)
			return nil, err
		}
		e.opts.Logf("resuming create of %s after a failed attempt", name)
		e.launch(job)
		return &job, nil
	}

	source := src.dir
	if abs, err := filepath.Abs(source); err == nil {
		source = abs
	}
	instDir := e.instanceDir(name)
	if stage != nil {
		source = filepath.Join(instDir, "template")
	}
	// A directory this admission creates is this admission's to remove if
	// it fails before the instance is durable: uninstall counts every
	// directory under instances/ as a live instance, and status and
	// destroy would know nothing of this one.
	_, statErr := os.Stat(instDir)
	fresh := errors.Is(statErr, fs.ErrNotExist)
	discard := func() {
		if fresh {
			_ = os.RemoveAll(instDir)
		}
	}

	now := time.Now().UTC()
	// Where this instance's own audit rows begin. A destroy leaves the
	// rows behind — they are the security record — so an instance that
	// takes a name a previous one had needs a line between them, and it
	// is drawn here, once, at the moment the new one exists.
	//
	// A read that fails refuses the create. Falling back to zero was
	// worse than not creating the lab: zero means "everything", and it
	// would be written into the instance row permanently, so one
	// transient store error would hand the next attendee the previous
	// generation's joins and reveals for the life of the instance. A
	// create the operator can retry is the cheaper failure.
	// The create job is stamped with the generation it is creating: it
	// starts unknown, because the instance does not exist yet, and the
	// job's later writes carry the value from here on.
	auditFrom, err := e.opts.Store.LatestAuditSeq()
	if err != nil {
		return nil, storeErr("read the audit stream of "+name, err)
	}
	inst := state.Instance{
		Name: name, Template: plan.Template.Name, Version: plan.Template.Version,
		Mode: mode, Source: source, Created: now, Updated: now, Stage: state.StageNone,
		Licenses:  mergeLicenses(nil, presented(plan, req.AcceptLicenses)),
		AuditFrom: auditFrom,
	}
	if plan.Profile != nil {
		inst.Profile = plan.Profile.Name
	}
	// The queued job is the admission's first durable write — before
	// anything lands under instances/, before the instance: a crash
	// between the writes leaves a job that names the instance, fails with
	// "no such instance" on resume, and takes the directory it had moved
	// into place with it (createSteps) — the name stays free, uninstall
	// counts no ghost — never an instance nobody will ever drive. The
	// reverse window — an instance without a job — is recovered by
	// resumable() as well.
	jobID, err := e.freshJobID()
	if err != nil {
		return nil, err
	}
	job := state.Job{ID: jobID, Kind: "create", Instance: name, Gen: auditFrom, State: state.JobQueued, Stage: "queued", Started: now}
	if err := e.opts.Store.PutJob(job); err != nil {
		return nil, storeErr("record job", err)
	}
	if stage != nil {
		// Delivery instances pin a snapshot: immune to catalog updates by
		// construction (roadmap §7). The staged copy is moved into place
		// whole, replacing whatever a failed admission left: a stale
		// snapshot is never copied *over* — files the catalog no longer
		// carries would otherwise survive into the new instance.
		if err := stage.install(instDir); err != nil {
			e.abandon(job, err)
			discard()
			return nil, err
		}
	} else if err := os.MkdirAll(instDir, 0o700); err != nil {
		e.abandon(job, err)
		discard()
		return nil, err
	}
	// The acceptances this create carries are recorded now — in the audit
	// stream and in the instance's evidence (API §6.2: explicit, per
	// create, with actor and timestamp) — while the admission can still be
	// abandoned whole: a record the store refuses stops the create before
	// the instance is durable, and the directory the journal wrote into
	// goes with the admission.
	if err := e.recordAcceptances(&inst, inst.Licenses, req.actor()); err != nil {
		e.abandon(job, err)
		discard()
		return nil, err
	}
	if err := e.opts.Store.PutInstance(inst); err != nil {
		e.abandon(job, storeErr("record instance "+name, err))
		discard()
		return nil, storeErr("record instance "+name, err)
	}
	// The instance is durable from here: its record points at this
	// directory (the snapshot and the pinned modules for a delivery
	// instance), and a failure past this point leaves a failed job that
	// the next `podaro up` resumes from exactly that source. The directory
	// is the instance's now, not this admission's to remove.
	fresh = false
	if err := e.publishPlanned(name, plan); err != nil {
		// The job re-derives every service from the plan on resume, so
		// a missing row is recovered; the snapshot it re-reads is kept.
		e.abandon(job, err)
		return nil, err
	}
	e.launch(job)
	return &job, nil
}

// abandon marks a queued job that will never be launched as failed, best
// effort: the store just refused a write, so this one may fail too — in
// which case retireOrphan (a retry) or resumable (a restart) finds the
// driverless record and retires it before anything reuses the slot.
func (e *Engine) abandon(job state.Job, cause error) {
	now := time.Now().UTC()
	job.State, job.Stage, job.Finished, job.Error = state.JobFailed, "failed", &now, envelope(cause)
	if err := e.opts.Store.PutJob(job); err != nil {
		e.opts.Logf("job %s for %s abandoned but not recorded: %v", job.ID, job.Instance, err)
	}
}

// retireOrphan clears an active job recorded for a name that has no
// instance: activeJob retires a driverless record; one this process is
// still driving (it fails on its own, finding no instance) is busy.
func (e *Engine) retireOrphan(name string) error {
	orphan, err := e.activeJob(name)
	if err != nil {
		return err
	}
	if orphan != nil {
		return e.busy(name, orphan)
	}
	return nil
}

// activeJob is the exclusive-slot lookup (API §4). A store fault is an
// error, never a free slot. An active record that no goroutine of this
// engine drives is a job that is over — its terminal write was refused
// (the outcome is kept in unrecorded) or the process that queued it
// never launched it — and is retired here rather than left to hold the
// slot until a restart re-walks it.
func (e *Engine) activeJob(name string) (*state.Job, error) {
	active, err := e.opts.Store.ActiveJob(name)
	if err != nil {
		return nil, storeErr("look up the active job of "+name, err)
	}
	if active == nil || e.isRunning(active.ID) {
		return active, nil
	}
	final, known := e.knownOutcome(active.ID)
	if !known && e.wasDriven(active.ID) {
		// Launched here and still without an outcome: the engine is
		// stopping and run left the record running on purpose (the next
		// start resumes it). The slot is held, not freed.
		return active, nil
	}
	if !known {
		now := time.Now().UTC()
		final = *active
		final.State, final.Stage, final.Finished = state.JobFailed, "failed", &now
		pe := pdr.New(pdr.CodeRuntimeFailed, "%s job %s was recorded but never driven", active.Kind, active.ID)
		pe.Next = "podaro status " + name + " · re-run the command"
		final.Error = pe
	}
	if err := e.opts.Store.PutJob(final); err != nil {
		return nil, storeErr("record job "+final.ID, err)
	}
	e.forgetOutcome(final.ID)
	if !known {
		if err := e.event(final.ID, "job", "", "failed", "recorded but never driven; retired"); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// wasDriven reports whether this process launched the job and has not
// landed a terminal record for it.
func (e *Engine) wasDriven(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.driven[id]
	return ok
}

func (e *Engine) isRunning(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.running[id]
	return ok
}

func (e *Engine) knownOutcome(id string) (state.Job, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	j, ok := e.unrecorded[id]
	return j, ok
}

func (e *Engine) forgetOutcome(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.unrecorded, id)
}

// presented keeps only the accepted ids the plan actually declares: an
// acceptance is recorded for terms that were shown, never for an id a
// template might grow later (that one is presented, and gated, then).
func presented(plan *lab.Plan, accepted []string) []string {
	declared := map[string]bool{}
	for _, l := range plan.Licenses {
		declared[l.ID] = true
	}
	var out []string
	for _, id := range accepted {
		if declared[id] {
			out = append(out, id)
		}
	}
	return out
}

// staging is a delivery snapshot under admission: the template copy and
// the module definitions pinned for it, built under STATE_DIR/staging/ —
// outside instances/, so a process that dies mid-copy leaves a leftover
// the next Start sweeps, never a directory that uninstall counts as a
// live instance — and moved into the instance's directory only after
// the job that names the instance is durable.
type staging struct {
	root, template, modules string
}

func (e *Engine) stagingDir() string { return filepath.Join(e.opts.StateDir, "staging") }

// stageSnapshot copies the template at dir into a fresh staging
// directory. A source that contains the state directory would be copied
// into itself (the walk would meet its own destination): it is refused —
// on physical paths, so a symlinked state directory cannot hide inside
// the source. Not being able to resolve either is a refusal.
func (e *Engine) stageSnapshot(dir string) (*staging, error) {
	if err := os.MkdirAll(e.opts.StateDir, 0o700); err != nil {
		return nil, err
	}
	realState, err1 := filepath.EvalSymlinks(e.opts.StateDir)
	realDir, err2 := filepath.EvalSymlinks(dir)
	if err1 != nil || err2 != nil || within(filepath.Join(realState, "staging"), realDir) {
		pe := pdr.New(pdr.CodeInstanceName, "cannot snapshot %s: it contains the state directory %s", dir, e.opts.StateDir)
		pe.Next = "run the template from a directory outside the state directory, or use authoring mode (podaro up DIR)"
		if err1 != nil || err2 != nil {
			pe.Message = fmt.Sprintf("cannot snapshot %s: the paths could not be resolved", dir)
			pe.Cause = errors.Join(err1, err2).Error()
		}
		return nil, pe
	}
	if err := os.MkdirAll(e.stagingDir(), 0o700); err != nil {
		return nil, err
	}
	root, err := os.MkdirTemp(e.stagingDir(), "snapshot-")
	if err != nil {
		return nil, err
	}
	s := &staging{root: root, template: filepath.Join(root, "template"), modules: filepath.Join(root, "modules")}
	if err := copyTree(dir, s.template); err != nil {
		s.discard()
		pe := pdr.New(pdr.CodeRuntimeFailed, "cannot snapshot the template at %s", dir)
		pe.Cause = err.Error()
		return nil, pe
	}
	if err := os.MkdirAll(s.modules, 0o700); err != nil { // empty for a template of inline services
		s.discard()
		return nil, err
	}
	return s, nil
}

// discard removes whatever the admission did not move into its instance.
func (s *staging) discard() { _ = os.RemoveAll(s.root) }

// install moves the staged template and modules into the instance's
// directory, each replacing what a failed admission may have left there
// — never copied over it, so a file the catalog no longer carries never
// survives into the new instance.
func (s *staging) install(instDir string) error {
	if err := os.MkdirAll(instDir, 0o700); err != nil {
		return err
	}
	for _, part := range []struct{ from, name string }{{s.template, "template"}, {s.modules, "modules"}} {
		dst := filepath.Join(instDir, part.name)
		if err := os.RemoveAll(dst); err != nil {
			return err
		}
		if err := os.Rename(part.from, dst); err != nil {
			pe := pdr.New(pdr.CodeRuntimeFailed, "cannot move the snapshot into %s", instDir)
			pe.Cause = err.Error()
			return pe
		}
	}
	return nil
}

// sweepStaging removes what STATE_DIR/staging/ holds. An admission stages
// its snapshot there and takes it away before it returns, so at start —
// no admission in flight — anything there was left by a process that
// died mid-admission: never an instance (nothing under instances/, no
// record naming it), removed without ceremony. A leftover that cannot be
// removed is reported, not fatal: it holds no lab and uninstall never
// counts it.
func (e *Engine) sweepStaging() {
	e.jobMu.Lock()
	defer e.jobMu.Unlock()
	dir := e.stagingDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			e.opts.Logf("staging: %v", err)
		}
		return
	}
	for _, en := range entries {
		p := filepath.Join(dir, en.Name())
		if err := os.RemoveAll(p); err != nil {
			e.opts.Logf("staging: cannot remove %s: %v", p, err)
			continue
		}
		e.opts.Logf("swept %s: a snapshot staged by an interrupted create", p)
	}
}

// removeAdmissionLeftover is Create's crash window: the job is the
// admission's first durable write and the instance its last, so a create
// job with no instance behind it is an admission that died between the
// two — and the directory it had moved into place under instances/ is
// that death's only trace: no record names it, status and destroy know
// nothing of it, uninstall would count it as a live instance. It goes
// with the job's failure, journaled first (a refused line leaves it for
// `podaro up --name` to replace), so the name is free and nothing is
// left to guess at.
func (e *Engine) removeAdmissionLeftover(job *state.Job) error {
	dir := e.instanceDir(job.Instance)
	if _, err := os.Stat(dir); err != nil {
		return nil
	}
	if err := e.event(job.ID, "instance", "", "failed", "no instance was recorded; removing "+dir+", left by the interrupted admission"); err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove %s: %w", dir, err)
	}
	return nil
}

// within reports whether path lies inside dir (or is dir), by lexical
// path comparison of absolute forms.
func within(path, dir string) bool {
	ap, err1 := filepath.Abs(path)
	ad, err2 := filepath.Abs(dir)
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(ad, ap)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// moduleNames lists the library modules the plan's services use, sorted
// and deduplicated; inline services (no module) contribute nothing. A
// reference is normalized to the library's directory name.
func moduleNames(plan *lab.Plan) []string {
	seen := map[string]bool{}
	var names []string
	for _, ps := range plan.Services {
		name := strings.TrimPrefix(ps.Module, "modules/")
		if i := strings.IndexByte(name, '@'); i >= 0 {
			name = name[:i]
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// libraryFor is the module library an instance's jobs plan against: a
// delivery instance resolves against the definitions pinned with its
// snapshot (invariant 4); an authoring instance tracks the engine's.
func (e *Engine) libraryFor(inst *state.Instance) (*lab.Library, error) {
	if inst.Mode != state.ModeDelivery {
		return e.opts.Library, nil
	}
	// Only the pinned copy: a pinned library that is gone (a partial
	// state restore) is damage to report, never a reason to plan against
	// the engine's library, whose module of the same name and version may
	// differ from what was admitted (invariant 4).
	pinned := filepath.Join(e.instanceDir(inst.Name), "modules")
	if fi, err := os.Stat(pinned); err != nil || !fi.IsDir() {
		pe := pdr.New(pdr.CodeRuntimeFailed, "the pinned module library of %s is missing", inst.Name)
		pe.Cause = pinned + " is not a directory; a delivery instance runs only the module definitions admitted with it"
		pe.Next = "restore " + pinned + " from a state backup · or destroy " + inst.Name + " and create it anew"
		return nil, pe
	}
	return lab.DirLibrary(pinned), nil
}

// newIDs returns the ids of all that have does not hold.
func newIDs(have, all []string) []string {
	seen := map[string]bool{}
	for _, id := range have {
		seen[id] = true
	}
	var out []string
	for _, id := range all {
		if !seen[id] {
			out = append(out, id)
		}
	}
	return out
}

// recordAcceptances audits each licence accepted for an instance (API
// §6.2: acceptance is explicit, per create, recorded in evidence with
// actor and timestamp): one record per id in the audit stream, mirrored
// into the instance's evidence journal as a reveal is — the id, never
// the terms' text, and no value of any kind. Nothing is recorded for an
// id the plan did not present (presented) or the record already held.
func (e *Engine) recordAcceptances(inst *state.Instance, ids []string, by Actor) error {
	now := time.Now().UTC()
	for _, id := range ids {
		rec := state.Audit{At: now, Instance: inst.Name, Action: "accept-license", Actor: by.Subject, Mechanism: by.Mechanism, Detail: id}
		if err := e.opts.Store.AppendAudit(rec); err != nil {
			return storeErr("audit the acceptance of "+id, err)
		}
		entry := evidence.Entry{Type: evidence.TypeAudit, Instance: inst.Name, At: now, Authoring: inst.Mode == state.ModeAuthoring, Audit: &rec}
		if _, err := e.journal(inst.Name).Append(entry); err != nil {
			e.opts.Logf("%s: evidence: %v", inst.Name, err)
		}
	}
	return nil
}

// mergeLicenses returns have plus every id of more not yet in it, sorted.
func mergeLicenses(have, more []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range append(append([]string{}, have...), more...) {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// DefaultProbeInterval is the readiness probe cadence for a service whose
// readiness declares no interval: the module schema's default (spec 0003
// §9.2, `interval` default 5s). Options.PollInterval overrides it.
const DefaultProbeInterval = 5 * time.Second

// probeInterval is the cadence the probe runs at: the declared
// readiness.interval when present, else the engine's fallback — which is
// the schema default unless an operator or test set Options.PollInterval.
func probeInterval(readiness *lab.Readiness, fallback time.Duration) time.Duration {
	if readiness != nil {
		if d, err := parseDuration(readiness.Interval); err == nil && d > 0 {
			return d
		}
	}
	if fallback <= 0 {
		return DefaultProbeInterval
	}
	return fallback
}

// storeErr wraps a persistence fault as the runtime-failed envelope.
func storeErr(op string, err error) error {
	pe := pdr.New(pdr.CodeRuntimeFailed, "%s failed", op)
	pe.Cause = err.Error()
	pe.Next = "check the state database (journalctl --user -u podaro) and re-run"
	return pe
}

// resumable decides whether an existing instance may be re-created in
// place: no active job, its last job failed, and the request names the
// same template (and mode, when given). Otherwise the name is taken.
// lookup returns the instance of that name, nil when there is none, and a
// store fault as an error: a fault is never "the name is free", so no
// admission ever upserts over what may be there.
func (e *Engine) lookup(name string) (*state.Instance, error) {
	inst, err := e.opts.Store.GetInstance(name)
	if errors.Is(err, state.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, storeErr("look up instance "+name, err)
	}
	return inst, nil
}

func badName(name string) error {
	e := pdr.New(pdr.CodeInstanceName, "instance name %q is not a lowercase DNS label of at most 24 characters", name)
	e.Next = "choose a name like pii-lab"
	return e
}

func (e *Engine) resumable(inst *state.Instance, plan *lab.Plan, req CreateRequest, dir string, mode state.Mode) error {
	taken := func(cause string) error {
		pe := pdr.New(pdr.CodeInstanceExists, "instance %q already exists", inst.Name)
		pe.Cause = cause
		pe.Next = "podaro status " + inst.Name + " · or destroy it first"
		return pe
	}
	active, err := e.activeJob(inst.Name)
	if err != nil {
		return err
	}
	if active != nil {
		return taken(fmt.Sprintf("its %s job %s is %s", active.Kind, active.ID, active.State))
	}
	jobs, err := e.opts.Store.ListJobs(inst.Name)
	if err != nil {
		return storeErr("list jobs of "+inst.Name, err)
	}
	// No job at all is the crash window between recording the instance
	// and its job (or a job write that failed): recoverable, like a failed
	// create.
	if len(jobs) > 0 && (jobs[0].State != state.JobFailed || (jobs[0].Kind != "create" && jobs[0].Kind != "reconcile")) {
		return taken("its last job succeeded; a running lab is never re-created in place")
	}
	if inst.Template != plan.Template.Name || inst.Version != plan.Template.Version {
		return taken(fmt.Sprintf("it runs template %s@%s, not %s@%s", inst.Template, inst.Version, plan.Template.Name, plan.Template.Version))
	}
	profile := ""
	if plan.Profile != nil {
		profile = plan.Profile.Name
	}
	if inst.Profile != profile {
		return taken(fmt.Sprintf("it was created with profile %q, not %q", inst.Profile, profile))
	}
	if mode != inst.Mode {
		return taken(fmt.Sprintf("it is a %s instance; modes never switch in place", inst.Mode))
	}
	if mode == state.ModeAuthoring {
		if abs, err := filepath.Abs(dir); err != nil || abs != inst.Source {
			return taken(fmt.Sprintf("it tracks %s, not %s", inst.Source, dir))
		}
	}
	return nil
}

// source is what a create request resolves to: the directory to plan
// from, the mode it implies (path → authoring, catalog → delivery), the
// module library to plan it with, and whether that directory is already
// the instance's own pinned snapshot (a delivery retry, D60) rather than
// a live template to snapshot.
type source struct {
	dir     string
	mode    state.Mode
	library *lab.Library
	pinned  bool
}

// resolveSource maps the request to its source.
//
// A delivery instance already recorded under the requested name, for the
// requested template, is planned from its own snapshot and pinned modules
// — not from the catalog, and not from the directory a `--mode delivery`
// request names. A retry after a failed create (Manual §8) must meet
// exactly what was admitted, and the catalog entry or the directory may
// have been upgraded or removed since; the instance is immune to both by
// construction (roadmap §7; invariant 4). Whether the retry is admissible
// at all is resumable()'s call. Another template under a taken name still
// resolves against the catalog or the directory and is refused there. The
// catalog key is the entry's directory, the instance records the
// template's name; the catalog templates and `podaro catalog` keep the
// two the same.
func (e *Engine) resolveSource(req CreateRequest, existing *state.Instance) (source, error) {
	if req.Path != "" && req.Template != "" {
		// The documented alternatives (API §7.1): a request naming both
		// would have the engine guess which lab was meant.
		pe := pdr.New(pdr.CodeCreateRequest, "template %q and path %q are alternatives; the request names both", req.Template, req.Path)
		pe.Next = "send template or path, not both · podaro up <template|dir>"
		return source{}, pe
	}
	if req.Path == "" && req.Template == "" {
		// Nothing was looked up, so nothing is "not found": the request
		// names no source at all.
		pe := pdr.New(pdr.CodeCreateRequest, "no template or path given")
		pe.Next = "podaro up <template|dir>"
		return source{}, pe
	}
	if req.Template != "" && podaro.Retirement().Template(req.Template) {
		// A template the owner retired (the retirement manifest the binary
		// embeds) is refused by name, before any catalog lookup or
		// validation: whatever an earlier build left in the catalog, it is
		// never offered, recreated or repaired (the reconciliation plan's R2).
		pe := pdr.New(pdr.CodeTemplateRetired, "template %q was retired by the owner on %s", req.Template, podaro.Retirement().RetiredOn)
		pe.Cause = "no release carries it · installed catalog: " + strings.Join(e.offeredCatalog(), ", ") + " · podaro explain " + pdr.CodeTemplateRetired
		pe.Next = "podaro up <one of those> · or podaro up ./path/to/template"
		return source{}, pe
	}
	deliveryWanted := req.Template != "" || state.Mode(req.Mode) == state.ModeDelivery
	if existing != nil && existing.Mode == state.ModeDelivery && deliveryWanted && sameTemplate(req, existing) {
		if fi, err := os.Stat(filepath.Join(existing.Source, "lab.yaml")); err == nil && !fi.IsDir() {
			lib, err := e.libraryFor(existing)
			if err != nil {
				return source{}, err
			}
			return source{dir: existing.Source, mode: state.ModeDelivery, library: lib, pinned: true}, nil
		}
	}
	if req.Path != "" {
		fi, err := os.Stat(req.Path)
		if err != nil || !fi.IsDir() {
			pe := pdr.New(pdr.CodeTemplateNotFound, "%s is not a template directory", req.Path)
			pe.Next = "podaro up ./path/to/template — a directory holding lab.yaml"
			return source{}, pe
		}
		return source{dir: req.Path, mode: state.ModeAuthoring, library: e.opts.Library}, nil
	}
	if !nameRe.MatchString(req.Template) || e.opts.CatalogDir == "" {
		return source{}, e.templateNotFound(req.Template)
	}
	dir := filepath.Join(e.opts.CatalogDir, req.Template)
	if fi, err := os.Stat(filepath.Join(dir, "lab.yaml")); err != nil || fi.IsDir() {
		return source{}, e.templateNotFound(req.Template)
	}
	return source{dir: dir, mode: state.ModeDelivery, library: e.opts.Library}, nil
}

// sameTemplate reports whether the request names the template the
// instance runs: by catalog name, or — for a path — by the name the
// directory declares now. A directory that is gone names nothing else, so
// the snapshot is the way back; one that declares another template is
// another lab, refused by resumable() against the plan it yields.
func sameTemplate(req CreateRequest, inst *state.Instance) bool {
	if req.Template != "" {
		return req.Template == inst.Template
	}
	raw, err := os.ReadFile(filepath.Join(req.Path, "lab.yaml"))
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	if err != nil {
		return false
	}
	var doc struct {
		Metadata lab.Metadata `yaml:"metadata"`
	}
	return yaml.Unmarshal(raw, &doc) == nil && doc.Metadata.Name == inst.Template
}

func (e *Engine) templateNotFound(name string) *pdr.Error {
	pe := pdr.New(pdr.CodeTemplateNotFound, "template %q is not installed", name)
	pe.Cause = "installed catalog: " + strings.Join(e.offeredCatalog(), ", ")
	pe.Next = "podaro up <one of those> · or podaro up ./path/to/template"
	return pe
}

// offeredCatalog is the installed catalog less any template the
// retirement manifest lists — what a refusal may offer instead (the
// reconciliation plan's R3: a retired entry an earlier build left in the
// catalog is never offered, on this line or any other).
func (e *Engine) offeredCatalog() []string {
	offered, _ := podaro.Retirement().Catalog(e.CatalogNames())
	return offered
}

// CatalogNames lists installed templates.
func (e *Engine) CatalogNames() []string {
	entries, err := os.ReadDir(e.opts.CatalogDir)
	if err != nil {
		return nil
	}
	var names []string
	for _, en := range entries {
		if en.IsDir() {
			if _, err := os.Stat(filepath.Join(e.opts.CatalogDir, en.Name(), "lab.yaml")); err == nil {
				names = append(names, en.Name())
			}
		}
	}
	sort.Strings(names)
	return names
}

// hostnameGate refuses a plan whose gateway hostnames collide with a
// running instance's. An instance claims `<instance>` and, for every
// embeddable `ui` service, `<service>-<instance>` (User Manual §5) — one
// DNS label each, and both halves may contain hyphens, so `web` on
// `api-lab` and `web-api` on `lab` would both spell web-api-lab, and the
// gateway could route only one of them. Applied
// at admission and again by the job to the plan it re-reads (D48).
func (e *Engine) hostnameGate(name string, plan *lab.Plan) error {
	labels := []string{name}
	for _, ps := range plan.Services {
		if uiPort(ps) > 0 && ps.Embed != "api-only" {
			labels = append(labels, ps.Name+"-"+name)
		}
	}
	mine := map[string]bool{}
	for _, h := range labels {
		// Each is one DNS label: a service name may be 63 characters on
		// its own, so the pair must be checked, not the halves.
		if len(h) > 63 {
			pe := pdr.New(pdr.CodeInstanceName, "hostname %s is %d characters; a DNS label holds 63", h, len(h))
			pe.Cause = "<service>-<instance> is one DNS label: the service name and the instance name must fit in 63 characters together"
			pe.Next = "choose a shorter name: podaro up … --name NAME"
			return pe
		}
		mine[h] = true
	}
	instances, err := e.opts.Store.ListInstances()
	if err != nil {
		return storeErr("list instances", err)
	}
	for _, other := range instances {
		if other.Name == name {
			continue
		}
		theirs := []string{other.Name}
		services, err := e.opts.Store.ListServices(other.Name)
		if err != nil {
			return storeErr("list services of "+other.Name, err)
		}
		for _, svc := range services {
			if svc.UIPort > 0 && svc.Embed != "api-only" {
				theirs = append(theirs, svc.Name+"-"+other.Name)
			}
		}
		for _, h := range theirs {
			if mine[h] {
				pe := pdr.New(pdr.CodeInstanceName, "instance %q would share the hostname %s with instance %q", name, h, other.Name)
				pe.Cause = "<instance> and <service>-<instance> are single DNS labels whose halves may contain hyphens, so two labs can spell the same hostname"
				pe.Next = "choose another name: podaro up … --name NAME"
				return pe
			}
		}
	}
	return nil
}

// licenseGate is API §6.2: every EULA the plan lists must be accepted
// explicitly for this create.
func (e *Engine) licenseGate(plan *lab.Plan, accepted []string) error {
	ok := map[string]bool{}
	for _, id := range accepted {
		ok[id] = true
	}
	var missing []pdr.Detail
	for _, l := range plan.Licenses {
		if !ok[l.ID] {
			missing = append(missing, pdr.Detail{License: l.ID, URL: l.URL}) // API §6.2's shape
		}
	}
	if len(missing) == 0 {
		return nil
	}
	pe := pdr.New(pdr.CodeLicenseRequired, "license acceptance required")
	pe.Details = missing
	var ids []string
	for _, d := range missing {
		ids = append(ids, d.License)
	}
	pe.Next = "re-run with --accept-license " + strings.Join(ids, " --accept-license ") + " (podaro up prompts interactively on a TTY)"
	return pe
}

// Destroy records and starts the destroy job; confirm must equal the name
// (API §7: the API-level echo of the CLI's type-the-name ceremony).
// Actor is who asked for an act the audit stream records (API §2.5): a
// principal's subject and mechanism, or the local socket door, where the
// operating-system user is the credential.
// unknownGen marks a job whose generation is not (yet) known: a create
// before its instance exists, or a row written before the column did. An
// audit sequence is never negative, so it matches no generation — such a
// job is the operator's to see and nobody else's.
const unknownGen = -1

type Actor struct {
	Subject   string
	Mechanism string
	// Gen is the generation of the instance this actor is entitled to,
	// when it is entitled to one in particular: an attendee's session is
	// opened against one lab, and a name can come back. nil is the
	// operator, who is bound to no generation.
	//
	// It is compared *inside* the operation's own instance resolution,
	// not before it. A check that resolves the instance, compares, and
	// lets the operation resolve it again is a check with a window in
	// it — which is what rounds 11 and 12 kept discovering from the
	// other side.
	Gen *int64
}

// Socket is the actor of the local door.
var Socket = Actor{Mechanism: "socket"}

// Destroy is DestroyAs on the local door.
func (e *Engine) Destroy(ctx context.Context, name, confirm string) (*state.Job, error) {
	return e.DestroyAs(ctx, name, confirm, Socket)
}

// DestroyAs admits a destroy asked for by an actor and starts its job.
func (e *Engine) DestroyAs(ctx context.Context, name, confirm string, by Actor) (*state.Job, error) {
	// Admission is one critical section (API §4's exclusive slot), the
	// lookup and the repair decision included: a repair for a name whose
	// instance is gone must not observe that state, yield to a create of
	// the same name, and then destroy the replacement.
	e.jobMu.Lock()
	defer e.jobMu.Unlock()
	// The slot before the instance: a job runs outside this lock, so a
	// destroy that finishes between the two reads — the instance looked
	// up present, then gone with its job done — must not let a second
	// destroy through on a slot the first has just freed (the concurrency test caught it under the race detector).
	// Read this
	// way round, a finished first destroy leaves the second to find no
	// instance, and a running one holds the slot.
	active, err := e.activeJob(name)
	if err != nil {
		return nil, err
	}
	if active != nil {
		return nil, e.busy(name, active)
	}
	inst, err := e.opts.Store.GetInstance(name)
	if errors.Is(err, state.ErrNotFound) {
		// A destroy that removed the instance but could not land its own
		// completion (a journal or terminal write refused, D49) is
		// repaired by destroying again: the job re-walks, finds nothing
		// left, and records the success. Only that case is admitted for
		// a name with no instance; anything else is not found.
		jobs, jerr := e.opts.Store.ListJobs(name)
		if jerr != nil {
			return nil, storeErr("list jobs of "+name, jerr)
		}
		if len(jobs) > 0 {
			if final, ok := e.knownOutcome(jobs[0].ID); ok {
				jobs[0] = final // the store still says active; the engine knows better (D30)
			}
		}
		if len(jobs) == 0 || jobs[0].Kind != "destroy" || jobs[0].State != state.JobFailed {
			return nil, e.notFound(name)
		}
		inst = &state.Instance{Name: name}
	} else if err != nil {
		// A store fault is not absence (D27): never answer 404 for a
		// lookup that did not happen.
		return nil, storeErr("look up instance "+name, err)
	}
	if confirm != inst.Name {
		pe := pdr.New(pdr.CodeDestroyConfirm, "confirm %q does not match instance %q", confirm, inst.Name)
		pe.Next = "type the instance name exactly"
		return nil, pe
	}
	jobID, err := e.freshJobID()
	if err != nil {
		return nil, err
	}
	job := state.Job{ID: jobID, Kind: "destroy", Instance: name, Gen: inst.AuditFrom, State: state.JobQueued, Stage: "queued", Started: time.Now().UTC()}
	// The destroy is audited before it exists (API §2.5): who asked,
	// through what, and the job that will carry it out — in the system
	// stream, which outlives the instance and its evidence. The record
	// precedes the job record, so no destroy job — resumable after a
	// restart or not — ever exists without its record: a record the
	// stream refuses stops the destroy before anything is written, and
	// a job the store then refuses leaves the record standing as that of
	// an attempt that was not admitted.
	if err := e.opts.Store.AppendAudit(state.Audit{At: job.Started, Action: "destroy", Actor: by.Subject, Mechanism: by.Mechanism, Detail: "instance " + name + " · job " + job.ID}); err != nil {
		return nil, storeErr("audit the destroy of "+name, err)
	}
	if err := e.opts.Store.PutJob(job); err != nil {
		return nil, storeErr("record job", err)
	}
	e.launch(job)
	return &job, nil
}

// backfillGatewayFacts derives the ui facts the gateway routes on for an
// instance that predates them. A database written before S5 has them at
// zero (migration 4 adds the columns with defaults) and a healthy
// instance is never reconciled, so without this its product hostnames
// would never be published and its console would show no product URLs —
// with no way to repair it in place, a completed instance having nothing
// left to run. Which instances owe the facts is *recorded* by that
// migration, never read off the rows: a service that declares no ui
// endpoint carries the same zeros as a row the backfill never reached,
// and telling the two apart by value would re-derive a stable instance
// at every start — and, for an authoring instance, from a working
// directory that may have changed while the engine was down, publishing
// a route no job ever admitted. The facts come from
// the plan (the read every job makes), the hostname gate judges them as
// it would at a create — two instances from before the gate existed may
// claim one hostname, and the second keeps none rather than making the
// router ambiguous — and they are published under the admission lock,
// each row keeping the route it holds (putService). The mark is cleared
// only once they are published, so a backfill interrupted between two
// rows is finished by the next start.
func (e *Engine) backfillGatewayFacts(inst *state.Instance, services []state.Service) error {
	pending, err := e.opts.Store.GatewayBackfill(inst.Name)
	if err != nil {
		return storeErr("read the gateway backfill mark of "+inst.Name, err)
	}
	if !pending {
		return nil
	}
	if len(services) == 0 {
		// Nothing is recorded to carry the facts: an instance whose create
		// never wrote a service row owes nothing, and the create that
		// resumes writes them itself.
		return e.opts.Store.SetGatewayBackfill(inst.Name, false)
	}
	library, err := e.libraryFor(inst)
	if err != nil {
		return err
	}
	plan, _, err := lab.MakePlan(lab.PlanOptions{Options: lab.Options{Path: inst.Source, Library: library}, Profile: inst.Profile})
	if err != nil {
		return err
	}
	e.jobMu.Lock()
	defer e.jobMu.Unlock()
	if err := e.hostnameGate(inst.Name, plan); err != nil {
		return err
	}
	// publishPlanned clears the mark once the facts are on every row, so
	// a backfill interrupted between two of them leaves it standing and
	// the next start finishes the instance (round 24).
	return e.publishPlanned(inst.Name, plan)
}

// reserveHostnames re-applies the hostname gate against the plan an
// attempt re-read and publishes every planned service's facts — the rows
// every other admission's gate reads — under the admission lock, so the
// labels this plan claims are taken from the moment they are admitted.
func (e *Engine) reserveHostnames(inst *state.Instance, plan *lab.Plan) error {
	e.jobMu.Lock()
	defer e.jobMu.Unlock()
	if err := e.hostnameGate(inst.Name, plan); err != nil {
		return err
	}
	return e.publishPlanned(inst.Name, plan)
}

// publishPlanned records every service the plan declares — a fresh row
// with the plan's facts, or the existing row with them refreshed — so the
// labels the plan claims (the ui port and embed the hostname gate reads)
// are visible to every other admission. Callers hold jobMu.
func (e *Engine) publishPlanned(name string, plan *lab.Plan) error {
	services, err := e.opts.Store.ListServices(name)
	if err != nil {
		return storeErr("list services of "+name, err)
	}
	byName := map[string]state.Service{}
	for _, s := range services {
		byName[s.Name] = s
	}
	// What each row held before this publication, so a write that fails
	// part way through takes back the rows that landed: a row whose host
	// port is already mapped is routed the moment it gains a ui port, and
	// a half-published plan under a job about to be abandoned would leave
	// that route with nothing to complete or remove it — a start finds
	// the containers running and never reconciles them.
	// Best effort by construction: a rollback write that fails too
	// is logged, not hidden.
	type published struct {
		before state.Service
		fresh  bool // the row did not exist before this call
	}
	var landed []published
	rollback := func() {
		for i := len(landed) - 1; i >= 0; i-- {
			p := landed[i]
			if p.fresh {
				if err := e.opts.Store.DeleteService(name, p.before.Name); err != nil {
					e.opts.Logf("%s: the row published for %s could not be taken back: %v", name, p.before.Name, err)
				}
				continue
			}
			row := p.before
			if err := e.putService(&row); err != nil {
				e.opts.Logf("%s: the facts published for %s could not be put back: %v", name, p.before.Name, err)
			}
		}
	}
	for _, ps := range plan.Services {
		svc, ok := byName[ps.Name]
		if !ok {
			svc = state.Service{Instance: name, Name: ps.Name, Container: containerName(name, ps.Name), Stage: state.StageNone}
		}
		before := svc
		svc.Module, svc.Image = ps.Module, ps.Image.Ref()
		svc.UIPort, svc.UIScheme, svc.Embed = uiPort(ps), uiScheme(ps), ps.Embed
		svc.Typical, svc.Budget = "", ""
		if ps.Readiness != nil {
			svc.Typical, svc.Budget = ps.Readiness.Typical, budgetOf(ps.Readiness)
		}
		if err := e.putService(&svc); err != nil {
			rollback()
			return storeErr("record service "+ps.Name, err)
		}
		landed = append(landed, published{before: before, fresh: !ok})
	}
	// Publishing the plan's facts is exactly what the backfill mark asks
	// for, so whoever publishes them clears it — a job a shutdown
	// interrupted is resumed by the next start, which skips the backfill
	// for an instance whose job it resumes, and a mark left standing
	// would have the start after that derive the facts again: for an
	// authoring instance, from a working directory that may have changed
	// since. An instance destroyed meanwhile has no
	// mark to clear.
	if err := e.opts.Store.SetGatewayBackfill(name, false); err != nil && !errors.Is(err, state.ErrNotFound) {
		rollback()
		return storeErr("clear the gateway backfill mark of "+name, err)
	}
	return nil
}

func (e *Engine) notFound(name string) *pdr.Error {
	pe := pdr.New(pdr.CodeInstanceNotFound, "no such instance %q", name)
	pe.Next = "podaro status"
	return pe
}

func (e *Engine) busy(name string, active *state.Job) *pdr.Error {
	pe := pdr.New(pdr.CodeInstanceBusy, "instance %q is busy: %s job %s is %s", name, active.Kind, active.ID, active.State)
	pe.Cause = active.Stage
	pe.Next = "podaro status " + name
	pe.Details = []pdr.Detail{{Path: "job", Hint: active.ID}}
	return pe
}

// Job returns one job.
func (e *Engine) Job(id string, by Actor) (*state.Job, error) {
	if final, ok := e.knownOutcome(id); ok {
		// The store still says active; the engine knows better.
		return &final, nil
	}
	j, err := e.opts.Store.GetJob(id)
	if errors.Is(err, state.ErrNotFound) {
		pe := pdr.New(pdr.CodeInstanceNotFound, "no such job %q", id)
		pe.Next = "podaro status"
		return nil, pe
	}
	if err != nil {
		return nil, storeErr("look up job "+id, err)
	}
	// A destroy keeps an instance's jobs, so a name used twice has jobs
	// from more than one lab. A bearer entitled to one generation is
	// told about that one's jobs and no others.
	if by.Gen != nil && j.Gen != *by.Gen {
		pe := pdr.New(pdr.CodeInstanceNotFound, "no such job %q", id)
		pe.Next = "podaro status"
		return nil, pe
	}
	return j, nil
}

// Events returns a job's journal; a store fault is the store-error
// envelope, never an empty journal.
func (e *Engine) Events(id string, by Actor) ([]state.Event, error) {
	// The journal is the job's, so the job decides who may read it.
	if by.Gen != nil {
		if _, err := e.Job(id, by); err != nil {
			return nil, err
		}
	}
	events, err := e.opts.Store.ListEvents(id)
	if err != nil {
		return nil, storeErr("read the journal of job "+id, err)
	}
	return events, nil
}

// Start resumes jobs the last engine left active and reconciles every
// instance's containers to its recorded stage (roadmap §9: reconcile-on-
// start; Manual §8: instances survive host reboots).
func (e *Engine) Start(ctx context.Context) error {
	e.sweepStaging()
	jobs, err := e.opts.Store.ListJobs("")
	if err != nil {
		return err
	}
	instances, err := e.opts.Store.ListInstances()
	if err != nil {
		return err
	}
	// An instance an earlier build created from a template the owner has
	// since retired is never operated on this engine's own initiative
	// (the reconciliation plan's R3): its active jobs are declined rather
	// than resumed — a destroy excepted, which is the operator's act — and
	// reconcile passes it by, its containers left exactly as they are.
	unsupported := map[string]*state.Instance{}
	for i := range instances {
		if retiredTemplate(&instances[i]) {
			unsupported[instances[i].Name] = &instances[i]
		}
	}
	// Nothing is launched until every startup read and write below has
	// succeeded: a Start that fails launches nothing, so the caller's
	// teardown (serve closes the store and runtime on that error) never
	// races a job, and the record stays queued for the next start.
	var launches []state.Job
	resumed := map[string]bool{}
	for _, j := range jobs {
		if j.Active() {
			if inst := unsupported[j.Instance]; inst != nil && j.Kind != "destroy" {
				if err := e.declineJob(j, inst); err != nil {
					return err
				}
				continue
			}
			e.opts.Logf("resuming %s job %s for %s at %q", j.Kind, j.ID, j.Instance, j.Stage)
			resumed[j.Instance] = true
			if j.Kind == "create" || j.Kind == "seed" || j.Kind == "verify" {
				// A resumed job finds its lab stopped: a seed or verify
				// restores it first (restored), a create re-walks in the
				// reconcile posture — containers that kept their data are
				// not initialised or seeded twice (wasResumed); a fresh job
				// never does either.
				e.mu.Lock()
				if e.resumedJobs == nil {
					e.resumedJobs = map[string]bool{}
				}
				e.resumedJobs[j.ID] = true
				e.mu.Unlock()
			}
			launches = append(launches, j)
		}
	}
	// Every instance's history of generated secrets is brought up to what
	// its secret store shows — kind records and values present — before
	// anything relies on it: a database upgraded to migration 7 holds no
	// history for what earlier releases generated, and a start is where
	// that is remembered, while the store still has the records.
	// A store that cannot be read is logged; its
	// filter fails closed at use.
	for _, inst := range instances {
		if _, err := e.rememberGeneratedSecrets(inst.Name, e.secretStore(inst.Name)); err != nil {
			e.opts.Logf("%s: the generated-secrets history could not be brought up to the store's records: %v", inst.Name, err)
		}
	}
	for _, inst := range instances {
		if unsupported[inst.Name] != nil {
			// Reported, never reconciled: no runtime call is made for it,
			// so a stopped container stays stopped and a running one keeps
			// running (PDR-W103).
			e.reportUnsupported(inst)
			continue
		}
		if resumed[inst.Name] {
			continue
		}
		if inst.Stage == state.StageNone {
			continue // never got going: its create job failed; nothing to restore
		}
		services, err := e.opts.Store.ListServices(inst.Name)
		if err != nil {
			return storeErr("list services of "+inst.Name, err)
		}
		if err := e.backfillGatewayFacts(&inst, services); err != nil {
			// A backfill that cannot happen must not stop the engine: the
			// lab runs exactly as it did, only its product hostnames stay
			// unpublished until a job re-derives them.
			e.opts.Logf("%s: the gateway facts could not be derived from its plan: %v", inst.Name, err)
		}
		if !e.needsReconcile(ctx, inst.Name, services) {
			continue
		}
		jobID, err := e.freshJobID()
		if err != nil {
			return err
		}
		job := state.Job{ID: jobID, Kind: "reconcile", Instance: inst.Name, Gen: inst.AuditFrom, State: state.JobQueued, Stage: "queued", Started: time.Now().UTC()}
		if err := e.opts.Store.PutJob(job); err != nil {
			return err
		}
		e.opts.Logf("reconciling %s: the lab is not running as recorded; restoring stage %s", inst.Name, inst.Stage)
		launches = append(launches, job)
	}
	for _, j := range launches {
		e.launch(j)
	}
	return nil
}

// needsReconcile reports whether an instance's lab is not running as its
// rows say: a container missing, stopped, not the container the row
// records — another created under the name while the engine was down,
// carrying our labels or not — or no
// longer mapping a port the row publishes; and a running object under
// the name that is not ours — a stranger the lab must never stand on
// (reconcile applies the ownership rule at adoption and fails, named).
// The rule is the one every dial and route applies (ownContainer,
// portLive): what they would refuse, a start does not leave standing.
func (e *Engine) needsReconcile(ctx context.Context, instance string, services []state.Service) bool {
	for i := range services {
		svc := &services[i]
		st, err := e.opts.Runtime.Inspect(ctx, svc.Container)
		if err != nil || st == nil || !st.Running {
			return true
		}
		want := runtime.ContainerSpec{Name: svc.Container, Labels: map[string]string{runtime.LabelInstance: instance, runtime.LabelService: svc.Name}}
		if err := runtime.Owned(st.Labels, want); err != nil {
			e.opts.Logf("%s: %v", instance, err)
			return true
		}
		if !ownContainer(instance, svc, st) {
			e.opts.Logf("%s: container %s is not the one recorded for %s (%.12s, recorded %.12s): it was replaced while the engine was down", instance, svc.Container, svc.Name, st.ID, svc.ContainerID)
			return true
		}
		for port, hp := range svc.Ports {
			if st.Ports[port] != hp {
				e.opts.Logf("%s: container %s no longer maps port %d to host port %d as recorded for %s", instance, svc.Container, port, hp, svc.Name)
				return true
			}
		}
		// The run, too: a container restarted while the engine was down —
		// the same id, the same ports — is another run that never passed
		// readiness; the reconcile proves it again (bringUp re-probes a
		// container started after the healthy record) and records the new
		// start, as the connected rung holds a run to the recorded start
		// (recordedRun).
		if !st.StartedAt.IsZero() && svc.StartedAt != nil && !st.StartedAt.Equal(*svc.StartedAt) {
			e.opts.Logf("%s: container %s was restarted while the engine was down (started %s; readiness was proven on the run started %s): readiness is proven again", instance, svc.Container, st.StartedAt.UTC().Format(time.RFC3339Nano), svc.StartedAt.UTC().Format(time.RFC3339Nano))
			return true
		}
	}
	return false
}

// wasResumed reports — once — whether Start resumed the job after a
// restart (resumedJobs).
func (e *Engine) wasResumed(jobID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	resumed := e.resumedJobs[jobID]
	delete(e.resumedJobs, jobID)
	return resumed
}

// restored runs a seed or verify job's steps, restoring the lab first when
// the job is one Start resumed after a restart: such a job finds its
// containers stopped — Start resumes it instead of reconciling the
// instance — so the create path first walks the instance as a reconcile
// would, up to seeded and without judging, in this job's journal; then
// the job's own steps run; a resumed seed ends with the judgement a
// reconcile would have made — baselines only, whatever the seed is named
// — whenever the ladder stands below ready, so it returns there even when
// an earlier restore was cut off by another stop. The restore itself runs
// when the containers are not running as the rows say or the recorded
// stage is below seeded (an interrupted restore); the walk is idempotent.
// A job that was not resumed never restores: a verify judges the lab as
// it is — a stopped service is the regression the pre-flight exists to
// surface, never something it repairs away — and a seed delivers to what
// runs.
func (e *Engine) restored(ctx context.Context, job *state.Job, steps func(context.Context, *state.Job) error) error {
	if !e.wasResumed(job.ID) {
		return steps(ctx, job)
	}
	inst, err := e.opts.Store.GetInstance(job.Instance)
	if errors.Is(err, state.ErrNotFound) {
		return e.notFound(job.Instance)
	}
	if err != nil {
		return storeErr("look up instance "+job.Instance, err)
	}
	services, err := e.opts.Store.ListServices(job.Instance)
	if err != nil {
		return storeErr("list services of "+job.Instance, err)
	}
	if len(services) > 0 && (e.needsReconcile(ctx, job.Instance, services) || inst.Stage.Rank() < state.StageSeeded.Rank()) {
		if err := e.event(job.ID, "restore", "", "starting", "resumed after a restart with its lab not running as recorded; the lab is restored before the "+job.Kind); err != nil {
			return err
		}
		if err := e.createStepsAs(ctx, job, true, false); err != nil {
			return err
		}
	}
	if err := steps(ctx, job); err != nil {
		return err
	}
	if job.Kind != "seed" {
		return nil
	}
	cur, err := e.opts.Store.GetInstance(job.Instance)
	if errors.Is(err, state.ErrNotFound) {
		return e.notFound(job.Instance)
	}
	if err != nil {
		return storeErr("look up instance "+job.Instance, err)
	}
	if cur.Stage.Rank() >= state.StageReady.Rank() {
		return nil
	}
	return e.verifyWith(ctx, job, baselinesOnly)
}

// Wait blocks until the job ends (tests and the CLI's local fallback).
func (e *Engine) Wait(ctx context.Context, id string) (*state.Job, error) {
	e.mu.Lock()
	done, ok := e.running[id]
	e.mu.Unlock()
	if ok {
		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return e.Job(id, Socket)
}

// Shutdown waits for running jobs to reach a journaled checkpoint. Jobs
// are resumable, so a hard stop mid-step is safe too.
// Shutdown stops the jobs in flight and waits for them: each is
// cancelled and reaches its next checkpoint (every step is journaled and
// idempotent, so its record stays running and the next Start resumes it),
// and only then may the caller close the store and runtime under it.
// A job that has not stopped when ctx ends is reported as the error.
func (e *Engine) Shutdown(ctx context.Context) error {
	e.cancel()
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		e.mu.Lock()
		n := len(e.running)
		e.mu.Unlock()
		return fmt.Errorf("%d job(s) still running: %w", n, ctx.Err())
	}
}

func (e *Engine) launch(job state.Job) {
	done := make(chan struct{})
	e.mu.Lock()
	e.running[job.ID] = done
	e.driven[job.ID] = struct{}{}
	e.mu.Unlock()
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer func() {
			e.mu.Lock()
			delete(e.running, job.ID)
			e.mu.Unlock()
			close(done)
		}()
		e.run(job)
	}()
}

// run executes a job to completion, journaling every step. Steps are
// idempotent against runtime state, so a job resumed after a crash
// re-walks the same sequence and skips what already happened.
func (e *Engine) run(job state.Job) {
	ctx := e.ctx
	job.State = state.JobRunning
	e.mu.Lock()
	if e.jobInstances == nil {
		e.jobInstances = map[string]string{}
		e.jobKinds = map[string]string{}
	}
	e.jobInstances[job.ID] = job.Instance
	e.jobKinds[job.ID] = job.Kind
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.jobInstances, job.ID)
		delete(e.jobKinds, job.ID)
		e.mu.Unlock()
	}()
	var err error
	if perr := e.opts.Store.PutJob(job); perr != nil {
		// Work the journal cannot hold is not done: no runtime mutation
		// without a durable running record (a resume would otherwise
		// find no trace of what happened).
		err = storeErr("record job "+job.ID, perr)
	} else {
		switch job.Kind {
		case "create":
			err = e.createStepsAs(ctx, &job, e.wasResumed(job.ID), true)
		case "reconcile":
			err = e.createStepsAs(ctx, &job, true, true)
		case "destroy":
			err = e.destroySteps(ctx, &job)
		case "seed":
			err = e.restored(ctx, &job, e.seedSteps)
		case "verify":
			err = e.restored(ctx, &job, e.verifySteps)
		case "reset":
			err = e.resetSteps(ctx, &job)
		default:
			err = fmt.Errorf("unknown job kind %q", job.Kind)
		}
	}
	if err == nil {
		// A success the journal cannot record is not a recorded success.
		err = e.event(job.ID, "job", "", "succeeded", "")
	}
	if err != nil && e.ctx.Err() != nil {
		// The engine is stopping: the job stopped at a checkpoint, not
		// at a failure — nothing about the lab is known to be wrong. Its
		// record stays running (the stage it reached), so the next Start
		// resumes it exactly as after a kill -9; a failure recorded here
		// would lie and would not be resumed.
		if jerr := e.event(job.ID, "job", "", "interrupted", "engine stopping; resumes on the next start"); jerr != nil {
			e.opts.Logf("job %s: %v", job.ID, jerr)
		}
		return
	}
	now := time.Now().UTC()
	job.Finished = &now
	if err != nil {
		// The failure's text is persisted (the job record, the journal)
		// and logged: it passes the instance's redaction filter first.
		err = e.redactErrFor(job.Kind, job.Instance, err)
		job.State = state.JobFailed
		job.Error = envelope(err)
		job.Stage = "failed"
		if jerr := e.event(job.ID, "job", "", "failed", errMessage(err)); jerr != nil {
			e.opts.Logf("job %s: %v", job.ID, jerr)
		}
	} else {
		job.State = state.JobSucceeded
		job.Stage = "done"
	}
	e.finish(job)
}

// finish records a job's terminal state, retrying with backoff. A write
// the store keeps refusing is remembered in memory: Job() reports the
// true outcome, activeJob() lands the record before reusing the slot,
// and a restart re-walks the idempotent steps at worst.
func (e *Engine) finish(job state.Job) {
	e.observeJob(job)
	var err error
	for attempt, wait := 0, e.finishRetry; attempt < 6; attempt, wait = attempt+1, wait*2 {
		if err = e.opts.Store.PutJob(job); err == nil {
			e.mu.Lock()
			delete(e.driven, job.ID)
			e.mu.Unlock()
			return
		}
		time.Sleep(wait)
	}
	e.opts.Logf("job %s for %s ended %s but the state database refused the record: %v", job.ID, job.Instance, job.State, err)
	e.mu.Lock()
	e.unrecorded[job.ID] = job
	delete(e.driven, job.ID) // the outcome is known here (knownOutcome); it is not a driverless record
	e.mu.Unlock()
}

func (e *Engine) stage(job *state.Job, stage string) {
	job.Stage = stage
	_ = e.opts.Store.PutJob(*job)
}

// event journals one step (roadmap §9: the persistent step journal). A
// refused journal write is the step's failure — a history that cannot be
// recorded is not best-effort logging; a resumed job re-walks and
// re-journals the idempotent steps. So is a line the redaction filter
// cannot be built for: it is neither journaled nor logged (PDR-E412).
func (e *Engine) event(jobID, step, service, status, detail string) error {
	red, perr := e.jobRedactor(jobID)
	if perr != nil {
		return perr
	}
	detail = red.Redact(detail)
	parts := []string{step, service, status, detail}
	line := make([]string, 0, len(parts))
	for _, s := range parts {
		if s != "" {
			line = append(line, s)
		}
	}
	e.opts.Logf("job %s · %s", jobID, strings.Join(line, " "))
	if err := e.opts.Store.AppendEvent(state.Event{Job: jobID, At: time.Now().UTC(), Step: step, Service: service, Status: status, Detail: detail}); err != nil {
		return storeErr("journal job "+jobID, err)
	}
	return nil
}

// createSteps is the create path up to healthy (S4's top rung): network,
// then per service pull → create → start → alive → healthy.
func (e *Engine) createSteps(ctx context.Context, job *state.Job) error {
	return e.createStepsAs(ctx, job, job.Kind == "reconcile", true)
}

// createStepsAs is the create path with the reconcile posture explicit
// (labView.reconcile) and the final judgement optional: a reconcile job's
// walk judges (baselines re-verify — User Manual §8); the restoration a
// seed or verify resumed after a reboot performs before its own steps
// stops at seeded (judge false) and leaves the judging to the job, so a
// lab is judged once and by the job's own rules.
func (e *Engine) createStepsAs(ctx context.Context, job *state.Job, reconcile, judge bool) error {
	inst, err := e.opts.Store.GetInstance(job.Instance)
	if errors.Is(err, state.ErrNotFound) {
		if job.Kind == "create" {
			if err := e.removeAdmissionLeftover(job); err != nil {
				return err
			}
		}
		return e.notFound(job.Instance)
	}
	if err != nil {
		// A store fault is not absence (D27): the job fails naming the
		// fault, and the instance — which may well exist — stays.
		return storeErr("look up instance "+job.Instance, err)
	}
	if retiredTemplate(inst) {
		// No create, reconcile or restore walks a lab the owner retired,
		// whatever its source would plan to: the walk's first runtime act
		// is below, and this is before it (the reconciliation plan's R3).
		return e.unsupported(inst)
	}
	library, err := e.libraryFor(inst)
	if err != nil {
		return err
	}
	plan, res, err := lab.MakePlan(lab.PlanOptions{Options: lab.Options{Path: inst.Source, Library: library}, Profile: inst.Profile})
	if err != nil {
		return err
	}
	// The identity is fixed at create (D16): a tracked directory whose
	// metadata now names another template or version is not this
	// instance's lab, and the job says so — before any gate derived from
	// that plan could ask the operator to accept terms for a lab this
	// instance may not run — rather than running it under the old labels.
	if plan.Template.Name != inst.Template || plan.Template.Version != inst.Version {
		pe := pdr.New(pdr.CodeRuntimeFailed, "%s now declares template %s@%s; instance %s was created from %s@%s", inst.Source, plan.Template.Name, plan.Template.Version, inst.Name, inst.Template, inst.Version)
		pe.Cause = "the template's metadata changed after the instance was created; identity never changes in place"
		pe.Next = "restore the metadata and re-run · or destroy " + inst.Name + " and create it from the new template"
		return pe
	}
	// The plan is re-read on every attempt (an authoring instance tracks
	// its directory), so the admission gates apply again, against the
	// licenses accepted at create: a template that grew a license, or an
	// unrenderable need, since Create admitted it fails here — before any
	// runtime mutation — with the same envelopes Create would give.
	if err := e.licenseGate(plan, inst.Licenses); err != nil {
		return err
	}
	lv := &labView{inst: inst, plan: plan, res: res, checkpoints: lab.FlattenCheckpoints(res), reconcile: reconcile}
	lv.standing, lv.actions = lab.SeedRoles(res)
	// The hostname gate and the publication of the labels it admits are
	// one critical section with Create's admission (API §7.1): a plan
	// that gained a hostname since the instance was created — an
	// authoring instance whose author added a service — publishes it
	// here, under the admission lock and before anything runs, so a
	// create racing this attempt finds the label taken rather than
	// passing its own gate against rows this attempt has not written.
	if err := e.reserveHostnames(inst, plan); err != nil {
		return err
	}
	labels := map[string]string{runtime.LabelInstance: inst.Name, runtime.LabelTemplate: inst.Template, runtime.LabelManaged: "true"}

	e.stage(job, "creating network")
	network := networkName(inst.Name)
	if err := e.opts.Runtime.EnsureNetwork(ctx, network, labels, false); err != nil {
		if err := e.event(job.ID, "network", "", "failed", err.Error()); err != nil {
			return err
		}
		return runtimeErr("create network "+network, err)
	}
	if err := e.event(job.ID, "network", "", "ok", network); err != nil {
		return err
	}
	// The internal network: no route out, where one-shot runs — init
	// helpers, extension adapters and generators — reach lab services and
	// nothing else (Spec 0002 §2). Lab containers join both.
	internal := internalNetworkName(inst.Name)
	if err := e.opts.Runtime.EnsureNetwork(ctx, internal, labels, true); err != nil {
		if err := e.event(job.ID, "network", "", "failed", err.Error()); err != nil {
			return err
		}
		return runtimeErr("create network "+internal, err)
	}
	if err := e.event(job.ID, "network", "", "ok", internal+" (internal)"); err != nil {
		return err
	}
	// Per-instance secrets, generated once (spec 0003 §6; roadmap
	// invariant 6), then a row for every checkpoint so the tally's totals
	// are known before anything is evaluated.
	e.stage(job, "generating secrets")
	values, err := e.secretsStep(job, lv)
	if err != nil {
		return err
	}
	if err := e.ensureResultRows(lv); err != nil {
		return err
	}

	services, err := e.opts.Store.ListServices(inst.Name)
	if err != nil {
		return storeErr("list services of "+inst.Name, err)
	}
	byName := map[string]state.Service{}
	for _, s := range services {
		byName[s.Name] = s
	}
	planned := map[string]bool{}
	for _, ps := range plan.Services {
		planned[ps.Name] = true
	}
	// Services the current plan no longer declares (an authoring retry
	// after a rename or removal) are taken down first — ownership-checked,
	// like every removal — so nothing undeclared keeps running.
	for _, stale := range services {
		if planned[stale.Name] {
			continue
		}
		e.stage(job, "removing "+stale.Name+" (no longer in the template)")
		if err := e.withdrawRoute(&stale); err != nil {
			return err
		}
		if err := e.removeOwnedContainer(ctx, inst.Name, stale); err != nil {
			if err := e.event(job.ID, "remove", stale.Name, "failed", err.Error()); err != nil {
				return err
			}
			return err
		}
		// The journal line lands before the row goes: the row is what a
		// retry re-walks from, so it outlives its own removal's record.
		if err := e.event(job.ID, "remove", stale.Name, "ok", "no longer in the template"); err != nil {
			return err
		}
		if err := e.opts.Store.DeleteService(inst.Name, stale.Name); err != nil {
			return storeErr("forget service "+stale.Name, err)
		}
	}
	ordered, err := bringUpOrder(plan, res)
	if err != nil {
		return err
	}
	for _, ps := range ordered {
		svc, ok := byName[ps.Name]
		if !ok {
			svc = state.Service{Instance: inst.Name, Name: ps.Name, Container: containerName(inst.Name, ps.Name)}
		}
		// Plan-derived facts are refreshed on every attempt: a retry after
		// the author changed the image or the readiness timing must use
		// the new values, not the ones recorded at the failed attempt.
		svc.Module, svc.Image = ps.Module, ps.Image.Ref()
		svc.UIPort, svc.UIScheme, svc.Embed = uiPort(ps), uiScheme(ps), ps.Embed
		svc.Typical, svc.Budget = "", ""
		if ps.Readiness != nil {
			svc.Typical, svc.Budget = ps.Readiness.Typical, budgetOf(ps.Readiness)
		}
		priorID, priorStage := svc.ContainerID, svc.Stage
		if err := e.bringUp(ctx, job, inst, ps, readinessOf(res, ps.Name), res.Composition.Effective(ps.Name), values, &svc, network, labels); err != nil {
			if ctx.Err() == nil { // an interrupted step is not the service's error
				svc.Error = errMessage(e.redactErr(inst.Name, err))
				_ = e.putService(&svc)
			}
			return err
		}
		if priorID == "" || svc.ContainerID != priorID {
			lv.recreated = true
		}
		// A reconcile that restarted the very container it recorded
		// initialized keeps what init set inside it (a restart keeps a
		// container's filesystem): the rung is re-recorded, the helper is
		// not run twice. A new container, or a service that had not
		// reached initialized, runs init as a create does.
		if lv.reconcile && priorID != "" && svc.ContainerID == priorID && priorStage.Rank() >= state.StageInitialized.Rank() && svc.Stage.Rank() >= state.StageHealthy.Rank() && svc.Stage.Rank() < state.StageInitialized.Rank() {
			if err := e.event(job.ID, "init", ps.Name, "skipped", "reconcile: the container restarted with its data"); err != nil {
				return err
			}
			if err := e.setStage(&svc, state.StageInitialized); err != nil {
				return err
			}
			continue
		}
		// The one-shot init helper, gated on this service's health (spec
		// 0003 §9.1), before the next service starts: a sibling that
		// depends on what init sets (a dashboard on the password its
		// store's init job set) finds it done. Services come up in name
		// order, init targets first (bringUpOrder).
		if err := e.initStep(ctx, job, lv, ps, &svc, values); err != nil {
			if ctx.Err() == nil {
				svc.Error = errMessage(e.redactErr(inst.Name, err))
				_ = e.putService(&svc)
			}
			return err
		}
	}
	// The instance-level rungs: connected → seeded → verified → ready.
	if err := e.connectStep(ctx, job, lv); err != nil {
		return err
	}
	if err := e.seedStep(ctx, job, lv); err != nil {
		return err
	}
	if !judge {
		return nil
	}
	return e.verifyStep(ctx, job, lv)
}

// sweepContainers removes every container the runtime lists under the
// instance's label, after proving each is ours: the label filter finds
// candidates, ownership decides, and a foreign object wearing the label
// stops the destroy, named. Not being able to list is a failure.
func (e *Engine) sweepContainers(ctx context.Context, job *state.Job, instance string) error {
	rt := e.opts.Runtime
	objs, err := rt.Objects(ctx, instance)
	if err != nil {
		if err := e.event(job.ID, "sweep", "", "failed", err.Error()); err != nil {
			return err
		}
		return runtimeErr("list leftovers of "+instance, err)
	}
	for _, c := range objs.Containers {
		st, err := rt.Inspect(ctx, c)
		if err != nil {
			return runtimeErr("inspect "+c, err)
		}
		if st == nil {
			continue
		}
		if err := runtime.Owned(st.Labels, runtime.ContainerSpec{Name: c, Labels: map[string]string{runtime.LabelInstance: instance}}); err != nil {
			if err := e.event(job.ID, "sweep", "", "failed", err.Error()); err != nil {
				return err
			}
			pe := pdr.New(pdr.CodeRuntimeFailed, "destroy refused: %s", err.Error())
			pe.Next = "remove that container by hand if it is yours, then re-run podaro destroy " + instance
			return pe
		}
		// By the id the inspection saw, never by the name (D150).
		if err := rt.Remove(ctx, st.ID); err != nil {
			return runtimeErr("remove "+c, err)
		}
		if err := e.event(job.ID, "sweep", "", "ok", "removed "+c); err != nil {
			return err
		}
	}
	return nil
}

// removeOwnedContainer removes a service's container after proving it is
// this instance's; a foreign object under the name fails, named.
// withdrawRoute forgets a service's published ports before its container
// goes: the gateway proxies `<service>-<instance>` to the host port the
// row names, and a host port the removal frees can be handed to another
// lab's container at once — a row still naming it would route the old
// hostname to the new listener. The row itself stays (a retry re-walks
// from it; the container is removed by name), only its route goes. The
// withdrawal takes the route lock: a connection being opened completes
// first, and none opened after it finds the route.
func (e *Engine) withdrawRoute(svc *state.Service) error {
	if len(svc.Ports) == 0 {
		return nil
	}
	e.routeMu.Lock()
	defer e.routeMu.Unlock()
	svc.Ports = nil
	if err := e.opts.Store.PutService(*svc); err != nil {
		return storeErr("withdraw the route of "+svc.Name, err)
	}
	return nil
}

func (e *Engine) removeOwnedContainer(ctx context.Context, instance string, svc state.Service) error {
	rt := e.opts.Runtime
	st, err := rt.Inspect(ctx, svc.Container)
	if err != nil {
		return runtimeErr("inspect "+svc.Container, err)
	}
	if st == nil {
		return nil // nothing under the name: nothing of ours to remove
	}
	want := runtime.ContainerSpec{Name: svc.Container, Labels: map[string]string{runtime.LabelInstance: instance, runtime.LabelService: svc.Name}}
	if err := runtime.Owned(st.Labels, want); err != nil {
		pe := pdr.New(pdr.CodeRuntimeFailed, "refused: %s", err.Error())
		pe.Next = "remove that container by hand if it is yours, then re-run"
		return pe
	}
	// By the id the inspection saw, never by the name: a container that
	// took the name meanwhile is not the one inspected and stands (D150 — the same rule at every removal the engine makes after an inspection).
	if err := rt.Remove(ctx, st.ID); err != nil {
		return runtimeErr("remove "+svc.Container, err)
	}
	return nil
}

// bringUp takes one service to healthy, skipping steps the runtime shows
// are already done.
func (e *Engine) bringUp(ctx context.Context, job *state.Job, inst *state.Instance, ps lab.PlanService, readiness *lab.Readiness, cfg *lab.EffectiveConfig, values map[string]string, svc *state.Service, network string, labels map[string]string) error {
	rt := e.opts.Runtime
	name := svc.Name
	svc.Error = ""
	if cfg == nil {
		cfg = &lab.EffectiveConfig{}
	}
	// The configuration is rendered with the instance's secrets (spec 0003
	// §6): the environment travels as a 0600 file under the instance
	// (never on argv, never in logs), files are copied into the container's
	// own storage before it starts (no host bind mounts, threat model B4);
	// both are rewritten on every attempt so a resumed job carries the
	// authored values.
	rendered, err := renderConfig(cfg, values)
	if err != nil {
		if jerr := e.event(job.ID, "render", name, "failed", err.Error()); jerr != nil {
			return jerr
		}
		pe := pdr.New(pdr.CodeRuntimeFailed, "cannot render the configuration of %s", name)
		pe.Cause = err.Error()
		pe.Next = "podaro up again to resume; if a secret file is missing, destroy and re-create the instance"
		return pe
	}
	envFile, err := e.writeEnvFile(inst.Name, name, rendered)
	if err != nil {
		return runtimeErr("render env for "+name, err)
	}

	e.stage(job, "pulling "+name)
	if err := rt.Pull(ctx, svc.Image); err != nil {
		if err := e.event(job.ID, "pull", name, "failed", err.Error()); err != nil {
			return err
		}
		return runtimeErr("pull "+svc.Image, err)
	}
	if err := e.event(job.ID, "pull", name, "ok", svc.Image); err != nil {
		return err
	}

	svcLabels := map[string]string{}
	for k, v := range labels {
		svcLabels[k] = v
	}
	svcLabels[runtime.LabelService] = name
	publish := map[int]bool{}
	for _, ep := range ps.Endpoints {
		publish[ep.Port] = true
	}
	probePort := 0
	probePath, probeExpect, probeScheme := "/", 200, "http"
	if readiness != nil {
		r := readiness.Probe
		probePort = r.Port
		if r.Path != "" {
			probePath = r.Path
		}
		if r.ExpectStatus != 0 {
			probeExpect = r.ExpectStatus
		}
		if r.Scheme != "" {
			probeScheme = r.Scheme
		}
		if probePort > 0 {
			publish[probePort] = true
		}
	}
	var ports []int
	for p := range publish {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	spec := runtime.ContainerSpec{
		Name: svc.Container, Image: svc.Image, Network: network, Networks: []string{internalNetworkName(inst.Name)}, Alias: name, Hostname: name,
		Labels: svcLabels, Publish: ports, CPU: ps.Resources.CPU, Memory: ps.Resources.Memory,
		EnvFile: envFile, Entrypoint: rendered.Entrypoint, Command: rendered.Args, Files: rendered.Files,
	}
	priorID := svc.ContainerID // the container the store's stage refers to
	// A container that is ours but stale — the author changed the service
	// — is replaced by Create, and its host ports are freed as it goes;
	// the row's route is withdrawn first (under the route lock), so the
	// old hostname is never proxied to whatever takes those ports
	// meanwhile. The route is published again below, once the
	// replacement's ports are read. An unchanged container keeps its
	// route: no window opens.
	if len(svc.Ports) > 0 {
		digest, err := spec.Digest()
		if err != nil {
			return runtimeErr("digest the spec of "+name, err)
		}
		st, err := rt.Inspect(ctx, svc.Container)
		if err != nil {
			return runtimeErr("inspect "+svc.Container, err)
		}
		if st == nil || st.Labels[runtime.LabelSpec] != digest {
			if err := e.withdrawRoute(svc); err != nil {
				return err
			}
		}
	}
	e.stage(job, "creating "+name)
	id, err := rt.Create(ctx, spec)
	if err != nil {
		if err := e.event(job.ID, "create", name, "failed", err.Error()); err != nil {
			return err
		}
		return runtimeErr("create "+svc.Container, err)
	}
	svc.ContainerID = id
	if err := e.putService(svc); err != nil {
		return storeErr("record service "+name, err)
	}
	if err := e.event(job.ID, "create", name, "ok", svc.Container); err != nil {
		return err
	}

	e.stage(job, "starting "+name)
	// By the id the create answered and the row records: a container
	// another process placed under the name meanwhile is not this
	// service's, and its state and ports are never taken for it (S6
	// review, round 48).
	st, err := rt.Inspect(ctx, svc.ContainerID)
	if err != nil {
		return runtimeErr("inspect "+svc.Container, err)
	}
	if st == nil || !st.Running {
		// By the id the create answered and the row records, never by
		// the name another process may reuse after removing this
		// container.
		if err := rt.Start(ctx, svc.ContainerID); err != nil {
			if err := e.event(job.ID, "start", name, "failed", err.Error()); err != nil {
				return err
			}
			return runtimeErr("start "+svc.Container, err)
		}
		st, err = rt.Inspect(ctx, svc.ContainerID)
		if err != nil {
			return runtimeErr("inspect "+svc.Container, err)
		}
	}
	// Alive means running now, not "start returned": a container that
	// exited (or vanished) right after start is a failed step, named —
	// never recorded as alive, never a succeeded job.
	if st == nil {
		if err := e.event(job.ID, "start", name, "failed", "container disappeared after start"); err != nil {
			return err
		}
		pe := pdr.New(pdr.CodeRuntimeFailed, "%s disappeared right after start", name)
		pe.Cause = "container " + svc.Container + " no longer exists"
		pe.Next = "podaro doctor · then re-run to resume at this step"
		return pe
	}
	if !st.Running {
		if err := e.event(job.ID, "start", name, "failed", "container exited right after start"); err != nil {
			return err
		}
		pe := pdr.New(pdr.CodeRuntimeFailed, "%s exited right after start", name)
		pe.Cause = "container " + svc.Container + " is not running"
		pe.Next = "podman logs " + svc.Container + " · fix the template, then re-run to resume at this step"
		return pe
	}
	// A service the store already records healthy — on this very
	// container, still running since before that record — needs no
	// second probe and no second deadline: a resumed job re-walks the
	// steps, it does not re-judge a readiness already proven (a later
	// service's longer wait would otherwise make an earlier one "late").
	// The record counts only for the job that made it (a resumed job keeps
	// job.Started): a new attempt after a failure re-probes, because the
	// old green proved the old condition — the author may have changed the
	// probe since, or the service may have gone unhealthy while running.
	// And only under the same probe contract, inside the budget that
	// applies now: a resumed authoring job re-reads its directory, so a
	// probe edited while the engine was down is a new condition the old
	// green never proved, and a budget shortened since (the row carries the
	// refreshed one, D24) is a deadline the old green may fall after.
	if svc.Stage.Rank() >= state.StageHealthy.Rank() && svc.HealthyAt != nil && !svc.HealthyAt.Before(job.Started) && priorID == id && !st.StartedAt.IsZero() && !st.StartedAt.After(*svc.HealthyAt) && svc.Readiness == readinessDigest(readiness) && !svc.HealthyAt.After(latest(st.StartedAt, job.Started).Add(budgetDuration(svc.Budget))) {
		if err := e.publishRoute(svc, st.Ports); err != nil {
			return storeErr("record healthy "+name, err)
		}
		if err := e.event(job.ID, "healthy", name, "ok", "already recorded healthy at "+svc.HealthyAt.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
		return e.refreshInstanceStage(inst.Name)
	}
	started := st.StartedAt
	if started.IsZero() {
		started = time.Now().UTC()
	}
	svc.StartedAt = &started
	// Past every branch that refuses a container which did not come up:
	// this image is one that ran, and it is recorded with the run rather
	// than left to be read off the plan later.
	svc.RanImage, svc.RanModule = svc.Image, svc.Module
	svc.Stage = state.StageAlive
	svc.HealthyAt = nil
	svc.Readiness = ""
	// Stage writes are the job's truth: a refused write fails the step (a
	// succeeded job with a stale stage would never be repaired, since
	// neither up nor reconcile revisits a healthy lab).
	if err := e.publishRoute(svc, st.Ports); err != nil {
		return storeErr("record alive "+name, err)
	}
	if err := e.event(job.ID, "alive", name, "ok", fmt.Sprintf("container %s running", shortID(st.ID))); err != nil {
		return err
	}
	if err := e.refreshInstanceStage(inst.Name); err != nil {
		return err
	}

	// Healthy: the readiness probe, polled until the budget (spec 0003
	// §9.2 — exceeding it is a failure, not patience).
	typical := svc.Typical
	if typical == "" {
		typical = "a moment"
	}
	e.stage(job, fmt.Sprintf("waiting for %s (typically %s)", name, typical))
	if probePort == 0 {
		// No readiness declared: alive is as far as the ladder can honestly
		// go for this service — nothing is guessed at (a TCP endpoint or an
		// HTTP root that is not 200 would only burn the budget).
		if err := e.event(job.ID, "healthy", name, "skipped", "no readiness declared; the ladder stops at alive"); err != nil {
			return err
		}
		svc.Stage = state.StageAlive
		if err := e.putService(svc); err != nil {
			return storeErr("record alive "+name, err)
		}
		return nil
	}
	if _, err := parseDuration(svc.Budget); err != nil {
		// The row carries the effective budget (budgetOf); a row written
		// before that rule falls to the same default, and says so.
		svc.Budget = DefaultReadinessBudget
	}
	budget := budgetDuration(svc.Budget)
	// The budget runs from whichever came last, the job's start or the
	// container's: a job resumed after an engine restart keeps the
	// deadline its container already had (no second budget for the same
	// job), while a re-run after a failed attempt — a new job — gets its
	// own, and a restarted container starts the clock again.
	from := latest(started, job.Started)
	deadline := from.Add(budget)
	interval := probeInterval(readiness, e.opts.PollInterval)
	hostPort := st.Ports[probePort]
	if hostPort == 0 {
		// A declared probe with no host binding cannot run: that is a
		// runtime failure — never the no-readiness case, never a silent
		// alive with the budget bypassed.
		if err := e.event(job.ID, "healthy", name, "failed", fmt.Sprintf("no host binding for readiness port %d", probePort)); err != nil {
			return err
		}
		pe := pdr.New(pdr.CodeRuntimeFailed, "%s has no host binding for its readiness port %d", name, probePort)
		pe.Cause = fmt.Sprintf("the runtime published no 127.0.0.1 port for container port %d of %s", probePort, svc.Container)
		pe.Next = "podman port " + svc.Container + " · podaro doctor · then re-run to resume at this step"
		return pe
	}
	url := fmt.Sprintf("%s://127.0.0.1:%d%s", probeScheme, hostPort, probePath)
	for {
		// Each attempt is bounded by the deadline too: a probe that
		// connects and then stalls cannot outlive the budget.
		pctx, cancel := context.WithDeadline(ctx, deadline)
		ok := e.opts.Probe(pctx, url, probeExpect)
		cancel()
		late := time.Now().After(deadline)
		if ok && !late {
			// The probe's answer is the container's only if the same run
			// of it — the one inspected after start — is still running and
			// mapping the probe port now: a service that exited during its
			// readiness wait hands its host port to whoever binds it next,
			// and that listener's answer is nobody's health (the container adapter applies the same rule, D88, and the connected rung the same, connected).
			after, err := rt.Inspect(ctx, svc.Container)
			if err != nil {
				return runtimeErr("inspect "+svc.Container, err)
			}
			if !sameRun(st, after) || !portLive(inst.Name, svc, after, probePort) {
				if err := e.event(job.ID, "healthy", name, "failed", "container stopped or was replaced during its readiness wait; the probe's answer came from whatever holds the port now"); err != nil {
					return err
				}
				pe := pdr.New(pdr.CodeRuntimeFailed, "%s stopped during its readiness wait", name)
				pe.Cause = fmt.Sprintf("container %s is not running the run that started, or no longer maps port %d; the probe's answer came from whatever holds the port now", svc.Container, probePort)
				pe.Next = "podman logs " + svc.Container + " · fix the template, then re-run to resume at this step"
				return pe
			}
			now := time.Now().UTC()
			svc.HealthyAt = &now
			svc.Stage = state.StageHealthy
			svc.Readiness = readinessDigest(readiness)
			if err := e.putService(svc); err != nil {
				return storeErr("record healthy "+name, err)
			}
			if err := e.event(job.ID, "healthy", name, "ok", "healthy in "+now.Sub(started).Round(time.Second).String()); err != nil {
				return err
			}
			return e.refreshInstanceStage(inst.Name)
		}
		if late {
			// Exceeding the budget is a failure, not patience — a probe
			// that only turns green after the deadline is still a miss.
			if err := e.event(job.ID, "healthy", name, "failed", "budget "+svc.Budget+" exceeded"); err != nil {
				return err
			}
			pe := pdr.New(pdr.CodeReadinessBudget, "%s did not become healthy within %s", name, svc.Budget)
			pe.Cause = fmt.Sprintf("readiness probe %s://%s:%d%s never returned %d within the budget", probeScheme, name, probePort, probePath, probeExpect)
			if ok {
				pe.Cause = fmt.Sprintf("readiness probe %s://%s:%d%s returned %d only after the budget", probeScheme, name, probePort, probePath, probeExpect)
			}
			pe.Next = fmt.Sprintf("podaro logs %s %s · podaro up again to resume", inst.Name, name)
			return pe
		}
		// Never sleep past the deadline: the budget is the failure
		// boundary even when the cadence is longer than what is left.
		wait := interval
		if until := time.Until(deadline); until < wait {
			wait = until
		}
		if wait < 0 {
			wait = 0
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}

}

// destroySteps removes everything the instance owns and proves it.
func (e *Engine) destroySteps(ctx context.Context, job *state.Job) error {
	inst, err := e.opts.Store.GetInstance(job.Instance)
	if errors.Is(err, state.ErrNotFound) {
		return nil // already gone: a resumed destroy finished before the crash
	}
	if err != nil {
		return storeErr("look up instance "+job.Instance, err)
	}
	rt := e.opts.Runtime
	services, err := e.opts.Store.ListServices(inst.Name)
	if err != nil {
		return storeErr("list services of "+inst.Name, err)
	}
	for _, svc := range services {
		e.stage(job, "removing "+svc.Name)
		if err := e.withdrawRoute(&svc); err != nil {
			return err
		}
		// Destroy removes only what is provably this instance's: a foreign
		// container under the predictable name is left alone and named.
		if err := e.removeOwnedContainer(ctx, inst.Name, svc); err != nil {
			if err := e.event(job.ID, "remove", svc.Name, "failed", err.Error()); err != nil {
				return err
			}
			var pe *pdr.Error
			if errors.As(err, &pe) && strings.HasPrefix(pe.Message, "refused:") {
				pe.Message = "destroy " + pe.Message
				pe.Next = "remove that container by hand if it is yours, then re-run podaro destroy " + inst.Name
			}
			return err
		}
		if err := e.event(job.ID, "remove", svc.Name, "ok", svc.Container); err != nil {
			return err
		}
	}
	// Orphans before the network: a managed container under this
	// instance's label that the service table never recorded (a create
	// interrupted between the runtime and the store) would keep the
	// network attached and make its non-forced removal fail on every
	// retry. Sweep them — ownership-checked like everything else — first.
	if err := e.sweepContainers(ctx, job, inst.Name); err != nil {
		return err
	}
	e.stage(job, "removing network")
	network := networkName(inst.Name)
	if labels, exists, err := rt.InspectNetwork(ctx, network); err != nil {
		return runtimeErr("inspect network "+network, err)
	} else if exists {
		if err := runtime.OwnedNetwork(network, labels, map[string]string{runtime.LabelInstance: inst.Name}); err != nil {
			if err := e.event(job.ID, "network", "", "failed", err.Error()); err != nil {
				return err
			}
			pe := pdr.New(pdr.CodeRuntimeFailed, "destroy refused: %s", err.Error())
			pe.Next = "remove that network by hand if it is yours, then re-run podaro destroy " + inst.Name
			return pe
		}
	}
	if err := rt.RemoveNetwork(ctx, network); err != nil {
		if err := e.event(job.ID, "network", "", "failed", err.Error()); err != nil {
			return err
		}
		return runtimeErr("remove network", err)
	}
	if err := e.event(job.ID, "network", "", "ok", "removed"); err != nil {
		return err
	}
	// Anything else labeled with the instance is a bug, not a leftover —
	// and not being able to look is a failure, never a pass.
	objs, err := rt.Objects(ctx, inst.Name)
	if err != nil {
		if err := e.event(job.ID, "sweep", "", "failed", err.Error()); err != nil {
			return err
		}
		return runtimeErr("list leftovers of "+inst.Name, err)
	}
	if !objs.Empty() {
		// The label filter finds candidates; ownership decides. A foreign
		// object wearing this instance's label stops the destroy, named.
		refuse := func(what string, err error) error {
			if err := e.event(job.ID, "sweep", "", "failed", err.Error()); err != nil {
				return err
			}
			pe := pdr.New(pdr.CodeRuntimeFailed, "destroy refused: %s", err.Error())
			pe.Next = "remove that " + what + " by hand if it is yours, then re-run podaro destroy " + inst.Name
			return pe
		}
		if err := e.sweepContainers(ctx, job, inst.Name); err != nil {
			return err
		}
		// A run secret a crashed one-shot left behind is named for this
		// instance and goes with it (Spec 0002 §2: secrets live for the run).
		for _, s := range objs.Secrets {
			if err := rt.RemoveSecret(ctx, s); err != nil {
				return runtimeErr("remove run secret "+s, err)
			}
			if err := e.event(job.ID, "sweep", "", "ok", "removed run secret "+s); err != nil {
				return err
			}
		}
		for _, n := range objs.Networks {
			labels, exists, err := rt.InspectNetwork(ctx, n)
			if err != nil {
				return runtimeErr("inspect network "+n, err)
			}
			if !exists {
				continue
			}
			if err := runtime.OwnedNetwork(n, labels, map[string]string{runtime.LabelInstance: inst.Name}); err != nil {
				return refuse("network", err)
			}
			if err := rt.RemoveNetwork(ctx, n); err != nil {
				return runtimeErr("remove network "+n, err)
			}
			if err := e.event(job.ID, "sweep", "", "ok", "removed network "+n); err != nil {
				return err
			}
		}
		objs, err = rt.Objects(ctx, inst.Name)
		if err != nil {
			return runtimeErr("list leftovers of "+inst.Name, err)
		}
		if !objs.Empty() {
			pe := pdr.New(pdr.CodeRuntimeFailed, "destroy left runtime objects behind: %v", objs)
			pe.Next = "remove them by hand and re-run podaro destroy " + inst.Name
			return pe
		}
	}
	e.stage(job, "removing state")
	// Under the instance guard: a checkpoint record, attestation, progress
	// write, or reveal in flight lands before this or finds the instance
	// gone — never into a directory this removal just took (guard.go).
	lock := e.instanceLock(inst.Name)
	lock.Lock()
	rmErr := os.RemoveAll(e.instanceDir(inst.Name))
	if rmErr == nil {
		rmErr = e.opts.Store.DeleteInstance(inst.Name)
	}
	e.forgetEvaluations(inst.Name)
	e.forgetJournal(inst.Name)
	lock.Unlock()
	if rmErr != nil {
		return rmErr
	}
	if err := e.event(job.ID, "state", "", "ok", "instance removed"); err != nil {
		return err
	}
	return nil
}

// refreshInstanceStage sets the instance stage to the lowest service
// stage: the ladder is only as high as its slowest rung.
// refreshInstanceStage records the instance's stage as the lowest of its
// services'. A refused read or write is the step's failure: status
// renders from this field, a succeeded job is never revisited, and a
// stage left at none makes Start skip the instance for good.
func (e *Engine) refreshInstanceStage(name string) error {
	inst, err := e.opts.Store.GetInstance(name)
	if err != nil {
		return storeErr("look up instance "+name, err)
	}
	services, err := e.opts.Store.ListServices(name)
	if err != nil {
		return storeErr("list services of "+name, err)
	}
	lowest := state.StageReady
	if len(services) == 0 {
		lowest = state.StageNone
	}
	for _, s := range services {
		if s.Stage.Rank() < lowest.Rank() {
			lowest = s.Stage
		}
	}
	inst.Stage = lowest
	// The high-water mark: raised here and nowhere else, because this is
	// the one place the instance's stage is written and both markAll and
	// demoteAll end in it. A demote therefore cannot lower it, which is
	// what lets the ladder say a fall happened (UX §5, plan S14).
	if lowest.Rank() > inst.Reached.Rank() {
		inst.Reached = lowest
	}
	inst.Updated = time.Now().UTC()
	if err := e.opts.Store.PutInstance(*inst); err != nil {
		return storeErr("record stage of "+name, err)
	}
	return nil
}

func (e *Engine) instanceDir(name string) string {
	return filepath.Join(e.opts.StateDir, "instances", name)
}

// uiPort is the container port of the service's `ui` endpoint — the one
// the gateway proxies `<service>-<instance>.<domain>` to (User Manual §5).
func uiPort(ps lab.PlanService) int {
	for _, ep := range ps.Endpoints {
		if ep.Purpose == "ui" {
			return ep.Port
		}
	}
	return 0
}

func uiScheme(ps lab.PlanService) string {
	for _, ep := range ps.Endpoints {
		if ep.Purpose == "ui" {
			if ep.Scheme == "" {
				return "http"
			}
			return ep.Scheme
		}
	}
	return ""
}

// Instance returns one instance record (the gateway's routing lookup).
func (e *Engine) Instance(name string, by Actor) (*state.Instance, error) {
	inst, err := e.opts.Store.GetInstance(name)
	if err != nil {
		return nil, e.notFound(name)
	}
	// Compared against the instance this call resolved:
	// a bearer entitled to one generation is told the same
	// thing about any other as it is about a lab that is not there.
	if by.Gen != nil && inst.AuditFrom != *by.Gen {
		return nil, e.notFound(name)
	}
	return inst, nil
}

// Service returns one service record of an instance, or nil.
func (e *Engine) Service(instance, name string) (*state.Service, error) {
	services, err := e.opts.Store.ListServices(instance)
	if err != nil {
		return nil, err
	}
	for i := range services {
		if services[i].Name == name {
			return &services[i], nil
		}
	}
	return nil, nil
}

// ErrNoRoute is DialService's answer for a service with no published
// port: not up yet, or its route withdrawn.
var ErrNoRoute = errors.New("the service has no published port")

// DialService opens a connection to a service's UI port for the gateway.
// The port is read from the row at the moment of the call and the
// connection opened under the same lock a withdrawal takes
// (withdrawRoute), so a row read earlier is never what connects: a
// connection opened before the route went reaches the container that
// was there, one opened after finds no route. The row is a claim and
// the runtime is the fact: the container the row names must be running,
// ours, the one recorded, and still mapping the ui port to the host
// port the row holds — a service that crashed or was stopped outside a
// job freed its port, which another lab's container may hold by now,
// and its route is withdrawn here rather than followed. The connection
// is bound to that container: a host port is bound for as long as its
// container runs, so a container found running before the connection
// and — the same run: its identity and its start time — still running
// and mapping the port after it held the port throughout, and the
// connection reached it; anything else is closed, not handed out.
func (e *Engine) DialService(ctx context.Context, instance, service string, by Actor, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (net.Conn, error) {
	e.routeMu.RLock()
	// The generation is checked here, inside the lock a withdrawal
	// takes, rather than by the caller before it: the gateway classifies
	// a host before there is anyone to authenticate, so a lab destroyed
	// and re-created between that classification and this dial would
	// otherwise be proxied to the bearer of the lab that is gone.
	if by.Gen != nil {
		inst, ierr := e.lookup(instance)
		if ierr != nil || inst == nil || inst.AuditFrom != *by.Gen {
			e.routeMu.RUnlock()
			return nil, ErrNoRoute
		}
	}
	svc, err := e.Service(instance, service)
	if err != nil {
		e.routeMu.RUnlock()
		return nil, err
	}
	if svc == nil || svc.Ports[svc.UIPort] == 0 {
		e.routeMu.RUnlock()
		return nil, ErrNoRoute
	}
	before, err := e.opts.Runtime.Inspect(ctx, svc.Container)
	if err != nil {
		e.routeMu.RUnlock()
		return nil, runtimeErr("inspect "+svc.Container, err)
	}
	if !routeLive(instance, svc, before) {
		e.routeMu.RUnlock()
		if err := e.withdrawStaleRoute(ctx, instance, svc); err != nil {
			return nil, err
		}
		return nil, ErrNoRoute
	}
	conn, err := dial(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", svc.Ports[svc.UIPort]))
	if err != nil {
		e.routeMu.RUnlock()
		return nil, err
	}
	after, err := e.opts.Runtime.Inspect(ctx, svc.Container)
	if err != nil {
		e.routeMu.RUnlock()
		_ = conn.Close()
		return nil, runtimeErr("inspect "+svc.Container, err)
	}
	if !sameRun(before, after) || !routeLive(instance, svc, after) {
		e.routeMu.RUnlock()
		_ = conn.Close()
		if err := e.withdrawStaleRoute(ctx, instance, svc); err != nil {
			return nil, err
		}
		return nil, ErrNoRoute
	}
	e.routeMu.RUnlock()
	return conn, nil
}

// RouteLive reports whether a service still publishes the port the
// gateway proxies to — the row alone, read under the lock a withdrawal
// takes. The proxy asks it before every round trip: an idle keep-alive
// connection is reused without dialling, so a request arriving after a
// withdrawal (a destroy, a stale container replaced) would otherwise
// ride the pooled connection to the container that is going. What the
// runtime says is asked at the dial, where a connection is made
// (DialService); this is the cheap half, on every request.
func (e *Engine) RouteLive(instance, service string) error {
	e.routeMu.RLock()
	defer e.routeMu.RUnlock()
	svc, err := e.Service(instance, service)
	if err != nil {
		return err
	}
	if svc == nil || svc.Ports[svc.UIPort] == 0 {
		return ErrNoRoute
	}
	return nil
}

// routeLive reports whether the container the row names is the one the
// route may be followed to: present, running, carrying this instance's
// and service's labels, the container the row recorded, and mapping the
// ui port to the host port the row holds.
func routeLive(instance string, svc *state.Service, st *runtime.ContainerState) bool {
	return portLive(instance, svc, st, svc.UIPort)
}

// portLive reports whether a service's recorded container is running,
// owned by the instance, the very container the row names, and mapping
// one container port to the host port the row records — the test the
// gateway applies to its route and the checkpoint target to its dial.
func portLive(instance string, svc *state.Service, st *runtime.ContainerState, port int) bool {
	if st == nil || !st.Running || !ownContainer(instance, svc, st) {
		return false
	}
	return svc.Ports[port] > 0 && st.Ports[port] == svc.Ports[port]
}

// ownContainer reports whether an inspected object is the service's own
// container: managed, owned by this instance and service, and — once the
// row names one — the very container it names. Anything else under the
// predictable name is a stranger: never the lab, whatever its state.
func ownContainer(instance string, svc *state.Service, st *runtime.ContainerState) bool {
	if st == nil {
		return false
	}
	want := runtime.ContainerSpec{Name: svc.Container, Labels: map[string]string{runtime.LabelInstance: instance, runtime.LabelService: svc.Name}}
	if runtime.Owned(st.Labels, want) != nil {
		return false
	}
	return svc.ContainerID == "" || st.ID == svc.ContainerID
}

// sameRun reports whether two inspections saw the same run of one
// container: the same identity and the same start time — a container
// stopped and started again in between is another run, whatever holds
// its port now.
func sameRun(before, after *runtime.ContainerState) bool {
	return after != nil && after.ID == before.ID && after.StartedAt.Equal(before.StartedAt)
}

// publishRoute records the host ports the runtime reports for the
// container the row names — the route — under the route lock.
func (e *Engine) publishRoute(svc *state.Service, ports map[int]int) error {
	e.routeMu.Lock()
	defer e.routeMu.Unlock()
	svc.Ports = ports
	return e.opts.Store.PutService(*svc)
}

// putService writes a job's copy of a service row under the route lock,
// keeping the route the row holds now: a stage or error write never
// republishes ports a withdrawal took away, nor forgets ones a
// publication landed since.
func (e *Engine) putService(svc *state.Service) error {
	e.routeMu.Lock()
	defer e.routeMu.Unlock()
	cur, err := e.Service(svc.Instance, svc.Name)
	if err != nil {
		return err
	}
	if cur != nil {
		svc.Ports = cur.Ports
	} else {
		svc.Ports = nil
	}
	return e.opts.Store.PutService(*svc)
}

// withdrawStaleRoute forgets a route DialService found dead, under the
// route lock, and only if it is still dead there: the row must still
// name the container and port found dead — a job may have published a
// replacement's route meanwhile, and that one stands — and the runtime,
// asked again under the lock, must still not show that container live,
// since a job may have started it again (the same container, the same
// port) and be waiting on the lock to publish it.
func (e *Engine) withdrawStaleRoute(ctx context.Context, instance string, seen *state.Service) error {
	e.routeMu.Lock()
	defer e.routeMu.Unlock()
	row, err := e.Service(instance, seen.Name)
	if err != nil || row == nil {
		return err
	}
	if e.afterStaleRouteRead != nil {
		e.afterStaleRouteRead()
	}
	if len(row.Ports) == 0 {
		return nil
	}
	if row.Container != seen.Container || row.ContainerID != seen.ContainerID || row.Ports[row.UIPort] != seen.Ports[seen.UIPort] {
		return nil // republished since: not the route found dead
	}
	st, err := e.opts.Runtime.Inspect(ctx, row.Container)
	if err != nil {
		return runtimeErr("inspect "+row.Container, err)
	}
	if routeLive(instance, row, st) {
		return nil // started again since: the route stands
	}
	row.Ports = nil
	if err := e.opts.Store.PutService(*row); err != nil {
		return storeErr("withdraw the route of "+row.Name, err)
	}
	return nil
}

// SystemAudit lists the system audit stream (API §2.5).
// Jobs lists an instance's job rows, newest first, with any terminal
// outcome the store refused to record folded in — the same rows View
// reads for its ladder, for a caller that must follow more than the
// latest one. The live feed is that caller: `View.Job` is the newest row
// alone, so a job that ended while another was admitted in the same
// window disappeared behind it.
func (e *Engine) Jobs(instance string, by Actor) ([]state.Job, error) {
	jobs, err := e.opts.Store.ListJobs(instance)
	if err != nil {
		return nil, storeErr("list jobs of "+instance, err)
	}
	for i := range jobs {
		if final, ok := e.knownOutcome(jobs[i].ID); ok {
			jobs[i] = final
		}
	}
	if by.Gen != nil {
		// The retained history of the labs that held this name before is
		// not this bearer's.
		mine := jobs[:0]
		for _, j := range jobs {
			if j.Gen == *by.Gen {
				mine = append(mine, j)
			}
		}
		jobs = mine
	}
	return jobs, nil
}

func (e *Engine) Audit(instance string) ([]state.Audit, error) {
	list, err := e.opts.Store.ListAudit(instance)
	if list == nil {
		list = []state.Audit{}
	}
	return list, err
}

func networkName(instance string) string        { return "pdr-" + instance }
func containerName(instance, svc string) string { return "pdr-" + instance + "-" + svc }

// jobRand is the entropy source for job ids (a seam for tests, as the
// runtime's randReader is).
var jobRand io.Reader = rand.Reader

// newJobID draws a job id, or says why it could not. Entropy that fails
// is never a silent `job_0000000000000000`: PutJob upserts on the id, so
// two admissions sharing one id would have the second overwrite the
// first's row — another instance's job, in the worst case — and both
// workers and every API client would then read one row for two jobs.
func newJobID() (string, error) {
	var b [8]byte
	if _, err := io.ReadFull(jobRand, b[:]); err != nil {
		pe := pdr.New(pdr.CodeRuntimeFailed, "could not draw a job id")
		pe.Cause = "the system entropy source failed: " + err.Error()
		pe.Next = "check the host's entropy source (journalctl --user -u podaro) and re-run"
		return "", pe
	}
	return "job_" + hex.EncodeToString(b[:]), nil
}

// freshJobID draws an id the state database does not already hold. The
// draw is 64 bits, so a collision is vanishingly unlikely — but "unlikely"
// is not "impossible", and the cost of one is another job's row silently
// replaced, so the id is checked before it is recorded rather than after.
// A store that cannot answer is a fault, never "the id is free": the same
// rule the instance-name lookup already keeps, so no admission ever
// upserts over what may be there.
func (e *Engine) freshJobID() (string, error) {
	for i := 0; i < 8; i++ {
		id, err := newJobID()
		if err != nil {
			return "", err
		}
		_, err = e.opts.Store.GetJob(id)
		switch {
		case errors.Is(err, state.ErrNotFound):
			return id, nil
		case err != nil:
			return "", storeErr("look up job "+id, err)
		}
	}
	pe := pdr.New(pdr.CodeRuntimeFailed, "could not draw an unused job id")
	pe.Cause = "eight draws in a row named a job the state database already holds"
	pe.Next = "check the state database (journalctl --user -u podaro) and re-run"
	return "", pe
}

// nameSuffix yields the random part of a generated instance name: eight
// hex characters (32 bits). Tests replace it to force collisions.
var nameSuffix = func() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func generateName(template string) string {
	base := template
	if len(base) > 15 { // 15 + "-" + 8 = the 24-character label limit
		base = base[:15]
	}
	base = strings.TrimRight(base, "-")
	return base + "-" + nameSuffix()
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func runtimeErr(op string, err error) error {
	var pe *pdr.Error
	if errors.As(err, &pe) {
		return pe
	}
	e := pdr.New(pdr.CodeRuntimeFailed, "%s failed", op)
	e.Cause = err.Error()
	e.Next = "podaro doctor · then re-run to resume at this step"
	return e
}

// jobRedactor is the redaction filter of the instance a running job
// belongs to (an empty filter for a job this engine did not launch), or
// the refusal an unreadable secret store earns (redactor).
func (e *Engine) jobRedactor(jobID string) (*secrets.Redactor, *pdr.Error) {
	e.mu.Lock()
	instance, ok := e.jobInstances[jobID]
	kind := e.jobKinds[jobID]
	e.mu.Unlock()
	if !ok || instance == "" {
		return nil, nil
	}
	return e.filterFor(kind, instance)
}

// filterFor is the redaction filter a job of one kind persists through:
// every job fails closed (redactor) but a destroy, which proceeds with the
// filter that can be built — it is the remedy the refusal names, and its
// journal carries step names, object names and verb-only runtime errors,
// never product output.
func (e *Engine) filterFor(kind, instance string) (*secrets.Redactor, *pdr.Error) {
	red, perr := e.redactor(instance)
	if perr != nil && kind == "destroy" {
		values, _ := e.secretStore(instance).Values()
		e.opts.Logf("%s: destroy proceeds with the redaction filter that can be built — %s", instance, perr.Message)
		return secrets.NewRedactor(values), nil
	}
	return red, perr
}

// redactErr passes an error's text through an instance's redaction
// filter: a PDR envelope keeps its shape with each field filtered; any
// other error becomes its filtered text. A runtime error may carry what
// podman printed about a rendered command, so nothing an error says is
// persisted or logged unfiltered.
func (e *Engine) redactErr(instance string, err error) error {
	return e.redactErrFor("", instance, err)
}

// redactErrFor is redactErr for a job of one kind (filterFor).
func (e *Engine) redactErrFor(kind, instance string, err error) error {
	if err == nil || instance == "" {
		return err
	}
	red, perr := e.filterFor(kind, instance)
	if perr != nil {
		// Fail closed: a text the filter never saw is neither persisted
		// nor logged. The failure recorded is the store's; the one it
		// stands for is withheld, and the record says so (round 21).
		out := *perr
		out.Cause += " — the failure this record stands for is withheld: its text could not be filtered"
		return &out
	}
	if red.Empty() {
		return err
	}
	var pe *pdr.Error
	if errors.As(err, &pe) {
		out := *pe
		out.Message, out.Cause, out.Evidence, out.Next = red.Redact(pe.Message), red.Redact(pe.Cause), red.Redact(pe.Evidence), red.Redact(pe.Next)
		if len(pe.Details) > 0 {
			out.Details = make([]pdr.Detail, len(pe.Details))
			for i, d := range pe.Details {
				d.Path, d.Hint = red.Redact(d.Path), red.Redact(d.Hint)
				out.Details[i] = d
			}
		}
		return &out
	}
	if filtered := red.Redact(err.Error()); filtered != err.Error() {
		return errors.New(filtered)
	}
	return err
}

func errMessage(err error) string {
	var pe *pdr.Error
	if errors.As(err, &pe) {
		if pe.Cause != "" {
			return pe.Code + " " + pe.Message + ": " + pe.Cause
		}
		return pe.Code + " " + pe.Message
	}
	return err.Error()
}

// envelopeJSON serializes an error as the API §3 envelope for the job
// record; a non-pdr error becomes a runtime-failed envelope.
// envelope is the §3 envelope of a job failure: the PDR error itself, or
// any other error wrapped as a runtime failure.
func envelope(err error) *pdr.Error {
	var pe *pdr.Error
	if !errors.As(err, &pe) {
		pe = pdr.New(pdr.CodeRuntimeFailed, "%s", err.Error())
	}
	return pe
}

// parseDuration accepts the spec's duration form (30s, 5m, 1h, 500ms).
func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	return time.ParseDuration(s)
}

// httpProbe is the readiness check: one GET, one expected status.
func httpProbe(ctx context.Context, url string, expect int) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := probeClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode == expect
}

var probeClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport:     &http.Transport{TLSClientConfig: insecureTLS(), DisableKeepAlives: true},
}

// copyTree copies a template directory into a snapshot directory.
func copyTree(src, dst string) error {
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		// A template ships what it contains. WalkDir does not descend a
		// symlink, but os.ReadFile follows one, so a link to a host file
		// used to be copied in as an ordinary file — and validation,
		// which runs on the snapshot and after it, then had no link left
		// to refuse. Spec 0003 §9's wall belongs here, where the copy
		// happens: it is the earliest point and it covers the whole tree
		// rather than the declared assets alone.
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; a template ships only what it contains (spec 0003 §9)", rel)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o600)
	})
}

// readinessOf finds a service's readiness declaration in the validated
// composition: the effective module's, or the inline service's.
// DefaultReadinessBudget is the start budget of a readiness block that
// declares none: the value the engine waits for, and the one the row, the
// journal and PDR-E205 report, so a miss names the limit that applied.
const DefaultReadinessBudget = "2m"

// budgetDuration parses a row's budget, falling to the default for a row
// written before budgetOf normalized it.
func budgetDuration(s string) time.Duration {
	if d, err := parseDuration(s); err == nil {
		return d
	}
	d, _ := parseDuration(DefaultReadinessBudget)
	return d
}

// latest is the later of two instants.
func latest(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// budgetOf is the effective budget of a readiness block: the declared one,
// else the default.
func budgetOf(r *lab.PlanReadiness) string {
	if r != nil && r.Budget != "" {
		return r.Budget
	}
	return DefaultReadinessBudget
}

// readinessDigest fingerprints the probe contract a healthy is proven
// under (scheme, port, path, expected status); nil readiness is "".
func readinessDigest(r *lab.Readiness) string {
	if r == nil {
		return ""
	}
	p := r.Probe
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s|%d", p.Scheme, p.Port, p.Path, p.ExpectStatus)))
	return "sha256:" + hex.EncodeToString(sum[:8])
}

func readinessOf(res *lab.Result, name string) *lab.Readiness {
	if res == nil || res.Composition == nil {
		return nil
	}
	cs, ok := res.Composition.Services[name]
	if !ok {
		return nil
	}
	if cs.Module != nil {
		return cs.Module.Readiness
	}
	return cs.Svc.Readiness
}
