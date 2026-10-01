// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/secrets"
	"github.com/jeremiahjrross/podaro/internal/state"
	"github.com/jeremiahjrross/podaro/internal/verify"
)

// labView is what a job or a read resolved for one instance: the plan and
// validated result of its source (a delivery instance's snapshot, an
// authoring instance's directory), the flattened checkpoint set, and
// which seeds create runs.
type labView struct {
	// want is the generation the caller was entitled to when this view
	// was resolved, or nil for a caller entitled to none. An operation
	// that reads further resources by name after resolving — the
	// journal, the secret store, the instance's directory — must call
	// `still` before returning what it found.
	want        *int64
	inst        *state.Instance
	plan        *lab.Plan
	res         *lab.Result
	checkpoints []lab.FlatCheckpoint
	standing    []string
	actions     []string
	// recreated is set by a job's service loop when any service got a new
	// container (a fresh create, a replaced or vanished container): the
	// data the old one held is gone, so standing seeds run again. A
	// reconcile that merely restarted stopped containers leaves it false
	// and keeps the data it finds (User Manual §8: after a reboot,
	// baselines re-verify — nothing is injected twice).
	recreated bool
	// reconcile marks a walk of the create path over a lab that already
	// ran: containers found with their data keep it (init not re-run,
	// standing seeds not re-injected) — a reconcile job's walk, and the
	// restoration a seed or verify resumed after a reboot does first.
	reconcile bool
	// unsupported marks the record-only view of an instance whose
	// template the owner retired (recordViewFor): no plan, no result,
	// no checkpoints — this release cannot make them — and the reads it
	// serves take the stored rows as the record they are.
	unsupported bool
}

// loadLab plans an instance's source with the library it was admitted
// with and flattens what the instance evaluates. An instance of a
// retired template is refused here, before its source is read: every
// read and every job that needs the lab comes through this, so none of
// them can plan, and so run, the retired lab (PDR-E215; the
// reconciliation plan's R3).
func (e *Engine) loadLab(inst *state.Instance) (*labView, error) {
	if retiredTemplate(inst) {
		return nil, e.unsupported(inst)
	}
	library, err := e.libraryFor(inst)
	if err != nil {
		return nil, err
	}
	plan, res, err := lab.MakePlan(lab.PlanOptions{Options: lab.Options{Path: inst.Source, Library: library}, Profile: inst.Profile})
	if err != nil {
		return nil, err
	}
	lv := &labView{inst: inst, plan: plan, res: res, checkpoints: lab.FlattenCheckpoints(res)}
	lv.standing, lv.actions = lab.SeedRoles(res)
	return lv, nil
}

// StepSeeds names the seeds a playbook step invokes as an action — the
// "step seeds" of API §2.4's fixed grant. Every other seed the template
// declares is a standing seed: create's own injection, the instance's
// starting data, and not an act the grant puts in an attendee's hands
// (lab.SeedRoles).
func (e *Engine) StepSeeds(name string, by Actor) (ret []string, err error) {
	lv, err := e.instanceViewFor(name, by.Gen)
	if err != nil {
		return nil, err
	}
	defer func() { err = e.confirmed(lv, err) }()
	return append([]string(nil), lv.actions...), nil
}

// checkpoint finds a flattened checkpoint by id.
func (lv *labView) checkpoint(id string) (lab.FlatCheckpoint, bool) {
	for _, cp := range lv.checkpoints {
		if cp.ID == id {
			return cp, true
		}
	}
	return lab.FlatCheckpoint{}, false
}

// service finds a planned service by name.
func (lv *labView) service(name string) (lab.PlanService, bool) {
	for _, ps := range lv.plan.Services {
		if ps.Name == name {
			return ps, true
		}
	}
	return lab.PlanService{}, false
}

// instanceView resolves an instance and its lab for the read surfaces.
func (e *Engine) instanceView(name string) (*labView, error) {
	return e.instanceViewFor(name, nil)
}

// instanceViewFor is instanceView for a caller entitled to one
// generation of this name. The comparison is against the instance this
// very call resolved, so there is no gap between deciding and acting —
// a caller that checks first and then lets the operation resolve again
// has only moved the window.
func (e *Engine) instanceViewFor(name string, want *int64) (*labView, error) {
	inst, err := e.lookup(name)
	if err != nil {
		return nil, err
	}
	if inst == nil {
		return nil, e.notFound(name)
	}
	if want != nil && inst.AuditFrom != *want {
		// The same answer a lab outside the grant gets: to this bearer,
		// a name that came back is a lab that is not there.
		return nil, e.notFound(name)
	}
	lv, err := e.loadLab(inst)
	if lv != nil {
		lv.want = want
	}
	return lv, err
}

// still reports that the lab this view was resolved against is still the
// one the name means. Everything an operation reads after resolving — a
// journal, a secret store, a directory — is addressed by name, so the
// comparison at resolution covers the resolution and nothing after it.
//
// Asking again at the end is enough, and that is not an approximation:
// an instance's `audit_from` is the audit high-water mark it was created
// at, and the audit sequence only ever increases, so a name cannot
// return to a generation it has left. Equal before and equal after
// therefore means it was never anything else in between, and everything
// read in between was this generation's.
// confirmed is `still` in the shape a deferred check needs: it keeps the
// first error when there is one, and otherwise reports whether the lab
// is still the one this view was resolved against.
func (e *Engine) confirmed(lv *labView, err error) error {
	if err != nil {
		return err
	}
	return e.still(lv)
}

func (e *Engine) still(lv *labView) error {
	if lv == nil || lv.want == nil {
		return nil
	}
	inst, err := e.lookup(lv.inst.Name)
	if err != nil {
		return err
	}
	if inst == nil || inst.AuditFrom != *lv.want {
		return e.notFound(lv.inst.Name)
	}
	return nil
}

// Per-instance paths (INSTALL §3: instances/<name>/ holds secrets,
// generated config, evidence).
func (e *Engine) secretStore(name string) *secrets.Store {
	return secrets.NewStore(filepath.Join(e.instanceDir(name), "secrets"))
}

// journal is the instance's evidence journal — one per instance for the
// engine's lifetime, so ids stay monotonic across every append within a
// millisecond and List's id order is the append order.
// Destroy forgets it with the rest of the instance's
// in-memory state (guard.go).
func (e *Engine) journal(name string) *evidence.Journal {
	e.journalMu.Lock()
	defer e.journalMu.Unlock()
	if e.journals == nil {
		e.journals = map[string]*evidence.Journal{}
	}
	j, ok := e.journals[name]
	if !ok {
		j = evidence.Open(filepath.Join(e.instanceDir(name), "evidence"))
		e.journals[name] = j
	}
	return j
}

func (e *Engine) envDir(name string) string { return filepath.Join(e.instanceDir(name), "env") }

// redactor builds the filter for an instance from its secret store —
// every value it holds, every time, so a value generated a moment ago is
// filtered too. The filter must hold a value for every secret the instance
// is known to have — the names its last secrets step generated or found,
// and every name the store keeps a kind record for — or it is no filter:
// a store that cannot be read, or that lost a value the running containers
// were configured with (a directory removed, a file deleted), refuses the
// operation that needed it — a result, a seed report, a journal line, a
// failure record — rather than persist or log text the filter never saw
// (PDR-E412).
func (e *Engine) redactor(name string) (*secrets.Redactor, *pdr.Error) {
	store := e.secretStore(name)
	values, err := store.Values()
	if err != nil {
		return nil, unreadableSecrets(name, err)
	}
	expected, err := e.expectedSecrets(name, store)
	if err != nil {
		return nil, unreadableSecrets(name, err)
	}
	var missing []string
	for _, n := range expected {
		if _, ok := values[n]; !ok {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return nil, missingSecrets(name, missing)
	}
	return secrets.NewRedactor(values), nil
}

// expectedSecrets names the secrets an instance's filter must hold: every
// secret ever generated for it — the history the state database keeps
// (Store.GeneratedSecrets), append-only until destroy, so an authoring
// edit that drops a declaration keeps its value expected while a container
// may still hold it, and one that adds a declaration expects nothing until
// the next create, reconcile or reset generates the value — brought up,
// first, to what the secret store itself shows generated: its kind records
// and the values present, which cover a value generated moments before its
// history row could land and everything an earlier release generated
// before the history existed (rememberGeneratedSecrets). Never the current
// plan, which is neither where the values came from nor immutable.
// An instance that is gone expects nothing —
// a destroy's last lines.
func (e *Engine) expectedSecrets(name string, store *secrets.Store) ([]string, error) {
	return e.rememberGeneratedSecrets(name, store)
}

// rememberGeneratedSecrets adds to an instance's history every secret its
// store shows generated — a kind record, or a value present — that the
// history does not hold yet, and returns the union, sorted. Start runs it
// for every instance before anything relies on the history: a database
// upgraded to migration 7 holds none for what earlier releases generated,
// and this is where that is remembered, while the store still has the
// records. An instance the database no
// longer has is remembered nowhere: nothing is expected of it.
func (e *Engine) rememberGeneratedSecrets(name string, store *secrets.Store) ([]string, error) {
	recorded, err := store.Recorded()
	if err != nil {
		return nil, err
	}
	present, err := store.Names()
	if err != nil {
		return nil, err
	}
	history, err := e.opts.Store.GeneratedSecrets(name)
	if err != nil {
		return nil, fmt.Errorf("read the generated secrets of %s: %w", name, err)
	}
	set := map[string]bool{}
	for _, n := range history {
		set[n] = true
	}
	var missing []string
	for _, n := range append(recorded, present...) {
		if !set[n] {
			set[n] = true
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		if err := e.opts.Store.AddGeneratedSecrets(name, missing); err != nil && !errors.Is(err, state.ErrNotFound) {
			return nil, fmt.Errorf("record the generated secrets of %s: %w", name, err)
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// missingSecrets is the refusal a store that lost a value earns: the
// containers were configured with it, so the value is out there and the
// filter cannot know it; nothing that could carry it is recorded, and the
// remedy is a destroy — the one job that proceeds with the filter that
// can be built (filterFor).
func missingSecrets(name string, missing []string) *pdr.Error {
	pe := pdr.New(pdr.CodeSecretStoreUnreadable, "the secret store of %s holds no value for %s, so nothing that could carry a secret is recorded", name, strings.Join(missing, ", "))
	pe.Cause = "the secret was generated for the instance and its containers were configured with the value; the store's file is gone — a directory removed, a file deleted — so the redaction filter cannot know what to filter"
	pe.Next = "the value cannot be regenerated in place: podaro destroy " + name + " and up again (a destroy proceeds with the filter that can be built) · or restore instances/" + name + "/secrets from where it went"
	return pe
}

// unreadableSecrets is the refusal an unreadable secret store earns: the
// operation that needed the filter does not happen, and the record says
// why — the store's error names a path, never a value.
func unreadableSecrets(name string, err error) *pdr.Error {
	pe := pdr.New(pdr.CodeSecretStoreUnreadable, "the secret store of %s cannot be read, so nothing that could carry a secret is recorded", name)
	pe.Cause = err.Error()
	pe.Next = "restore instances/" + name + "/secrets under the state directory — a directory the engine's user owns, mode 0700, one 0600 file per secret — then re-run · podaro doctor"
	return pe
}

// internalNetworkName is the instance's second network: no route out,
// where one-shot runs reach lab services and nothing else (Spec 0002 §2).
// internalNetworkName names an instance's second, internal network. The
// underscore, which no instance name can carry (they are DNS labels),
// keeps it apart from every instance's primary network: with a hyphen,
// instance foo's internal network and instance foo-int's primary one
// would both have been pdr-foo-int.
func internalNetworkName(instance string) string { return "pdr-" + instance + "_int" }

// --- the checkpoint target --------------------------------------------------

// instanceTarget is how adapters and seeds reach an instance: through the
// loopback ports its services publish (threat model B4 — the engine never
// joins an instance network), and the endpoints its plan declares.
type instanceTarget struct {
	e  *Engine
	lv *labView
}

func (t *instanceTarget) Resolve(service string, port int) (string, error) {
	_, hp, err := t.published(service, port)
	if err != nil {
		return "", err
	}
	return "127.0.0.1:" + strconv.Itoa(hp), nil
}

// published finds the service row and the host port it records for one
// container port.
func (t *instanceTarget) published(service string, port int) (*state.Service, int, error) {
	svc, err := t.e.Service(t.lv.inst.Name, service)
	if err != nil {
		return nil, 0, err
	}
	if svc == nil {
		return nil, 0, fmt.Errorf("no such service %q (services: %s)", service, strings.Join(t.lv.plan.Network.Aliases, ", "))
	}
	if hp := svc.Ports[port]; hp > 0 {
		return svc, hp, nil
	}
	var published []string
	for _, p := range sortedPorts(svc.Ports) {
		published = append(published, strconv.Itoa(p))
	}
	if len(published) == 0 {
		return nil, 0, fmt.Errorf("service %s publishes no port yet (stage %s) — is it running?", service, stageWord(svc.Stage))
	}
	return nil, 0, fmt.Errorf("service %s does not publish port %d — only its declared endpoints and readiness port are reachable (published: %s)", service, port, strings.Join(published, ", "))
}

// Dial connects to the loopback port a service publishes for one of its
// container ports, verifying — as the gateway's DialService does — that
// the recorded container is running, owned and mapping that port before
// the dial and unchanged after it. A service that crashed or was stopped
// outside a job keeps its row and its ports until a job reconciles them;
// the kernel may meanwhile hand the ephemeral host port to any listener,
// and a checkpoint judged or a seed delivered through it would be judged
// or delivered to the wrong door.
func (t *instanceTarget) Dial(ctx context.Context, service string, port int) (net.Conn, error) {
	svc, hp, err := t.published(service, port)
	if err != nil {
		return nil, err
	}
	rt := t.e.opts.Runtime
	before, err := rt.Inspect(ctx, svc.Container)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", svc.Container, err)
	}
	if !portLive(t.lv.inst.Name, svc, before, port) {
		return nil, fmt.Errorf("service %s is not running its recorded container on port %d — it stopped or was replaced outside a job; verify or reset the instance", service, port)
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", "127.0.0.1:"+strconv.Itoa(hp))
	if err != nil {
		return nil, err
	}
	after, err := rt.Inspect(ctx, svc.Container)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("inspect %s: %w", svc.Container, err)
	}
	if !sameRun(before, after) || !portLive(t.lv.inst.Name, svc, after, port) {
		_ = conn.Close()
		return nil, fmt.Errorf("service %s changed while connecting to port %d — its container stopped or was replaced; verify or reset the instance", service, port)
	}
	return conn, nil
}

func (t *instanceTarget) Container(ctx context.Context, service string) (*verify.ContainerFacts, error) {
	svc, err := t.e.Service(t.lv.inst.Name, service)
	if err != nil {
		return nil, err
	}
	if svc == nil {
		return nil, fmt.Errorf("no such service %q (services: %s)", service, strings.Join(t.lv.plan.Network.Aliases, ", "))
	}
	// The attempt's context: an inspect that stalls ends with the
	// checkpoint's timeout (PDR-E401) instead of holding the run.
	st, err := t.e.opts.Runtime.Inspect(ctx, svc.Container)
	if err != nil {
		return nil, err
	}
	facts := &verify.ContainerFacts{Stage: string(svc.Stage)}
	// Only the service's own container is a fact about the service: an
	// object under the predictable name that this instance does not own,
	// or that is not the container the row names, is a stranger — absent,
	// to the adapter — never a running lab;
	// the gateway's route and the target's dial apply the same rule.
	if st != nil && ownContainer(t.lv.inst.Name, svc, st) {
		facts.Exists = true
		facts.Running = st.Running
		facts.Labels = st.Labels
		// Healthy is a fact about now: the service's declared readiness
		// probe answered, on the live container's published port — never
		// the ladder's record of a probe that once passed, which a
		// container that keeps running while its product fails, or one
		// stopped and restarted outside a job, would still carry.
		// A service that declares no readiness
		// cannot be called healthy: its ladder stops at alive. And the
		// answer is the container's only if the same run of it held the
		// port before and after the probe (round 21).
		if st.Running {
			healthy, err := t.probeHealthy(ctx, svc, st)
			if err != nil {
				return nil, err
			}
			facts.Healthy = healthy
		}
	}
	return facts, nil
}

// probeHealthy runs the service's declared readiness probe once against
// the recorded container's published port, within the attempt's context —
// the same probe the create path waits on (bringUp). The answer is the
// container's only if the same run of it — identity and start time — was
// running and mapping the recorded port before the probe and still is
// after it, as the target's dial requires:
// a container stopped or replaced meanwhile hands its host port to
// whoever binds it next, and that listener's answer is nobody's health.
// An inspection after the probe that the runtime cannot answer — the
// attempt's time ran out during it, the runtime failed — is returned as
// the error it is, never folded into a health value: a `healthy: false`
// expectation would otherwise pass on a question the engine could not
// answer, and a `healthy: true` one fail instead of erroring.
func (t *instanceTarget) probeHealthy(ctx context.Context, svc *state.Service, before *runtime.ContainerState) (bool, error) {
	readiness := readinessOf(t.lv.res, svc.Name)
	if readiness == nil || readiness.Probe.Port == 0 {
		return false, nil
	}
	r := readiness.Probe
	path, expect, scheme := "/", 200, "http"
	if r.Path != "" {
		path = r.Path
	}
	if r.ExpectStatus != 0 {
		expect = r.ExpectStatus
	}
	if r.Scheme != "" {
		scheme = r.Scheme
	}
	if !portLive(t.lv.inst.Name, svc, before, r.Port) {
		return false, nil
	}
	if !t.e.opts.Probe(ctx, fmt.Sprintf("%s://127.0.0.1:%d%s", scheme, svc.Ports[r.Port], path), expect) {
		if err := ctx.Err(); err != nil {
			// A probe that consumed the attempt's time answered nothing:
			// the checkpoint times out (PDR-E401) rather than record an
			// unhealthy service it never observed.
			return false, fmt.Errorf("probe %s: %w", svc.Name, err)
		}
		return false, nil
	}
	after, err := t.e.opts.Runtime.Inspect(ctx, svc.Container)
	if err != nil {
		return false, fmt.Errorf("inspect %s after its probe: %w", svc.Container, err)
	}
	return sameRun(before, after) && portLive(t.lv.inst.Name, svc, after, r.Port), nil
}

// Endpoint is the seed resolver's: a service's declared endpoint port and
// scheme for a purpose ("" for the first declared).
func (t *instanceTarget) Endpoint(service, purpose string) (int, string, bool) {
	ep, ok := lab.EndpointOf(t.lv.res, service, purpose)
	if !ok {
		return 0, "", false
	}
	return ep.Port, ep.Scheme, true
}

func sortedPorts(m map[int]int) []int {
	out := make([]int, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func stageWord(s state.Stage) string {
	if s == state.StageNone {
		return "created"
	}
	return string(s)
}

// --- the connected rung -----------------------------------------------------

// connectBudget bounds how long a service may take to accept connections
// on its declared endpoints once healthy.
const connectBudget = 60 * time.Second

// connected proves a service's declared endpoints accept connections on
// their published loopback ports — what the gateway proxies and adapters
// query — polling until the budget. Each connection is attributed to the
// recorded container run as the target's dial attributes a checkpoint's
// (instanceTarget.Dial): the container is inspected before and after the
// dial and must be the one the row names, running the same run, mapping
// the port — a service that exited after its readiness probe, its host
// port taken by an unrelated listener, is a failed rung, named, never a
// connected one.
func (e *Engine) connected(ctx context.Context, svc *state.Service, endpoints []lab.Endpoint) error {
	deadline := time.Now().Add(connectBudget)
	rt := e.opts.Runtime
	for {
		// The run first, endpoints or none: the container the row names
		// must be running the run readiness was proven on — a service that
		// declares no endpoints is otherwise treated as connected without
		// a look.
		before, err := rt.Inspect(ctx, svc.Container)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", svc.Container, err)
		}
		if err := recordedRun(svc, before); err != nil {
			return err
		}
		var pending []string
		for _, ep := range endpoints {
			hp := svc.Ports[ep.Port]
			if hp == 0 {
				return fmt.Errorf("%s publishes no host port for endpoint %s :%d", svc.Name, ep.Purpose, ep.Port)
			}
			if !portLive(svc.Instance, svc, before, ep.Port) {
				return fmt.Errorf("%s is not running its recorded container %s on port %d: it stopped or was replaced after its readiness probe, and whatever listens there now is not the service", svc.Name, shortID(svc.ContainerID), ep.Port)
			}
			conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(hp), 2*time.Second)
			if err != nil {
				pending = append(pending, fmt.Sprintf("%s :%d", ep.Purpose, ep.Port))
				continue
			}
			conn.Close()
			after, err := rt.Inspect(ctx, svc.Container)
			if err != nil {
				return fmt.Errorf("inspect %s: %w", svc.Container, err)
			}
			if !sameRun(before, after) || !portLive(svc.Instance, svc, after, ep.Port) {
				return fmt.Errorf("%s changed while connecting to port %d: its container stopped or was replaced, and the listener that answered is not the service", svc.Name, ep.Port)
			}
		}
		if len(pending) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s does not accept connections on %s within %s", svc.Name, strings.Join(pending, ", "), connectBudget)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// recordedRun reports whether an inspected object is the service's
// recorded container running the run readiness was proven on: present,
// running, owned, the id the row names, and started when the row says
// (bringUp records the start it probed). The same container restarted
// since — its id and ports unchanged — is another run that never passed
// readiness, and nothing it does proves anything; a re-run proves
// readiness again for the new run.
// A runtime that reports no start time has nothing to hold the row's
// to.
func recordedRun(svc *state.Service, st *runtime.ContainerState) error {
	if st == nil || !st.Running || !ownContainer(svc.Instance, svc, st) {
		return fmt.Errorf("%s is not running its recorded container %s: it stopped or was replaced after its readiness probe", svc.Name, shortID(svc.ContainerID))
	}
	if !st.StartedAt.IsZero() && (svc.StartedAt == nil || !st.StartedAt.Equal(*svc.StartedAt)) {
		return fmt.Errorf("%s was restarted after its readiness probe: readiness was proven on the run started at %s, the run listening now started at %s — re-run to prove it again", svc.Name, startedWord(svc.StartedAt), st.StartedAt.UTC().Format(time.RFC3339Nano))
	}
	return nil
}

// startedWord renders a recorded start time, or its absence.
func startedWord(t *time.Time) string {
	if t == nil {
		return "an unrecorded time"
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// --- rows for every checkpoint ---------------------------------------------

// ensureResultRows records a pending (never evaluated) result for every
// checkpoint the plan declares and forgets rows for checkpoints it no
// longer does, so the tally's totals are known from the moment a create
// starts and an authoring instance's renamed checkpoint leaves no ghost.
func (e *Engine) ensureResultRows(lv *labView) error {
	// Under the instance lock, as a run's record is (guard.go): a result a
	// permitted concurrent run records for the current definition either
	// lands before this read — and is kept — or waits for these writes and
	// then stands; the pending row can never replace it.
	lock := e.instanceLock(lv.inst.Name)
	lock.Lock()
	defer lock.Unlock()
	existing, err := e.opts.Store.ListCheckpointResults(lv.inst.Name)
	if err != nil {
		return storeErr("list checkpoint results of "+lv.inst.Name, err)
	}
	have := map[string]state.CheckpointResult{}
	for _, r := range existing {
		have[r.ID] = r
	}
	declared := map[string]bool{}
	for _, cp := range lv.checkpoints {
		declared[cp.ID] = true
		row, ok := have[cp.ID]
		digest := lab.DefinitionDigest(cp)
		if ok && row.Class == cp.ResolvedClass && row.Adapter == cp.Adapter && row.Definition == digest {
			continue
		}
		if beforeEnsureWrite != nil {
			beforeEnsureWrite(lv.inst.Name)
		}
		// A new checkpoint, or one whose definition changed under an
		// authoring instance — class, adapter, params, expectation, timeout
		// or retries: a fresh pending row. No verdict carries across a
		// changed definition; the
		// next verify judges it anew.
		row = state.CheckpointResult{Instance: lv.inst.Name, ID: cp.ID, Class: cp.ResolvedClass, Adapter: cp.Adapter, Definition: digest}
		if err := e.opts.Store.PutCheckpointResult(row); err != nil {
			return storeErr("record checkpoint "+cp.ID, err)
		}
	}
	for id := range have {
		if !declared[id] {
			// One row at a time: DeleteCheckpointResults works by class, so
			// a stale row is replaced by nothing through the class delete of
			// a synthetic class it alone carries.
			stale := have[id]
			stale.Class = "stale"
			if err := e.opts.Store.PutCheckpointResult(stale); err != nil {
				return storeErr("retire checkpoint "+id, err)
			}
		}
	}
	if err := e.opts.Store.DeleteCheckpointResults(lv.inst.Name, "stale"); err != nil {
		return storeErr("retire stale checkpoints of "+lv.inst.Name, err)
	}
	return nil
}

// beforeEnsureWrite is a test seam: called by ensureResultRows, inside the
// instance lock, after it read the rows and before it writes a pending
// one, so a test can interleave a run's record there. Nil in production.
var beforeEnsureWrite func(instance string)

// currentResults is ensureResultRows' read-side twin: the latest row of
// every declared checkpoint as it stands for the checkpoint's current
// definition. A row judged by a definition since changed — an authoring
// edit after its last run, or a row from before definitions were
// recorded — is presented as pending, never evaluated for what the
// checkpoint now is, until a job's ensureResultRows resets it and the
// next evaluation judges it anew; a row for a checkpoint the plan no
// longer declares is left out. Nothing is written: a read stays a read.
func (lv *labView) currentResults(rows []state.CheckpointResult) []state.CheckpointResult {
	if lv.unsupported {
		// No definition to hold them to: this release cannot plan the
		// retired lab, so the rows stand as the record of what was last
		// judged, which is what the reports of it say.
		return rows
	}
	have := map[string]state.CheckpointResult{}
	for _, r := range rows {
		have[r.ID] = r
	}
	out := make([]state.CheckpointResult, 0, len(lv.checkpoints))
	for _, cp := range lv.checkpoints {
		digest := lab.DefinitionDigest(cp)
		if r, ok := have[cp.ID]; ok && r.Class == cp.ResolvedClass && r.Adapter == cp.Adapter && r.Definition == digest {
			out = append(out, r)
			continue
		}
		out = append(out, state.CheckpointResult{Instance: lv.inst.Name, ID: cp.ID, Class: cp.ResolvedClass, Adapter: cp.Adapter, Definition: digest})
	}
	return out
}

// gatesPass reports whether every gate baseline the plan declares has a
// pass among the rows — what ready means (roadmap §1 invariant 3), the
// same test the verify job applies to the results it produced.
func (lv *labView) gatesPass(rows []state.CheckpointResult) bool {
	status := map[string]string{}
	for _, r := range rows {
		status[r.ID] = r.Status
	}
	for _, cp := range lv.checkpoints {
		if cp.ResolvedClass == "baseline" && cp.Severity() == "gate" && status[cp.ID] != verify.StatusPass {
			return false
		}
	}
	return true
}

// tally counts the latest results by class (API §7.2; spec 0001 §1: never
// summed).
func tally(results []state.CheckpointResult) Tally {
	var t Tally
	for _, r := range results {
		switch r.Class {
		case "baseline":
			t.Baseline.Total++
			if r.Status == verify.StatusPass {
				t.Baseline.Passed++
			}
		case "objective":
			t.Objective.Total++
			switch r.Status {
			case verify.StatusPass, verify.StatusAttested:
				t.Objective.Passed++
			case verify.StatusFail, verify.StatusError:
				t.Objective.Failed++
			}
		}
	}
	return t
}

// notFoundKind is a 404 envelope for a sub-resource of an instance.
func notFoundKind(code, kind, id, next string) *pdr.Error {
	pe := pdr.New(code, "no such %s %q", kind, id)
	pe.Next = next
	return pe
}

// instanceGone tells a job's absent instance from a store fault.
func instanceGone(err error) bool { return errors.Is(err, state.ErrNotFound) }

// runtimeOf exposes the runtime to sub-packages' seams.
func (e *Engine) runtimeOf() runtime.Runtime { return e.opts.Runtime }
