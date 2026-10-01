// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// InstanceView is the API §7.2 instance object: state plus the ladder
// the console and CLI render identically (UX §5).
type InstanceView struct {
	Name        string        `json:"name"`
	Template    string        `json:"template"`
	Profile     string        `json:"profile,omitempty"`
	Mode        string        `json:"mode"`
	Created     time.Time     `json:"created"`
	Ladder      LadderView    `json:"ladder"`
	Services    []ServiceView `json:"services"`
	Checkpoints Tally         `json:"checkpoints"`
	ConsoleURL  string        `json:"console_url"`
	Job         *state.Job    `json:"job"`
	// Error is the failed job's envelope when the last job failed.
	Error *pdr.Error `json:"error,omitempty"`
	// Unsupported says why this release does not operate the instance —
	// "retired template", when an earlier build created it from a
	// template the owner has since retired (the reconciliation plan's
	// R3) — and the ladder's word reads "unsupported · retired template".
	// Omitted otherwise, so every other instance answers exactly as it
	// did before the field existed.
	Unsupported string `json:"unsupported,omitempty"`

	// gen is the instance's generation — its AuditFrom — as it stood
	// when this view was resolved. Unexported on purpose: it is an
	// internal sequence number, not part of the JSON a client reads,
	// and a fragment may render only what its JSON twin carries
	// (ADR-0003). A caller that resolves an instance and then writes
	// against it passes this to the write, so the write refuses if the
	// name has since become a different lab.
	gen int64
}

// Generation is the generation this view was resolved at.
func (v *InstanceView) Generation() int64 { return v.gen }

// LadderView is the condensed bar: seven cells, one per stage (UX §5).
type LadderView struct {
	Stage      string `json:"stage"`
	Condensed  string `json:"condensed"`
	Rank       int    `json:"rank"`
	InProgress bool   `json:"in_progress"`
	Label      string `json:"label"`
	// Regressed is UX §5's fall from ready: true when this instance has
	// stood at ready, stands below it now, and no job is running.
	// Omitted when false, so an instance that has never fallen renders
	// exactly the bytes it did before this field existed.
	Regressed bool `json:"regressed,omitempty"`
}

// ServiceView is one service line of the ladder.
type ServiceView struct {
	Name    string      `json:"name"`
	Stage   string      `json:"stage"`
	Word    string      `json:"word"`
	Context string      `json:"context"`
	Took    string      `json:"took,omitempty"`
	Embed   string      `json:"embed,omitempty"`
	URL     string      `json:"url,omitempty"`
	Ports   map[int]int `json:"ports,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// Tally is the class-split checkpoint count (never summed, spec 0001 §1).
type Tally struct {
	Baseline  Count          `json:"baseline"`
	Objective ObjectiveCount `json:"objective"`
}

// Count is passed/total.
type Count struct {
	Passed int `json:"passed"`
	Total  int `json:"total"`
}

// ObjectiveCount adds the failed count objectives carry.
type ObjectiveCount struct {
	Passed int `json:"passed"`
	Failed int `json:"failed"`
	Total  int `json:"total"`
}

// Views lists every instance (API §7 GET /instances).
func (e *Engine) Views() ([]InstanceView, error) {
	instances, err := e.opts.Store.ListInstances()
	if err != nil {
		return nil, err
	}
	out := make([]InstanceView, 0, len(instances))
	for _, inst := range instances {
		v, err := e.view(inst)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, nil
}

// View renders one instance.
// Generation is the instance's generation and nothing else: the audit
// high-water mark it was created at. It is one store read, where View
// builds the whole ladder — an authorization check runs on every request
// an attendee makes and has no use for the rest.
func (e *Engine) Generation(name string) (int64, error) {
	inst, err := e.opts.Store.GetInstance(name)
	if errors.Is(err, state.ErrNotFound) {
		return 0, e.notFound(name)
	}
	if err != nil {
		return 0, storeErr("look up instance "+name, err)
	}
	return inst.AuditFrom, nil
}

func (e *Engine) View(name string, by Actor) (*InstanceView, error) {
	inst, err := e.opts.Store.GetInstance(name)
	if errors.Is(err, state.ErrNotFound) {
		return nil, e.notFound(name)
	}
	if err != nil {
		return nil, storeErr("look up instance "+name, err)
	}
	// Compared against the instance this call resolved, like every other
	// read an attendee can reach.
	if by.Gen != nil && inst.AuditFrom != *by.Gen {
		return nil, e.notFound(name)
	}
	v, err := e.view(*inst)
	if err != nil {
		return nil, err
	}
	// And confirmed after, like every other read —
	// which this one was not, because it resolves the instance itself
	// rather than through instanceViewFor, so the deferred confirmation
	// added there never reached it. `view` goes on to read services,
	// jobs and checkpoint results by name.
	if by.Gen != nil {
		after, aerr := e.lookup(name)
		if aerr != nil {
			return nil, aerr
		}
		if after == nil || after.AuditFrom != *by.Gen {
			return nil, e.notFound(name)
		}
	}
	return v, nil
}

func (e *Engine) view(inst state.Instance) (*InstanceView, error) {
	services, err := e.opts.Store.ListServices(inst.Name)
	if err != nil {
		return nil, err
	}
	jobs, err := e.opts.Store.ListJobs(inst.Name)
	if err != nil {
		// Status never renders a settled lab over a job history it could
		// not read (API §7.2: the last job and its error are part of it).
		return nil, storeErr("list jobs of "+inst.Name, err)
	}
	var latest *state.Job
	if len(jobs) > 0 {
		j := jobs[0]
		if final, ok := e.knownOutcome(j.ID); ok {
			j = final
		}
		latest = &j
	}
	active := latest != nil && latest.Active()
	template := inst.Template
	if inst.Version != "" {
		template += "@" + inst.Version
	}
	v := &InstanceView{
		Name: inst.Name, Template: template, Profile: inst.Profile, Mode: string(inst.Mode), Created: inst.Created,
		Ladder: ladderView(inst.Stage, inst.Reached, active, latest),
		Job:    latest,
		gen:    inst.AuditFrom,
	}
	if latest != nil && latest.State == state.JobFailed && latest.Error != nil {
		pe := *latest.Error
		v.Error = &pe
	}
	// The class-split tally (spec 0001 §1: never summed) from the latest
	// results; a row exists for every declared checkpoint from the moment
	// a create starts, so totals are known before anything is evaluated.
	results, err := e.opts.Store.ListCheckpointResults(inst.Name)
	if err != nil {
		return nil, storeErr("list checkpoint results of "+inst.Name, err)
	}
	// The rows as they stand for the current definitions (currentResults):
	// a checkpoint edited since its last run counts as pending until it is
	// judged again. An instance whose source cannot be planned right now —
	// an authoring directory mid-edit — keeps the raw tally rather than
	// losing its status.
	if lv, err := e.loadLab(&inst); err == nil {
		results = lv.currentResults(results)
		// Ready means the current baselines pass (roadmap §1 invariant 3):
		// a gate baseline without a current pass — judged last under a
		// definition since changed, added since, or found red by a run —
		// holds the rendered ladder at seeded, where a verify that found it
		// red would put it (API §7.2), until it is judged again. The
		// persisted stage is not touched: the next verify or reconcile
		// records what it finds.
		if inst.Stage.Rank() >= state.StageVerified.Rank() && !lv.gatesPass(results) {
			v.Ladder = ladderView(state.StageSeeded, inst.Reached, active, latest)
		}
	}
	v.Checkpoints = tally(results)
	if retiredTemplate(&inst) {
		// The record as it stands, under a word that says the engine no
		// longer stands behind it: the rungs are what an earlier build
		// verified, and nothing here re-verifies them. A running destroy
		// keeps its own word.
		v.Unsupported = unsupportedReason
		if !(active && latest.Kind == "destroy") {
			v.Ladder.Label = "unsupported · " + unsupportedReason
		}
	}
	domain, port := e.opts.Address()
	if domain != "" {
		v.ConsoleURL = hostURL(inst.Name+"."+domain, port)
	}
	for _, s := range services {
		sv := serviceView(s, active, time.Now())
		if domain != "" && s.UIPort > 0 && s.Embed != "api-only" {
			sv.URL = hostURL(s.Name+"-"+inst.Name+"."+domain, port)
		}
		v.Services = append(v.Services, sv)
	}
	if v.Services == nil {
		v.Services = []ServiceView{}
	}
	return v, nil
}

// hostURL renders https://host[:port], omitting the default port.
func hostURL(host string, port int) string {
	if port == 443 || port == 0 {
		return "https://" + host
	}
	return fmt.Sprintf("https://%s:%d", host, port)
}

// inProgressLabel names what the engine is doing toward the next rung.
var inProgressLabel = map[state.Stage]string{
	state.StageNone:        "starting",
	state.StageAlive:       "initializing",
	state.StageHealthy:     "initializing",
	state.StageInitialized: "connecting",
	state.StageConnected:   "seeding",
	state.StageSeeded:      "verifying",
	state.StageVerified:    "finishing",
}

// ladderView builds the seven-cell bar: reached rungs ●, the rung in
// progress ◐, the rest ○ (UX §5). The word after the bar is the stage
// itself when idle, the activity when a job is running, "failed" when
// the last job failed.
//
// reached is the instance's high-water mark, which decides UX §5's
// regression — a fall *from* ready. Three clauses, each load-bearing:
// the mark says the lab was ever ready, so a lab still climbing for the
// first time is not an alarm; `stage` is what is *rendered* rather than
// what is persisted, so both falls are caught — the verify that demotes
// to seeded, and the hold at seeded when a gate baseline no longer
// passes while the stored stage still reads ready; and a running job
// suppresses it, because a reset dips below ready by design and UX §5's
// Presenter rule allows no alarm an audience could misread.
func ladderView(stage, reached state.Stage, active bool, latest *state.Job) LadderView {
	rank := stage.Rank()
	var b strings.Builder
	for i := 0; i < len(state.Ladder); i++ {
		switch {
		case i < rank:
			b.WriteString("●")
		case i == rank && active:
			b.WriteString("◐")
		default:
			b.WriteString("○")
		}
	}
	label := string(stage)
	if stage == state.StageNone {
		label = "created"
	}
	if active {
		if l, ok := inProgressLabel[stage]; ok {
			label = l
		}
		if latest != nil && latest.Kind == "destroy" {
			label = "destroying"
		}
	} else if latest != nil && latest.State == state.JobFailed {
		label = "failed"
	}
	regressed := reached.Rank() >= state.StageReady.Rank() && rank < state.StageReady.Rank() && !active
	return LadderView{Stage: string(stage), Condensed: b.String(), Rank: rank, InProgress: active, Label: label, Regressed: regressed}
}

// serviceView renders one service line: word + context clause per UX §5
// (what it's waiting on, or how long it took).
func serviceView(s state.Service, active bool, now time.Time) ServiceView {
	v := ServiceView{Name: s.Name, Stage: string(s.Stage), Ports: s.Ports, Error: s.Error, Embed: s.Embed}
	switch {
	case s.Error != "":
		v.Word = "failed"
		v.Context = s.Error
	case s.Stage == state.StageNone:
		if active {
			v.Word, v.Context = "creating", "waiting for the runtime"
		} else {
			v.Word, v.Context = "pending", "not started"
		}
	case s.Stage == state.StageAlive && active:
		v.Word = "initializing"
		if s.StartedAt != nil {
			elapsed := now.Sub(*s.StartedAt).Round(time.Second)
			if s.Typical != "" {
				v.Context = fmt.Sprintf("typically %s · elapsed %s", s.Typical, clock(elapsed))
			} else {
				v.Context = "elapsed " + clock(elapsed)
			}
		}
	case s.Stage == state.StageAlive:
		// Terminal alive: the job ended here — no readiness was declared,
		// so the ladder honestly stops (nothing is still underway).
		v.Word = "alive"
		if s.Typical == "" && s.Budget == "" {
			v.Context = "no readiness declared"
		}
	default:
		v.Word = string(s.Stage)
		if s.StartedAt != nil && s.HealthyAt != nil {
			v.Took = s.HealthyAt.Sub(*s.StartedAt).Round(time.Second).String()
			v.Context = "healthy in " + v.Took
		}
	}
	return v
}

// clock renders m:ss.
func clock(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	return fmt.Sprintf("%d:%02d", int(d.Minutes()), int(d.Seconds())%60)
}
