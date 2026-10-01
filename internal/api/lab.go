// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/console"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The lab surface of an instance (API §7–§10, plan S6): seeds, verify,
// reset, checkpoints, playbooks and progress, secrets, evidence. Every
// route is instance-scoped and enforces the resource half of the
// attendee grant (§2.4) through boundTo; the scope column of §11 is the
// minimum token scope. Reads that the fixed grant lists carry the
// instance scope, exactly as GET /instances/{name} does.
func (s *Server) labRoutes() {
	// The live feed (§4, plan S7). Instance scope: §2.4's fixed grant
	// lists events among an attendee's reads, and s.scoped enforces the
	// resource half, exactly as GET /instances/{name} does.
	s.handle("GET /instances/{name}/events", auth.ScopeInstance, s.events)
	s.handle("GET /instances/{name}/reset-plan", auth.ScopeRead, s.resetPlan)
	s.handle("POST /instances/{name}/reset", auth.ScopeOperate, s.reset)
	// §2.4's fixed grant lists step seeds, attest and the learner's
	// position among an attendee's own writes, and §11's legend has
	// always said a session qualifies for a scope. `granted` admits an
	// instance-bound session on these three without lowering the token
	// minimum; `scoped` still answers not-found for any instance but the
	// session's own.
	s.granted("POST /instances/{name}/seeds/{seed}", auth.ScopeOperate, s.runSeed)
	s.handle("POST /instances/{name}/verify", auth.ScopeInstance, s.verify)
	s.handle("GET /instances/{name}/checkpoints", auth.ScopeInstance, s.listCheckpoints)
	s.handle("POST /instances/{name}/checkpoints/{id}/run", auth.ScopeInstance, s.runCheckpoint)
	s.granted("POST /instances/{name}/checkpoints/{id}/attest", auth.ScopeOperate, s.attest)
	s.handle("GET /instances/{name}/playbooks", auth.ScopeInstance, s.listPlaybooks)
	s.handle("GET /instances/{name}/playbooks/{id}", auth.ScopeInstance, s.getPlaybook)
	s.handle("GET /instances/{name}/playbooks/{id}/progress", auth.ScopeInstance, s.getProgress)
	s.granted("PUT /instances/{name}/playbooks/{id}/progress", auth.ScopeOperate, s.putProgress)
	s.handle("GET /instances/{name}/secrets", auth.ScopeInstance, s.listSecrets)
	s.handle("POST /instances/{name}/secrets/{secret}/reveal", auth.ScopeInstance, s.reveal)
	s.handle("GET /instances/{name}/evidence", auth.ScopeInstance, s.listEvidence)
	s.handle("GET /instances/{name}/evidence/report.html", auth.ScopeInstance, s.report)
	s.handle("GET /instances/{name}/evidence/report.junit.xml", auth.ScopeInstance, s.junit)
	s.handle("GET /instances/{name}/evidence/{id}", auth.ScopeInstance, s.getEvidence)
}

// grantsSeed enforces the word "step" in §2.4's "step seeds".
//
// The seed endpoint is one endpoint for two different acts. A seed a
// playbook step invokes is the learner's own — pressing the step's
// button is what runs it. A seed no step names is a *standing* seed:
// create's injection, the instance's starting data (lab.SeedRoles). The
// grant names the first and not the second, so admitting an
// instance-bound session to the endpoint admitted it to both, and an
// attendee could re-run a bootstrap injection under the lab from which
// their own progress is judged.
//
// Only a bound session is asked: an operator, and a token carrying
// `operate`, may run any seed as before.
func (s *Server) grantsSeed(w http.ResponseWriter, r *http.Request, instance, seed string) bool {
	if boundTo(r) == "" {
		return true
	}
	steps, err := s.o.Engine.StepSeeds(instance, actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return false
	}
	for _, name := range steps {
		if name == seed {
			return true
		}
	}
	// The cause says what is true whether the seed is standing or absent:
	// it is not one a step of this lab invokes. A seed's name is not a
	// secret — it is in the template the attendee is working through.
	e := pdr.New(pdr.CodeScopeInsufficient, "instance access covers step seeds only")
	e.Cause = "no playbook step of this lab invokes the seed " + seed
	e.Next = "run the step's own action from the playbook · an operator can run any seed"
	e.Details = []pdr.Detail{{Path: "required_scope", Hint: auth.ScopeOperate}}
	s.writeError(w, r, e)
	return false
}

// scoped resolves the instance a route names, refusing a bound session
// any other instance with the not-found envelope (API §2.4: indistinct
// from an instance that does not exist).
func (s *Server) scoped(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("name")
	if bound := boundTo(r); bound != "" && name != bound {
		s.writeError(w, r, notFound("instance", name))
		return "", false
	}
	if !s.current(w, r, name) {
		return "", false
	}
	return name, true
}

// current checks a bound session against the lab as it stands *now*. A
// name can come back: an attendee session outlives the destroy that
// deleted its row, because the principal was resolved at the start of
// the request and nothing re-reads it, so without this the bearer acts
// on whatever the name means by the time the handler runs.
//
// A handler that reads a body must call this again after reading it.
// `scoped` runs first, and a body can be made to arrive as slowly as its
// sender likes — the destroy and the re-create fit in that window
// comfortably. The three that do are `verify`, `attest` and
// `putProgress`; each has a case in TestABodyInFlightCannotOutliveTheLab.
func (s *Server) current(w http.ResponseWriter, r *http.Request, name string) bool {
	p := PrincipalFrom(r.Context())
	if p == nil || p.Session == nil || p.Session.Instance == "" {
		return true // the operator is not bound to a generation
	}
	gen, err := s.o.Engine.Generation(name)
	if err != nil {
		s.writeError(w, r, err)
		return false
	}
	if gen != p.Session.Gen {
		// The same answer an instance outside the grant gets: a lab that
		// is not the one this session was opened against is, to this
		// bearer, a lab that is not there.
		s.writeError(w, r, notFound("instance", name))
		return false
	}
	return true
}

// readObject decodes one JSON object of at most limit bytes; an empty
// body is allowed when optional is set. It refuses trailing data.
func readObject(w http.ResponseWriter, r *http.Request, limit int64, optional bool, out any) error {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		if optional {
			return nil
		}
		return errors.New("empty body")
	}
	// The body must be a JSON *object*. `null`, a scalar or an array
	// decodes into a struct pointer without error and leaves it at its
	// zero value, so a handler would act on a body it never received: a
	// `PUT …/progress` of `null` would persist an empty record over the
	// learner's position, and a `POST …/verify` or `…/attest` of `null`
	// would read as the empty object it is not. Presence is not content
	// — the rule D169 and D192 already keep for a seed's params and an
	// http checkpoint's body.
	if trimmed[0] != '{' {
		return errors.New("the body must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// A member the destination shape does not have is refused, not
	// dropped. Without this the null hardening is bypassable by a typo:
	// `{"current_stap":"…"}` decodes cleanly, leaves CurrentStep and
	// Steps at their zero values, and the write replaces the learner's
	// position with an empty record — the same loss D196 and D197 closed,
	// reached by a third door. A misspelled `playbook` or `note` likewise
	// invoked the default silently.
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if terr := dec.Decode(new(json.RawMessage)); terr != io.EOF {
		return errors.New("trailing data after the object")
	}
	// A member that is present and null is refused for the same reason the
	// whole body is (D196): `encoding/json` leaves the destination field at
	// its zero value, so `{"current_step":null,"steps":null}` is a
	// well-formed object that still erases the learner's position, and
	// `{"playbook":null}` reads as "every playbook". The scan is top-level
	// only, which is where the loss happens — a null deeper in (a step of
	// `steps`) becomes a zero-valued entry the engine's own validation
	// already refuses by name. The body is one object by here, so this
	// reads it again safely.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return err
	}
	names := make([]string, 0, len(members))
	for k := range members {
		names = append(names, k)
	}
	sort.Strings(names) // a stable message whatever the map's order
	for _, k := range names {
		if bytes.Equal(bytes.TrimSpace(members[k]), []byte("null")) {
			return fmt.Errorf("member %q is null: omit it, or give it a value", k)
		}
	}
	return nil
}

func (s *Server) resetPlan(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	plan, err := s.o.Engine.ResetPlanFor(name)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.respond(w, r, http.StatusOK, map[string]any{"reset_plan": plan}, console.FragmentResetPlan,
		console.ResetData{Instance: name, Plan: plan, CSRF: csrfOf(r)})
}

func (s *Server) reset(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	job, err := s.o.Engine.ResetAs(r.Context(), name, actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *Server) runSeed(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	if !s.grantsSeed(w, r, name, r.PathValue("seed")) {
		return
	}
	job, err := s.o.Engine.SeedAs(r.Context(), name, r.PathValue("seed"), actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

// verify is POST /instances/{name}/verify: every checkpoint, or one
// playbook's objectives beside every baseline (`?playbook=` or a body
// `{"playbook":"…"}`). 202 + job.
func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	playbook := r.URL.Query().Get("playbook")
	var body struct {
		Playbook string `json:"playbook"`
	}
	if err := readObject(w, r, 64<<10, true, &body); err != nil {
		pe := pdr.New(pdr.CodeCreateRequest, "malformed verify body: %v", err)
		pe.Next = `POST {} or {"playbook":"<id>"} (API §7)`
		s.writeError(w, r, pe)
		return
	}
	if body.Playbook != "" {
		playbook = body.Playbook
	}
	if !s.current(w, r, name) {
		return
	}
	job, err := s.o.Engine.VerifyAs(r.Context(), name, playbook, actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *Server) listCheckpoints(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	cps, err := s.o.Engine.Checkpoints(name, actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if cps == nil {
		cps = []engine.CheckpointView{}
	}
	// The HTML twin is the Evidence scoreboard (UX §6). The filter chip
	// is a view of the same rows, never a second query: the JSON twin
	// carries every checkpoint, and the fragment shows the subset asked
	// for, so the two never disagree about what exists.
	s.respond(w, r, http.StatusOK, map[string]any{"checkpoints": cps}, console.FragmentEvidence,
		console.EvidenceData{Instance: name, Checkpoints: cps, Filter: r.URL.Query().Get("filter")})
}

// runCheckpoint is synchronous (API §8): 200 with the result whether it
// passed or failed; an adapter that could not judge is status error,
// still 200 — the run happened and is in evidence.
func (s *Server) runCheckpoint(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	res, err := s.o.Engine.RunCheckpoint(r.Context(), name, r.PathValue("id"), actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.respond(w, r, http.StatusOK, map[string]any{"result": res}, console.FragmentResult,
		s.resultLine(name, r.URL.Query().Get("playbook"), r.URL.Query().Get("step"), res, r.URL.Query().Get("mode"), actorOf(r)))
}

func (s *Server) attest(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	var body struct {
		Note string `json:"note"`
	}
	if err := readObject(w, r, 64<<10, true, &body); err != nil {
		pe := pdr.New(pdr.CodeAttestRefused, "malformed attest body: %v", err)
		pe.Next = `POST {} or {"note":"…"} (API §8)`
		s.writeError(w, r, pe)
		return
	}
	if !s.current(w, r, name) {
		return
	}
	res, err := s.o.Engine.Attest(r.Context(), name, r.PathValue("id"), body.Note, actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.respond(w, r, http.StatusOK, map[string]any{"result": res}, console.FragmentResult,
		s.resultLine(name, r.URL.Query().Get("playbook"), r.URL.Query().Get("step"), res, r.URL.Query().Get("mode"), actorOf(r)))
}

func (s *Server) listPlaybooks(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	list, err := s.o.Engine.Playbooks(name, actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if list == nil {
		list = []engine.PlaybookSummary{}
	}
	// The instance's mode travels with the list because the chooser
	// needs it: Author preview is a manner the *instance* is in, not one
	// a playbook declares, and a fragment may render only what its JSON
	// twin contains (ADR-0003). Without it the chooser could offer the
	// link on the assembled page and lose it the moment htmx re-fetched
	// this list.
	mode := ""
	if inst, err := s.o.Engine.Instance(name, actorOf(r)); err == nil && inst != nil {
		mode = string(inst.Mode)
	}
	s.respond(w, r, http.StatusOK, map[string]any{"playbooks": list, "mode": mode}, console.FragmentPlaybooks,
		console.PlaybooksData{Instance: name, Mode: mode, Playbooks: list})
}

func (s *Server) getPlaybook(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	pb, err := s.o.Engine.Playbook(name, r.PathValue("id"), actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	// The rail's data is gathered only for the HTML representation. The
	// JSON twin is the playbook alone, and a twin the console needs must
	// not fail a request that does not carry it.
	var rail console.RailData
	if wantsHTML(r) {
		rail, err = s.railData(r, name, pb)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
	}
	s.respond(w, r, http.StatusOK, map[string]any{"playbook": pb}, console.FragmentRail, rail)
}

// getProgress and putProgress carry the bare progress object (API §8:
// `{"current_step":…,"steps":{…}}`), the shape the console writes back.
func (s *Server) getProgress(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	p, err := s.o.Engine.Progress(name, r.PathValue("id"), actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) putProgress(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	var p state.Progress
	if err := readObject(w, r, 256<<10, false, &p); err != nil {
		pe := pdr.New(pdr.CodeProgressRefused, "malformed progress body: %v", err)
		pe.Next = `PUT {"current_step":"<id>","steps":{"<id>":{"status":"pass|fail|attested|skipped"}}} (API §8)`
		s.writeError(w, r, pe)
		return
	}
	if !s.current(w, r, name) {
		return
	}
	saved, err := s.o.Engine.PutProgress(name, r.PathValue("id"), p, actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	list, err := s.o.Engine.Secrets(name, actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if list == nil {
		list = []engine.SecretView{}
	}
	s.respond(w, r, http.StatusOK, map[string]any{"secrets": list}, console.FragmentSecrets,
		console.SecretsData{Instance: name, Secrets: list, CSRF: csrfOf(r)})
}

// reveal is the one audited hole in the secret wall (API §9): a session
// (the operator's, or an instance-bound one for its own instance), the
// socket, or a token carrying admin. Any other token is refused with the
// scope it lacks, before anything is read.
func (s *Server) reveal(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	p := PrincipalFrom(r.Context())
	if p.Mechanism == auth.MechanismToken && !p.Allows(auth.ScopeAdmin) {
		e := pdr.New(pdr.CodeScopeInsufficient, "a token reveals secrets only with the %s scope", auth.ScopeAdmin)
		e.Cause = "the token credential carries " + p.Scope + "; reveals are for signed-in people and admin tokens (API §9)"
		e.Next = "sign in at the console, or podaro auth token create --name <name> --scope admin"
		e.Details = []pdr.Detail{{Path: "required_scope", Hint: auth.ScopeAdmin}}
		s.writeError(w, r, e)
		return
	}
	value, err := s.o.Engine.Reveal(r.Context(), name, r.PathValue("secret"), actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	// The revealed value reaches the DOM only here, in the answer to the
	// click that asked for it (UX §6, threat model B8).
	s.respond(w, r, http.StatusOK, map[string]any{"value": value, "remask_after": engine.RemaskAfter.String()},
		console.FragmentReveal, console.RevealData{Instance: name, Name: r.PathValue("secret"), Value: value,
			RemaskAfter: engine.RemaskAfter.String(), Seconds: int(engine.RemaskAfter.Seconds()), CSRF: csrfOf(r)})
}

func (s *Server) listEvidence(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f := engine.EvidenceFilter{Type: q.Get("type"), Job: q.Get("job")}
	if since := q.Get("since"); since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			pe := pdr.New(pdr.CodeCreateRequest, "malformed since: %v", err)
			pe.Next = "since is an RFC 3339 timestamp (API §10)"
			s.writeError(w, r, pe)
			return
		}
		f.Since = t
	}
	entries, err := s.o.Engine.Evidence(name, f, actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if entries == nil {
		entries = []evidence.Entry{}
	}
	// The HTML twin is the Evidence tab's journal, fetched by the
	// scoreboard beneath its table. It is this endpoint's fragment and
	// not the scoreboard's because the entries are this endpoint's
	// answer: a fragment may render only what its JSON twin contains
	// (ADR-0003), and …/checkpoints has no journal in it.
	s.respond(w, r, http.StatusOK, map[string]any{"evidence": entries}, console.FragmentJournal,
		console.JournalData{Instance: name, Entries: entries})
}

func (s *Server) getEvidence(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	entry, err := s.o.Engine.EvidenceEntry(name, r.PathValue("id"), actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entry": entry})
}

// report serves the §10 human report. It is a whole document, not a
// console fragment: the point of it is that it survives being mailed to
// someone who has never heard of this engine, so it is served as one
// file with its own stylesheet and never negotiated into a fragment.
func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	raw, err := s.o.Engine.Report(name, actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// A report is a snapshot of a moment; a cached one is a lie about
	// the lab as it stands.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `inline; filename="podaro-`+name+`-evidence.html"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) junit(w http.ResponseWriter, r *http.Request) {
	name, ok := s.scoped(w, r)
	if !ok {
		return
	}
	raw, err := s.o.Engine.JUnit(name, actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// The console's side of the lab surface (plan S7). Each helper assembles
// the fragment's data from the same twins the JSON side returns; none
// reads anything the JSON caller could not fetch for itself.

// railData gathers the three twins the rail draws from — the playbook,
// its recorded progress, and the checkpoint list — plus the render
// manner the caller asked for.
//
// Progress is the one the rail may not do without. The page changes one
// field of the record it is handed and `PUT …/progress` replaces the
// stored row whole, so a rail rendered without it hands the page a
// *writable empty record*: the next navigation writes `steps: {}` back
// and erases every status the learner had earned. A store fault is not
// absence (D27), so it is returned — the console shows the error rather
// than a rail that destroys work on the next click.
//
// The checkpoint list is different in kind and is still left empty on a
// fault: nothing writes it back, so a read that failed costs a learner a
// re-verify, never their record. What it renders then is "not known",
// which the rail shows as unverified — the closest thing it has, and not
// the same thing as the truth.
func (s *Server) railData(r *http.Request, name string, pb *engine.PlaybookView) (console.RailData, error) {
	instMode := ""
	if inst, err := s.o.Engine.Instance(name, actorOf(r)); err == nil && inst != nil {
		instMode = string(inst.Mode)
	}
	d := console.RailData{Instance: name, Mode: railMode(r.URL.Query().Get("mode"), instMode, pb), CSRF: csrfOf(r),
		Open: r.URL.Query().Get("step"), Results: map[string]engine.CheckpointView{}}
	if pb != nil {
		d.Playbook = *pb
	}
	p, err := s.o.Engine.Progress(name, r.PathValue("id"), actorOf(r))
	if err != nil {
		return d, err
	}
	d.Progress = p
	if cps, err := s.o.Engine.Checkpoints(name, actorOf(r)); err == nil {
		for _, c := range cps {
			d.Results[c.ID] = c
		}
	}
	return d, nil
}

// railMode reads the manner from the query. An unknown manner is Guided:
// Guided is the safe default — it gates nothing and hides the presenter's
// notes, so a mistyped mode can never leak notes to a learner or drop the
// Verify button a learner needs (UX §8).
//
// Author preview is the authoring instance's own surface, and this never
// asked which kind of instance it was on. That was harmless while the
// manner rendered like Guided; once it showed the notes UX §8 promises,
// `?mode=author` on a delivery instance became a way for anyone with the
// lab open to read what its author wrote for someone else — the thing
// Guided's manners exist to prevent. The
// instance mode is engine-enforced everywhere else; it is enforced here
// too, by the same fallback an unknown manner gets, because a manner
// this instance does not have must never cost a learner their Verify
// button.
//
// Presenter is a manner the *playbook* declares, not one the instance is
// in — and that used to be the whole of what this said, while the branch
// below returned it to anyone who typed the query. Round 5 stopped the
// chooser offering a link to an undeclared manner; a hidden link is not
// a rule, so `?mode=presenter` still showed the presenter notes,
// suppressed the ordinary checkpoint controls and started the Presenter
// rechecks for a playbook whose contract forbids it.
// The rule is the chooser's own predicate, consulted
// here, with the same fallback: an undeclared manner renders as Guided.
func railMode(m, instanceMode string, pb *engine.PlaybookView) string {
	switch m {
	case console.ModePresenter:
		if pb != nil && !console.Declares(pb.PlaybookSummary, console.ModePresenter) {
			return console.ModeGuided
		}
		return m
	case console.ModeAuthor:
		if instanceMode == "authoring" {
			return m
		}
		return console.ModeGuided
	default:
		return console.ModeGuided
	}
}

// resultLine is the Verify state machine's answer for one step. The step
// id comes from the caller because a checkpoint may serve several steps
// (spec 0001 §6 steps[]); with none named the line still renders, keyed
// by the checkpoint's own id.
// resultLine builds the fragment's data. A Presenter re-check asks with
// its mode, and gets the confidence light with the verdict — the light
// is in the step's title, outside what this swaps.
func (s *Server) resultLine(name, playbook, step string, res *state.CheckpointResult, mode string, by engine.Actor) console.ResultLine {
	if step == "" && res != nil {
		step = res.ID
	}
	var cp *engine.CheckpointView
	if cps, err := s.o.Engine.Checkpoints(name, by); err == nil && res != nil {
		for _, c := range cps {
			if c.ID == res.ID {
				cc := c
				cp = &cc
				break
			}
		}
	}
	if mode == "presenter" {
		return console.NewPresenterResultLine(name, playbook, step, res, cp)
	}
	return console.NewResultLine(name, playbook, step, res, cp)
}

// csrfOf is the signed-in caller's CSRF token, for the fragments that
// carry a write control. A caller without a session gets none, and the
// control it renders is refused by the CSRF check — never silently
// accepted (API §2.2).
func csrfOf(r *http.Request) string {
	if p := PrincipalFrom(r.Context()); p != nil && p.Session != nil {
		return p.Session.CSRF
	}
	return ""
}
