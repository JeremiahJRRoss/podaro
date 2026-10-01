// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Evidence (API §10): the append-only journal, one entry, JUnit.
//
// Each resolves the instance's record, not its lab (recordViewFor): the
// evidence and the reports of an instance whose template the owner
// retired still read, which is what keeps its history the operator's to
// save before a destroy (the reconciliation plan's R3).

// EvidenceFilter narrows a listing.
type EvidenceFilter struct {
	Type  string
	Since time.Time
	Job   string
}

// Evidence lists an instance's journal: the file entries plus the
// instance's audit records (logins, reveals, resets, destroys) rendered
// as audit entries, in time order.
func (e *Engine) Evidence(name string, f EvidenceFilter, by Actor) (ret []evidence.Entry, err error) {
	lv, err := e.recordViewFor(name, by.Gen)
	if err != nil {
		return nil, err
	}
	defer func() { err = e.confirmed(lv, err) }()
	entries, err := e.journal(name).List(evidence.Filter{Type: evidence.Type(f.Type), Since: f.Since, Job: f.Job})
	if err != nil {
		return nil, storeErr("read the evidence of "+name, err)
	}
	if f.Type == "" || f.Type == string(evidence.TypeAudit) {
		audit, err := e.opts.Store.ListAudit(name)
		if err != nil {
			return nil, storeErr("read the audit stream of "+name, err)
		}
		seen := map[string]bool{}
		for _, en := range entries {
			if en.Type == evidence.TypeAudit && en.Audit != nil {
				seen[auditKey(*en.Audit)] = true
			}
		}
		rows := make([]evidence.Entry, 0, len(audit))
		for _, a := range audit {
			if f.Job != "" || (!f.Since.IsZero() && a.At.Before(f.Since)) || seen[auditKey(a)] {
				continue
			}
			// This instance, not the one that had the name before it. A
			// destroy takes the lab's directory, its journal and its
			// rows, but audit rows are the security record and stay —
			// so a name used twice merged the first lab's joins and
			// reveals into the second's evidence. That reaches an
			// attendee (this endpoint is theirs) and the report they may
			// be sent, naming people and secrets from a lab they were
			// never in. The whole history is still the operator's, on
			// the socket-only system audit stream.
			//
			// The line is the sequence, not the clock: `Seq` is
			// monotonic in both stores, and a host clock that stepped
			// back would otherwise put a live instance's own rows before
			// its creation and hide them.
			if a.Seq <= lv.inst.AuditFrom {
				continue
			}
			rec := a
			rows = append(rows, evidence.Entry{ID: "au_" + strconv.FormatInt(a.Seq, 10), At: a.At, Type: evidence.TypeAudit, Instance: name, Authoring: lv.inst.Mode == state.ModeAuthoring, Audit: &rec})
		}
		entries = mergeEvidence(entries, rows)
	}
	return entries, nil
}

func auditKey(a state.Audit) string {
	return a.At.UTC().Format(time.RFC3339Nano) + "|" + a.Action + "|" + a.Actor + "|" + a.Detail
}

// EvidenceEntry returns one entry.
func (e *Engine) EvidenceEntry(name, id string, by Actor) (ret *evidence.Entry, err error) {
	lv, err := e.recordViewFor(name, by.Gen)
	if err != nil {
		return nil, err
	}
	defer func() { err = e.confirmed(lv, err) }()
	if len(id) > 3 && id[:3] == "au_" {
		seq, err := strconv.ParseInt(id[3:], 10, 64)
		if err == nil {
			audit, err := e.opts.Store.ListAudit(name)
			if err != nil {
				return nil, storeErr("read the audit stream of "+name, err)
			}
			for _, a := range audit {
				// The same generation line the listing draws. Audit ids
				// are `au_<seq>` and sequences are consecutive integers,
				// so a reader who can fetch one entry can count
				// downwards — and this endpoint is the attendee's. A row
				// from the lab before this one is not found, exactly as
				// it is absent from the list.
				if a.Seq <= lv.inst.AuditFrom {
					continue
				}
				if a.Seq == seq {
					rec := a
					return &evidence.Entry{ID: id, At: a.At, Type: evidence.TypeAudit, Instance: name, Authoring: lv.inst.Mode == state.ModeAuthoring, Audit: &rec}, nil
				}
			}
		}
		return nil, notFoundKind(pdr.CodeEvidenceNotFound, "evidence entry", id, "GET /instances/"+name+"/evidence")
	}
	entry, err := e.journal(name).Get(id)
	if errors.Is(err, evidence.ErrNotFound) {
		return nil, notFoundKind(pdr.CodeEvidenceNotFound, "evidence entry", id, "GET /instances/"+name+"/evidence")
	}
	if err != nil {
		return nil, storeErr("read evidence "+id, err)
	}
	return entry, nil
}

// JUnit renders the latest results as JUnit XML.
func (e *Engine) JUnit(name string, by Actor) (ret []byte, err error) {
	lv, err := e.recordViewFor(name, by.Gen)
	if err != nil {
		return nil, err
	}
	defer func() { err = e.confirmed(lv, err) }()
	results, err := e.opts.Store.ListCheckpointResults(name)
	if err != nil {
		return nil, storeErr("list checkpoint results of "+name, err)
	}
	template := lv.inst.Template
	if lv.inst.Version != "" {
		template += "@" + lv.inst.Version
	}
	// The rows as they stand for the current definitions: an edited
	// checkpoint is "not evaluated" until judged again (currentResults).
	return evidence.JUnit(name, template, lv.currentResults(results)), nil
}

// mergeEvidence interleaves the journal's entries with the instance's
// audit rows without disturbing either sequence.
//
// Sorting the combined list by wall-clock `At` — which this did until
// round 70 — undoes the guarantee round 65 established: `Journal.List`
// returns entries in id order, which is append order and is monotonic
// whatever the host clock does, and a comparator keyed on `At` puts them
// back in clock order, reversing two appends across a clock correction.
// The API says §10's listing is append order, so the journal's own order
// is the one that must survive.
//
// Both inputs arrive already ordered — the journal by its monotonic ids,
// the audit stream by its sequence — so this is a merge, not a sort:
// each stream keeps its order by construction, and `At` decides only
// which stream's head goes next. A clock moved backwards can therefore
// place an audit row a little early or late among the journal's entries,
// which is the best any single ordering can do for two streams that
// carry no common sequence; it can no longer reorder the journal itself.
// Ties go to the journal, so an audit row recorded in the same instant as
// the entry it describes follows it.
func mergeEvidence(journal, audit []evidence.Entry) []evidence.Entry {
	if len(audit) == 0 {
		return journal
	}
	out := make([]evidence.Entry, 0, len(journal)+len(audit))
	i, j := 0, 0
	for i < len(journal) && j < len(audit) {
		if !audit[j].At.Before(journal[i].At) {
			out = append(out, journal[i])
			i++
			continue
		}
		out = append(out, audit[j])
		j++
	}
	out = append(out, journal[i:]...)
	return append(out, audit[j:]...)
}

// Report renders the human evidence report (API §10, plan S9): the
// artifact a presenter forwards and a trainee keeps.
//
// It is assembled from what the instance already holds — the current
// checkpoint results, the journal's seeds and milestones, and the audit
// stream's joins and reveals — so the report says what the evidence
// says and nothing more. The §10 exclusions are applied here as well as
// there: free text passes a scrubber built from this deployment's own
// domain, so a hostname reads as the service it names and a host
// address does not appear.
func (e *Engine) Report(name string, by Actor) (ret []byte, err error) {
	lv, err := e.recordViewFor(name, by.Gen)
	if err != nil {
		return nil, err
	}
	defer func() { err = e.confirmed(lv, err) }()
	results, err := e.opts.Store.ListCheckpointResults(name)
	if err != nil {
		return nil, storeErr("list checkpoint results of "+name, err)
	}
	entries, err := e.Evidence(name, EvidenceFilter{}, Socket)
	if err != nil {
		return nil, err
	}
	domain, _ := e.opts.Address()
	d := evidence.ReportData{
		Instance:  lv.inst.Name,
		Template:  lv.inst.Template,
		Version:   lv.inst.Version,
		Profile:   lv.inst.Profile,
		Mode:      string(lv.inst.Mode),
		Created:   lv.inst.Created,
		Generated: time.Now().UTC(),
		Engine:    podaro.Version(),
		Authoring: lv.inst.Mode == state.ModeAuthoring,
		// The rows as they stand for the current definitions, exactly as
		// JUnit takes them: an edited checkpoint is "not evaluated" until
		// it is judged again.
		Results: lv.currentResults(results),
		Scrub:   evidence.Scrubber(domain),
	}
	if lv.plan != nil {
		d.Title = lv.plan.Template.Title
	}
	// What ran comes from the rows the engine wrote when it made the
	// containers, never from the plan. An authoring instance tracks its
	// working directory — invariant 4's one declared exception — so the
	// plan reloaded here is whatever the author has saved since, and
	// building the table from it let an edit rewrite the record of a run:
	// a service, a module and an image digest no container was ever made
	// from, in the one artefact built to leave the building.
	// A lab that got no further than its create has no rows
	// and says so by having none.
	services, err := e.opts.Store.ListServices(name)
	if err != nil {
		return nil, storeErr("list services of "+name, err)
	}
	for _, svc := range services {
		// A row is written for every *planned* service before the job is
		// launched (`publishPlanned`), so a row on its own says the lab
		// meant to have this service — not that it ever had one.
		// Nor is the container's id enough:
		// `bringUp` writes it the moment `rt.Create` answers, before the
		// start is attempted, so a container that was made and never ran
		// carried one too. `StartedAt` is written only past the branches
		// that refuse a container which did not come up running, which
		// makes it the fact that a service *ran* (round 26).
		if svc.StartedAt == nil || svc.RanImage == "" {
			continue
		}
		// The image of the run, not the one on the row: `image` is the
		// plan's and is refreshed on every attempt, so an authoring
		// retry after an edited image put the replacement here while the
		// start time still belonged to the run before it.
		repository, digest, _ := strings.Cut(svc.RanImage, "@")
		d.Services = append(d.Services, evidence.ReportService{
			Name: svc.Name, Module: svc.RanModule, Image: repository, Digest: digest,
		})
	}
	attendees := map[string]*evidence.ReportAttendee{}
	for _, en := range entries {
		switch {
		case en.Seed != nil:
			d.Seeds = append(d.Seeds, evidence.ReportSeed{
				Name: en.Seed.Name, Generator: en.Seed.Generator, Count: en.Seed.Count,
				Duration: en.Seed.Duration, At: en.At, Seed: en.Seed.SeedValue,
				Failed: en.Seed.Error != nil, Message: seedMessage(*en.Seed),
			})
		case en.Lifecycle != nil:
			d.Milestones = append(d.Milestones, evidence.ReportMilestone{
				At: en.At, Event: en.Lifecycle.Event, Stage: en.Lifecycle.Stage,
				Code: en.Lifecycle.Code, Detail: en.Lifecycle.Detail,
			})
		case en.Audit != nil:
			switch en.Audit.Action {
			case "join":
				// The identity D4 promises the report: the name the
				// operator issued the access link under.
				a := attendees[en.Audit.Actor]
				if a == nil {
					a = &evidence.ReportAttendee{Name: en.Audit.Actor, First: en.At}
					attendees[en.Audit.Actor] = a
				}
				a.Joins++
				a.Last = en.At
			case "reveal":
				// The event, by secret name. The detail is the name; the
				// value was never recorded anywhere to print.
				d.Reveals = append(d.Reveals, evidence.ReportReveal{
					Secret: en.Audit.Detail, Actor: en.Audit.Actor, At: en.At,
				})
			case "accept-license":
				// A EULA accepted for this create (API §6.2): the id and who
				// accepted it, among the milestones.
				d.Milestones = append(d.Milestones, evidence.ReportMilestone{
					At: en.At, Event: "license accepted", Detail: en.Audit.Detail + " by " + en.Audit.Actor,
				})
			}
		}
	}
	for _, a := range attendees {
		d.Attendees = append(d.Attendees, *a)
	}
	sort.Slice(d.Attendees, func(i, j int) bool { return d.Attendees[i].Name < d.Attendees[j].Name })
	return evidence.Report(d)
}

// seedMessage is what a seed run says for itself: its own message, or
// the envelope of the failure that stopped it. The text is scrubbed by
// the report, not here.
func seedMessage(s evidence.SeedRun) string {
	if s.Error != nil {
		msg := s.Error.Code + " " + s.Error.Message
		if s.Error.Cause != "" {
			msg += " · " + s.Error.Cause
		}
		return msg
	}
	return s.Message
}
