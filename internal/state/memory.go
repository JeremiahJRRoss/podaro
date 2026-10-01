// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"sort"
	"sync"
	"time"
)

// Memory is the in-memory Store for tests and the fake-runtime harness.
type Memory struct {
	mu        sync.Mutex
	instances map[string]Instance
	services  map[string]map[string]Service
	jobs      map[string]Job
	jobOrder  []string
	events    map[string][]Event
	seq       int64
	sessions  map[string]Session
	tokens    map[string]Token
	tokenOrd  []string
	audit     []Audit
	logins    map[string]LoginState
	backfill  map[string]bool
	// unsupported is migration 16's mark (the reconciliation plan's R3).
	unsupported map[string]string
	results     map[string]map[string]CheckpointResult
	progress    map[string]map[string]Progress
	generated   map[string]map[string]bool
	// access holds instance access credentials by id, with accessOrd
	// keeping the order they were issued in (API §2.4, plan S9).
	access    map[string]Access
	accessOrd []string
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		instances:   map[string]Instance{},
		services:    map[string]map[string]Service{},
		jobs:        map[string]Job{},
		events:      map[string][]Event{},
		sessions:    map[string]Session{},
		tokens:      map[string]Token{},
		logins:      map[string]LoginState{},
		backfill:    map[string]bool{},
		unsupported: map[string]string{},
		results:     map[string]map[string]CheckpointResult{},
		progress:    map[string]map[string]Progress{},
		generated:   map[string]map[string]bool{},
		access:      map[string]Access{},
	}
}

func (m *Memory) PutCheckpointResult(r CheckpointResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.instances[r.Instance]; !ok {
		return ErrNotFound // a row never outlives, or precedes, its instance
	}
	if m.results[r.Instance] == nil {
		m.results[r.Instance] = map[string]CheckpointResult{}
	}
	m.results[r.Instance][r.ID] = r
	return nil
}

func (m *Memory) ListCheckpointResults(instance string) ([]CheckpointResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]CheckpointResult, 0, len(m.results[instance]))
	for _, r := range m.results[instance] {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) DeleteCheckpointResults(instance, class string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if class == "" {
		delete(m.results, instance)
		return nil
	}
	for id, r := range m.results[instance] {
		if r.Class == class {
			delete(m.results[instance], id)
		}
	}
	return nil
}

func (m *Memory) PutProgress(p Progress) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.instances[p.Instance]; !ok {
		return ErrNotFound
	}
	if m.progress[p.Instance] == nil {
		m.progress[p.Instance] = map[string]Progress{}
	}
	if p.Steps == nil {
		p.Steps = map[string]StepProgress{}
	}
	m.progress[p.Instance][p.Playbook] = p
	return nil
}

func (m *Memory) GetProgress(instance, playbook string) (*Progress, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.progress[instance][playbook]
	if !ok {
		return nil, ErrNotFound
	}
	steps := make(map[string]StepProgress, len(p.Steps))
	for k, v := range p.Steps {
		steps[k] = v
	}
	p.Steps = steps
	return &p, nil
}

func (m *Memory) DeleteProgress(instance string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.progress, instance)
	return nil
}

func (m *Memory) Close() error { return nil }

func (m *Memory) PutInstance(in Instance) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.instances[in.Name] = in
	return nil
}

func (m *Memory) GetInstance(name string) (*Instance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	in, ok := m.instances[name]
	if !ok {
		return nil, ErrNotFound
	}
	return &in, nil
}

func (m *Memory) ListInstances() ([]Instance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Instance, 0, len(m.instances))
	for _, in := range m.instances {
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) DeleteInstance(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.instances, name)
	delete(m.services, name)
	delete(m.backfill, name)
	delete(m.unsupported, name)
	delete(m.results, name)
	delete(m.progress, name)
	delete(m.generated, name)
	// A session bound to this instance goes with it: nothing re-checks
	// the instance when a session is resolved, so one left behind would
	// be valid against the next lab of that name.
	for id, sess := range m.sessions {
		if sess.Instance == name {
			delete(m.sessions, id)
		}
	}
	// An attendee credential names one instance and goes with it.
	kept := m.accessOrd[:0]
	for _, id := range m.accessOrd {
		if m.access[id].Instance == name {
			delete(m.access, id)
			continue
		}
		kept = append(kept, id)
	}
	m.accessOrd = append([]string(nil), kept...)
	return nil
}

func (m *Memory) GeneratedSecrets(instance string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.generated[instance]))
	for n := range m.generated[instance] {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func (m *Memory) AddGeneratedSecrets(instance string, names []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.instances[instance]; !ok {
		return ErrNotFound
	}
	if m.generated[instance] == nil {
		m.generated[instance] = map[string]bool{}
	}
	for _, n := range names {
		m.generated[instance][n] = true
	}
	return nil
}

// GatewayBackfill reports whether the instance still owes the ui facts
// the gateway routes on (see the SQLite store: migration 4 sets it for
// every instance older than those columns). A memory store has no
// database to upgrade, so nothing is owed unless a caller says so.
func (m *Memory) GatewayBackfill(instance string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.instances[instance]; !ok {
		return false, ErrNotFound
	}
	return m.backfill[instance], nil
}

func (m *Memory) SetGatewayBackfill(instance string, pending bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.instances[instance]; !ok {
		return ErrNotFound
	}
	if pending {
		m.backfill[instance] = true
	} else {
		delete(m.backfill, instance)
	}
	return nil
}

func (m *Memory) Unsupported(instance string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.instances[instance]; !ok {
		return "", ErrNotFound
	}
	return m.unsupported[instance], nil
}

func (m *Memory) MarkUnsupported(instance, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.instances[instance]; !ok {
		return ErrNotFound
	}
	if reason == "" {
		delete(m.unsupported, instance)
	} else {
		m.unsupported[instance] = reason
	}
	return nil
}

func (m *Memory) PutService(s Service) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.services[s.Instance] == nil {
		m.services[s.Instance] = map[string]Service{}
	}
	m.services[s.Instance][s.Name] = s
	return nil
}

func (m *Memory) ListServices(instance string) ([]Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Service, 0, len(m.services[instance]))
	for _, s := range m.services[instance] {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) DeleteService(instance, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.services[instance], name)
	return nil
}

func (m *Memory) PutJob(j Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.jobs[j.ID]; !ok {
		m.jobOrder = append(m.jobOrder, j.ID)
	}
	m.jobs[j.ID] = j
	return nil
}

func (m *Memory) GetJob(id string) (*Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &j, nil
}

func (m *Memory) ListJobs(instance string) ([]Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Job
	for i := len(m.jobOrder) - 1; i >= 0; i-- {
		j := m.jobs[m.jobOrder[i]]
		if instance == "" || j.Instance == instance {
			out = append(out, j)
		}
	}
	return out, nil
}

func (m *Memory) ActiveJob(instance string) (*Job, error) {
	jobs, _ := m.ListJobs(instance)
	for _, j := range jobs {
		if j.Active() {
			j := j
			return &j, nil
		}
	}
	return nil, nil
}

func (m *Memory) AppendEvent(e Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	e.Seq = m.seq
	m.events[e.Job] = append(m.events[e.Job], e)
	return nil
}

func (m *Memory) ListEvents(job string) ([]Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Event(nil), m.events[job]...), nil
}

func (m *Memory) PutSession(sess Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[sess.ID] = sess
	return nil
}

func (m *Memory) PutSessionAudited(sess Session, a Audit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[sess.ID] = sess
	m.appendAuditLocked(a)
	return nil
}

func (m *Memory) GetSession(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &sess, nil
}

func (m *Memory) TouchSession(id string, lastSeen, expires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[id]
	if !ok {
		return ErrNotFound
	}
	sess.LastSeen, sess.Expires = lastSeen, expires
	m.sessions[id] = sess
	return nil
}

func (m *Memory) DeleteSession(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}

func (m *Memory) DeleteSessionAudited(id string, a Audit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	m.appendAuditLocked(a)
	return nil
}

func (m *Memory) PurgeSessions(t time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, sess := range m.sessions {
		if !sess.Expires.After(t) {
			delete(m.sessions, id)
			n++
		}
	}
	return n, nil
}

func (m *Memory) PutToken(tok Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, t := range m.tokens {
		if id != tok.ID && (t.Name == tok.Name || t.Hash == tok.Hash) {
			return ErrConflict
		}
	}
	if _, ok := m.tokens[tok.ID]; !ok {
		m.tokenOrd = append(m.tokenOrd, tok.ID)
	}
	m.tokens[tok.ID] = tok
	return nil
}

func (m *Memory) PutTokenAudited(tok Token, a Audit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, t := range m.tokens {
		if id != tok.ID && (t.Name == tok.Name || t.Hash == tok.Hash) {
			return ErrConflict
		}
	}
	if _, ok := m.tokens[tok.ID]; !ok {
		m.tokenOrd = append(m.tokenOrd, tok.ID)
	}
	m.tokens[tok.ID] = tok
	m.appendAuditLocked(a)
	return nil
}

func (m *Memory) GetTokenByHash(hash string) (*Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tokens {
		if t.Hash == hash {
			t := t
			return &t, nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) ListTokens() ([]Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Token, 0, len(m.tokens))
	for _, id := range m.tokenOrd {
		if t, ok := m.tokens[id]; ok {
			out = append(out, t)
		}
	}
	return out, nil
}

func (m *Memory) TouchToken(id string, lastUsed time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tok, ok := m.tokens[id]
	if !ok {
		return ErrNotFound
	}
	used := lastUsed
	tok.LastUsed = &used
	m.tokens[id] = tok
	return nil
}

func (m *Memory) DeleteToken(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tokens[id]; !ok {
		return ErrNotFound
	}
	delete(m.tokens, id)
	return nil
}

func (m *Memory) DeleteTokenAudited(id string, a Audit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tokens[id]; !ok {
		return ErrNotFound
	}
	delete(m.tokens, id)
	m.appendAuditLocked(a)
	return nil
}

func (m *Memory) AppendAudit(a Audit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.appendAuditLocked(a)
	return nil
}

func (m *Memory) LatestAuditSeq() (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seq, nil
}

func (m *Memory) appendAuditLocked(a Audit) {
	m.seq++
	a.Seq = m.seq
	m.audit = append(m.audit, a)
}

func (m *Memory) ListAudit(instance string) ([]Audit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Audit
	for _, a := range m.audit {
		if a.Instance == instance {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *Memory) GetLoginState(source string) (*LoginState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ls, ok := m.logins[source]
	if !ok {
		return nil, nil
	}
	return &ls, nil
}

func (m *Memory) PutLoginState(ls LoginState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logins[ls.Source] = ls
	return nil
}

func (m *Memory) PutLoginStateAudited(ls LoginState, records ...Audit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logins[ls.Source] = ls
	for _, a := range records {
		m.appendAuditLocked(a)
	}
	return nil
}

func (m *Memory) ListLockedSources() ([]LoginState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []LoginState
	for _, ls := range m.logins {
		if ls.LockedUntil != nil {
			out = append(out, ls)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out, nil
}

// --- instance access credentials (API §2.4, plan S9) ------------------

func (m *Memory) PutAccessAudited(a Access, gen int64, rec Audit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, existing := range m.access {
		if id != a.ID && existing.Hash == a.Hash {
			return ErrConflict
		}
	}
	// The lab has to be there. A destroy committing between an operator's
	// check and this write would leave a credential with no instance,
	// which is joinable by name and becomes a working attendee
	// credential again the moment that name is used.
	// The generation the caller read, not just the name: a name
	// destroyed and created again between the read and this write passes
	// an existence test, and the link meant for the lab that is gone
	// would open its replacement.
	if inst, ok := m.instances[a.Instance]; !ok || inst.AuditFrom != gen {
		return ErrNotFound
	}
	if _, ok := m.access[a.ID]; !ok {
		m.accessOrd = append(m.accessOrd, a.ID)
	}
	a.Gen = gen
	m.access[a.ID] = a
	m.appendAuditLocked(rec)
	return nil
}

func (m *Memory) GetAccessByHash(hash string) (*Access, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.access {
		if a.Hash == hash {
			out := a
			return &out, nil
		}
	}
	return nil, ErrNotFound
}

// JoinAccessAudited records the use, stores the session and appends the
// audit records under one lock. A credential a revocation removed first
// opens no session at all.
func (m *Memory) JoinAccessAudited(id string, lastUsed time.Time, sess Session, recs ...Audit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.access[id]
	if !ok {
		return ErrNotFound
	}
	a.LastUsed = &lastUsed
	m.access[id] = a
	m.sessions[sess.ID] = sess
	for _, rec := range recs {
		m.appendAuditLocked(rec)
	}
	return nil
}

func (m *Memory) ListAccess(instance string) ([]Access, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Access
	for _, id := range m.accessOrd {
		if a, ok := m.access[id]; ok && a.Instance == instance {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *Memory) DeleteAccessAudited(instance, id string, rec Audit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.access[id]
	if !ok || a.Instance != instance {
		return ErrNotFound
	}
	delete(m.access, id)
	kept := m.accessOrd[:0]
	for _, existing := range m.accessOrd {
		if existing != id {
			kept = append(kept, existing)
		}
	}
	m.accessOrd = append([]string(nil), kept...)
	m.appendAuditLocked(rec)
	return nil
}
