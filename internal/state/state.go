// SPDX-License-Identifier: AGPL-3.0-only

// Package state is the engine's persistent memory (roadmap §9 Engine row:
// SQLite state, persistent jobs, reconcile-on-start). The Store interface
// is what the engine talks to; SQLite implements it for the product and
// an in-memory store implements it for tests. Both pass the same
// conformance suite (RunStoreTests).
package state

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// ErrNotFound reports an absent row.
var ErrNotFound = errors.New("not found")

// ErrConflict reports a uniqueness violation (a token name or hash that
// already exists).
var ErrConflict = errors.New("conflict")

// Mode is an instance's fixed posture (roadmap §3.1): authoring tracks a
// working directory; delivery pins a template snapshot.
type Mode string

const (
	ModeAuthoring Mode = "authoring"
	ModeDelivery  Mode = "delivery"
)

// Stage is a rung of the ready ladder (UX §5). The empty stage means
// "not yet alive".
type Stage string

const (
	StageNone        Stage = ""
	StageAlive       Stage = "alive"
	StageHealthy     Stage = "healthy"
	StageInitialized Stage = "initialized"
	StageConnected   Stage = "connected"
	StageSeeded      Stage = "seeded"
	StageVerified    Stage = "verified"
	StageReady       Stage = "ready"
)

// Ladder is the canonical stage order.
var Ladder = []Stage{StageAlive, StageHealthy, StageInitialized, StageConnected, StageSeeded, StageVerified, StageReady}

// Rank returns a stage's position on the ladder (0 = not alive).
func (s Stage) Rank() int {
	for i, st := range Ladder {
		if st == s {
			return i + 1
		}
	}
	return 0
}

// Instance is one lab instance (API §7.2 is rendered from this plus its
// services and the latest job).
type Instance struct {
	Name     string    `json:"name"`
	Template string    `json:"template"`
	Version  string    `json:"version,omitempty"`
	Profile  string    `json:"profile,omitempty"`
	Mode     Mode      `json:"mode"`
	Source   string    `json:"source"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
	Stage    Stage     `json:"stage"`
	// Reached is the highest rung this instance's ladder has stood at:
	// raised whenever the stage is recomputed, never lowered. The stage
	// alone cannot tell a lab still climbing for the first time from one
	// that has fallen back, and UX §5's regression is a fall *from*
	// ready — so this is what makes the difference sayable. Written in
	// refreshInstanceStage and nowhere else.
	Reached Stage `json:"reached,omitempty"`
	// Licenses are the EULA ids accepted at create (and on a resumed
	// create): the admission record the job re-applies to the plan it
	// re-reads, so a template that grew a license is refused, not run.
	Licenses []string `json:"licenses,omitempty"`
	// SeedSalt is the per-instance random value every seed_value derives
	// from (Spec 0002 §5: stable per instance and seed name). Not a
	// secret — it makes two instances' payloads differ — but never shown.
	SeedSalt string `json:"seed_salt,omitempty"`
	// AuditFrom is the audit sequence this instance's own rows begin at:
	// the stream's high-water mark when it was created. A destroy leaves
	// audit rows behind — they are the security record — so a name used
	// twice needs a line between the generations, and this is it.
	//
	// The line is the sequence and not the clock, deliberately: `Seq` is
	// monotonic in both stores, while a host clock that steps back would
	// put a live instance's own rows before its creation and hide them
	// (the lesson review round 69 already recorded for freshness).
	// Zero means "everything", which is what an instance created before
	// this column existed gets — nothing can reconstruct where its
	// generations began.
	AuditFrom int64 `json:"-"`
}

// CheckpointResult is the latest result of one checkpoint on an instance
// (API §8: the result object; spec 0001 §4: status ∈ pass|fail|attested|
// error, class always present). Observed and Expected are the adapter's
// JSON as recorded; Error is the §3 envelope of an error result.
type CheckpointResult struct {
	Instance string          `json:"-"`
	ID       string          `json:"id"`
	Class    string          `json:"class"`
	Adapter  string          `json:"adapter,omitempty"`
	Status   string          `json:"status"`
	At       time.Time       `json:"at"`
	Duration string          `json:"duration"`
	Job      string          `json:"job,omitempty"`
	Evidence string          `json:"evidence,omitempty"`
	Observed json.RawMessage `json:"observed,omitempty"`
	Expected json.RawMessage `json:"expected,omitempty"`
	Message  string          `json:"message,omitempty"`
	Hint     string          `json:"hint,omitempty"`
	Error    *pdr.Error      `json:"error,omitempty"`
	// Definition is the digest of the checkpoint definition the result was
	// judged by (lab.DefinitionDigest): a row whose checkpoint changed in
	// any behaviour-affecting way starts over as pending. Engine
	// bookkeeping, not part of the API shape.
	Definition string `json:"-"`
}

// Progress is one playbook's learner position on an instance (spec 0001
// §8, API §8): statuses come only from checkpoint results or an explicit
// skip, which the engine enforces on every write.
type Progress struct {
	Instance    string                  `json:"-"`
	Playbook    string                  `json:"-"`
	CurrentStep string                  `json:"current_step"`
	Steps       map[string]StepProgress `json:"steps"`
	Updated     time.Time               `json:"updated"`
}

// StepProgress is one step's recorded status and when it was recorded.
type StepProgress struct {
	Status string    `json:"status"`
	At     time.Time `json:"at"`
}

// Service is one service of an instance with its container facts.
type Service struct {
	Instance    string      `json:"instance"`
	Name        string      `json:"name"`
	Module      string      `json:"module,omitempty"`
	Image       string      `json:"image"`
	Container   string      `json:"container"`
	ContainerID string      `json:"container_id,omitempty"`
	Stage       Stage       `json:"stage"`
	Ports       map[int]int `json:"ports,omitempty"`
	Typical     string      `json:"typical,omitempty"`
	Budget      string      `json:"budget,omitempty"`
	StartedAt   *time.Time  `json:"started_at,omitempty"`
	HealthyAt   *time.Time  `json:"healthy_at,omitempty"`
	// RanImage is the image this service was last seen *running*, written
	// with StartedAt at the moment a container is confirmed up. Image
	// beside it is the plan's, refreshed on every attempt — so after an
	// edited retry that fails to start, Image is the replacement and
	// RanImage is still the one that ran. Evidence answers with this one.
	RanImage string `json:"ran_image,omitempty"`
	// RanModule is the module of that same run. Module beside it is the
	// plan's and moves with it, so a retry after an edited module paired
	// the previous run's image with the new module — a combination that
	// never existed. Every column of evidence's
	// "What ran" is now either a fact of the run or one that cannot move:
	// a renamed service is a different row.
	RanModule string `json:"ran_module,omitempty"`
	// Readiness fingerprints the probe contract HealthyAt was proven
	// under; a resumed job keeps a recorded healthy only for the same
	// contract.
	Readiness string `json:"readiness,omitempty"`
	Error     string `json:"error,omitempty"`
	// UIPort is the container port of the service's `ui` endpoint (0 when
	// it has none) and Embed its declared embed capability — what the
	// gateway routes `<service>-<instance>.<domain>` to (plan S5).
	UIPort   int    `json:"ui_port,omitempty"`
	UIScheme string `json:"ui_scheme,omitempty"`
	Embed    string `json:"embed,omitempty"`
}

// JobState is API §4's state enum.
type JobState string

const (
	JobQueued    JobState = "queued"
	JobRunning   JobState = "running"
	JobSucceeded JobState = "succeeded"
	JobFailed    JobState = "failed"
)

// Job is a persistent job (API §4): survives engine restarts and client
// disconnects; one exclusive job per instance at a time.
type Job struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Instance string   `json:"instance"`
	State    JobState `json:"state"`
	Stage    string   `json:"stage"`
	// Target narrows a job: the seed a seed job runs, the playbook a
	// verify job is limited to (plan S6).
	Target string `json:"target,omitempty"`
	// Gen is the generation of Instance this job belongs to. A destroy
	// keeps an instance's jobs and their journals — they are the record
	// of what happened — so a name used twice has jobs from more than
	// one lab, and the name alone cannot tell them apart. -1 marks a job
	// written before the column existed: an audit sequence is never
	// negative, so it matches no generation and is shown to the operator
	// alone.
	Gen      int64      `json:"-"`
	Started  time.Time  `json:"started"`
	Finished *time.Time `json:"finished"`
	// Error is the failed job's §3 envelope (API §4): an object, null
	// while there is none — never a string a client must decode twice.
	Error *pdr.Error `json:"error"`
}

// Active reports whether the job still holds the instance's exclusive slot.
func (j Job) Active() bool { return j.State == JobQueued || j.State == JobRunning }

// Event is one journal line of a job: what step ran, on what, with what
// outcome — the record resumption reads and the evidence stream feeds.
type Event struct {
	Seq     int64     `json:"seq"`
	Job     string    `json:"job"`
	At      time.Time `json:"at"`
	Step    string    `json:"step"`
	Service string    `json:"service,omitempty"`
	Status  string    `json:"status"`
	Detail  string    `json:"detail,omitempty"`
}

// Session is one server-side console session (API §2.2; threat model B2:
// "server-side session records"). The cookie carries the id plus an HMAC
// under the operator's session-signing key; the record is the truth.
// Instance is empty for the operator; instance access (API §2.4, plan S9)
// binds a session to one instance and the gateway refuses it elsewhere.
type Session struct {
	ID        string `json:"id"`
	Subject   string `json:"subject"`
	Mechanism string `json:"mechanism"`
	Instance  string `json:"instance,omitempty"`
	// Gen is the generation of Instance this session was opened against
	// — the instance's AuditFrom, copied from the credential that opened
	// it. A name can come back; a session that outlived the lab it names
	// must not act on the one that replaced it.
	Gen      int64     `json:"-"`
	CSRF     string    `json:"csrf"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"last_seen"`
	Expires  time.Time `json:"expires"`
}

// Token is one bearer token (API §2.3), stored hashed: Hash is the hex
// SHA-256 of the full secret, Prefix the first characters after `pdr_`
// shown in listings.
type Token struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Prefix   string     `json:"prefix"`
	Hash     string     `json:"-"`
	Scope    string     `json:"scope"`
	Created  time.Time  `json:"created"`
	LastUsed *time.Time `json:"last_used"`
}

// Access is one attendee credential for one instance (API §2.4, plan
// S9), stored hashed exactly as a token is: Hash is the hex SHA-256 of
// the full secret, Prefix the first characters after `pdi_` shown in
// listings. It is not a bearer credential — `GET /join/{token}` exchanges
// it once for an instance-scoped session — and it expires on its own,
// because a link handed out at the start of a workshop should stop
// working after it.
type Access struct {
	ID       string     `json:"id"`
	Instance string     `json:"instance"`
	Name     string     `json:"name"`
	Prefix   string     `json:"prefix"`
	Hash     string     `json:"-"`
	Created  time.Time  `json:"created"`
	Expires  time.Time  `json:"expires"`
	LastUsed *time.Time `json:"last_used"`
	// Gen is the generation of Instance this credential was issued for.
	// The session a join opens inherits it, so the binding survives from
	// the link to every request made with it.
	Gen int64 `json:"-"`
}

// Audit is one security-relevant event (API §2.5): who did what, through
// which mechanism, when. Instance is empty for the system stream.
type Audit struct {
	Seq       int64     `json:"seq"`
	At        time.Time `json:"at"`
	Instance  string    `json:"instance,omitempty"`
	Action    string    `json:"action"`
	Actor     string    `json:"actor,omitempty"`
	Mechanism string    `json:"mechanism,omitempty"`
	Detail    string    `json:"detail,omitempty"`
}

// LoginState is the per-source login throttle record (API §2.1): the
// consecutive failure count drives the backoff; LockedUntil is set while
// the source is locked out.
type LoginState struct {
	Source      string     `json:"source"`
	Failures    int        `json:"failures"`
	LastFailure time.Time  `json:"last_failure"`
	LockedUntil *time.Time `json:"locked_until,omitempty"`
}

// Store is the persistence contract.
type Store interface {
	Close() error

	PutInstance(Instance) error
	GetInstance(name string) (*Instance, error)
	ListInstances() ([]Instance, error)
	DeleteInstance(name string) error
	// GeneratedSecrets lists the names of the secrets ever generated for an
	// instance, sorted — an append-only history the redaction filter must
	// hold a value for, kept until the instance is deleted: an authoring
	// edit that drops a declaration does not drop the value a container
	// may still hold.
	GeneratedSecrets(instance string) ([]string, error)
	// AddGeneratedSecrets adds names to that history; names already there
	// stay. ErrNotFound for an instance that does not exist.
	AddGeneratedSecrets(instance string, names []string) error
	// GatewayBackfill reports whether an instance still owes the ui facts
	// the gateway routes on: migration 4 marks every instance that
	// existed before those columns did, and the flag is cleared once
	// they are published. It is a record of the upgrade, never a reading
	// of the data — a service that declares no ui endpoint carries the
	// same zeros as a row the backfill never reached.
	GatewayBackfill(instance string) (bool, error)
	SetGatewayBackfill(instance string, pending bool) error
	// Unsupported reports why this release does not operate an instance
	// — "retired template" — or "" (migration 16; the reconciliation
	// plan's R3). It records that the engine marked the instance, once;
	// which templates are retired is the embedded retirement manifest's
	// to say, and the engine reads it from there. A write of the instance
	// never clears the mark. ErrNotFound for an instance that does not
	// exist.
	Unsupported(instance string) (string, error)
	MarkUnsupported(instance, reason string) error

	PutService(Service) error
	ListServices(instance string) ([]Service, error)
	DeleteService(instance, name string) error

	PutJob(Job) error
	GetJob(id string) (*Job, error)
	// ListJobs returns jobs for an instance ("" for all), newest first.
	ListJobs(instance string) ([]Job, error)
	// ActiveJob returns the queued or running job holding the instance's
	// exclusive slot, or nil.
	ActiveJob(instance string) (*Job, error)

	AppendEvent(Event) error
	ListEvents(job string) ([]Event, error)

	PutSession(Session) error
	// PutSessionAudited stores a session and appends its audit record as
	// one write: both land or neither does, so no session ever exists
	// that the stream does not know about.
	PutSessionAudited(sess Session, a Audit) error
	GetSession(id string) (*Session, error)
	// TouchSession moves an existing session's last-seen and expiry;
	// ErrNotFound when no record holds the id — it never creates one, so
	// a use racing a sign-out cannot bring the session back.
	TouchSession(id string, lastSeen, expires time.Time) error
	DeleteSession(id string) error
	// DeleteSessionAudited removes a session and records its audit record
	// as one write: both land or neither does, so no sign-out is ever
	// done without the record that says who signed out. A session already
	// gone (expired, purged by a reset) still gets its record: the
	// sign-out is the act recorded, the deletion its idempotent effect.
	DeleteSessionAudited(id string, a Audit) error
	// PurgeSessions removes sessions whose Expires is at or before t and
	// reports how many went.
	PurgeSessions(t time.Time) (int, error)

	PutToken(Token) error
	// PutTokenAudited records a new token and its audit record as one
	// write: both land or neither does (ErrConflict for a taken name or
	// hash, with nothing recorded), so no credential ever exists without
	// the record that says who made it.
	PutTokenAudited(tok Token, a Audit) error
	GetTokenByHash(hash string) (*Token, error)
	// TouchToken records an existing token's last use; ErrNotFound when
	// the token is gone — it never re-creates one, so a use racing a
	// revocation cannot bring the token back.
	TouchToken(id string, lastUsed time.Time) error
	// ListTokens returns every token, oldest first.
	ListTokens() ([]Token, error)
	DeleteToken(id string) error
	// DeleteTokenAudited removes a token and records its audit record as
	// one write: both land or neither does (ErrNotFound for a token that
	// is not there, with nothing recorded), so no credential is ever
	// revoked without the record that says who revoked it.
	DeleteTokenAudited(id string, a Audit) error

	// PutAccessAudited records a new instance access credential and its
	// audit record as one write: both land or neither does (ErrConflict
	// for a taken hash, with nothing recorded), so no credential ever
	// exists without the record that says who issued it. ErrNotFound when
	// the instance is not there: a destroy that commits between an
	// operator's check and this write would otherwise leave a credential
	// that outlives its lab and admits its bearer to the next instance of
	// the same name.
	//
	// gen is the generation the caller read — the instance's AuditFrom.
	// ErrNotFound too when the name is there but is not that generation:
	// a name destroyed and created again inside the same window passes an
	// existence test, and the link issued for the lab that is gone would
	// open the one that replaced it.
	PutAccessAudited(a Access, gen int64, rec Audit) error
	// GetAccessByHash finds a credential by the hash of the secret
	// presented, or nil when none holds it.
	GetAccessByHash(hash string) (*Access, error)
	// JoinAccessAudited records a credential's use, stores the session it
	// opened and appends the audit records, as one write. ErrNotFound when
	// the credential is gone, with no session stored: a revocation the
	// operator has been told succeeded must not be followed by a session
	// the same link opens, and touching afterwards left exactly that
	// window open.
	//
	// Records, plural, because a join writes into two streams: what the
	// lab may say about itself, and what only the operator may read.
	// Both land with the session or neither does.
	JoinAccessAudited(id string, lastUsed time.Time, sess Session, recs ...Audit) error
	// ListAccess returns one instance's credentials, oldest first.
	ListAccess(instance string) ([]Access, error)
	// DeleteAccessAudited revokes a credential and records its audit
	// record as one write (ErrNotFound for one that is not there, with
	// nothing recorded).
	DeleteAccessAudited(instance, id string, rec Audit) error

	AppendAudit(Audit) error
	// LatestAuditSeq is the sequence of the newest audit row, or zero
	// when the stream is empty: where a new instance's own rows begin.
	LatestAuditSeq() (int64, error)
	// ListAudit returns one stream, oldest first ("" is the system stream).
	ListAudit(instance string) ([]Audit, error)

	// GetLoginState returns the source's record, or nil when it has none.
	GetLoginState(source string) (*LoginState, error)
	PutLoginState(LoginState) error
	// PutLoginStateAudited stores the source's record and appends its
	// audit records as one write: all land or none does, so no counted
	// failure or lockout ever stands that the stream does not know about.
	PutLoginStateAudited(ls LoginState, records ...Audit) error
	// ListLockedSources returns the sources whose lockout is set.
	ListLockedSources() ([]LoginState, error)

	// PutCheckpointResult records the latest result of one checkpoint,
	// replacing the previous one (the journal of every run is the
	// evidence, not this table).
	PutCheckpointResult(CheckpointResult) error
	// ListCheckpointResults returns an instance's latest results, by id.
	ListCheckpointResults(instance string) ([]CheckpointResult, error)
	// DeleteCheckpointResults forgets an instance's latest results of one
	// class ("" for every class) — reset clears objective results so the
	// system and the record agree (spec 0001 §8).
	DeleteCheckpointResults(instance, class string) error

	// PutProgress stores one playbook's progress on an instance.
	PutProgress(Progress) error
	// GetProgress returns it; ErrNotFound when nothing was recorded.
	GetProgress(instance, playbook string) (*Progress, error)
	// DeleteProgress forgets every playbook's progress on an instance
	// (reset clears objective progress; evidence keeps the history).
	DeleteProgress(instance string) error
}
