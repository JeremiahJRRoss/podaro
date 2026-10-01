// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite: one static binary, no cgo

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// SQLite is the product Store: one file, WAL mode, forward-only
// migrations applied after an automatic backup (INSTALL §6).
type SQLite struct {
	db   *sql.DB
	path string
}

// migrations are applied in order, once each; never edited after they
// ship — a change is a new entry.
var migrations = []string{
	`create table instances (
		name text primary key, template text not null, version text not null default '',
		profile text not null default '', mode text not null, source text not null,
		created text not null, updated text not null, stage text not null default '');
	create table services (
		instance text not null, name text not null, module text not null default '',
		image text not null, container text not null, container_id text not null default '',
		stage text not null default '', ports text not null default '{}',
		typical text not null default '', budget text not null default '',
		started_at text, healthy_at text, error text not null default '',
		primary key (instance, name));
	create table jobs (
		id text primary key, kind text not null, instance text not null, state text not null,
		stage text not null default '', started text not null, finished text, error text not null default '',
		seq integer not null);
	create index jobs_instance on jobs (instance, seq);
	create table events (
		seq integer primary key autoincrement, job text not null, at text not null,
		step text not null, service text not null default '', status text not null, detail text not null default '');
	create index events_job on events (job, seq);`,
	// 2 (plan S4, review round 10): the licenses accepted at create.
	`alter table instances add column licenses text not null default '';`,
	// 3 (plan S4, review round 21): the readiness contract a service's
	// healthy was recorded under.
	`alter table services add column readiness text not null default '';`,
	// 4 (plan S5): the network door — sessions, tokens, the audit stream, the
	// login throttle — and the ui endpoint facts the gateway routes on.
	`alter table services add column ui_port integer not null default 0;
	alter table services add column ui_scheme text not null default '';
	alter table services add column embed text not null default '';
	create table sessions (
		id text primary key, subject text not null, mechanism text not null,
		instance text not null default '', csrf text not null,
		created text not null, last_seen text not null, expires text not null);
	create index sessions_expires on sessions (expires);
	create table tokens (
		id text primary key, name text not null unique, prefix text not null,
		hash text not null unique, scope text not null, created text not null, last_used text,
		seq integer not null);
	create table audit (
		seq integer primary key autoincrement, at text not null, instance text not null default '',
		action text not null, actor text not null default '', mechanism text not null default '',
		detail text not null default '');
	create index audit_instance on audit (instance, seq);
	create table login_state (
		source text primary key, failures integer not null default 0,
		last_failure text not null default '', locked_until text);
	alter table instances add column gateway_backfill integer not null default 0;
	update instances set gateway_backfill = 1;`,
	// 5 (plan S6): the per-instance seed salt, the latest checkpoint
	// results (API §8), and playbook progress (spec 0001 §8).
	`alter table instances add column seed_salt text not null default '';
	alter table jobs add column target text not null default '';
	create table checkpoint_results (
		instance text not null, id text not null, class text not null, adapter text not null default '',
		status text not null, at text not null, duration text not null default '', job text not null default '',
		evidence text not null default '', observed text not null default '', expected text not null default '',
		message text not null default '', hint text not null default '', error text not null default '',
		primary key (instance, id));
	create table progress (
		instance text not null, playbook text not null, current_step text not null default '',
		steps text not null default '{}', updated text not null,
		primary key (instance, playbook));`,
	// Review round 10: the definition digest a result was judged
	// by, so an edited checkpoint starts over as pending.
	`alter table checkpoint_results add column definition text not null default '';`,
	// 7: the names of the secrets ever generated
	// for an instance — the redaction filter's expectation, kept until the
	// instance is deleted.
	`create table generated_secrets (
		instance text not null, name text not null,
		primary key (instance, name));`,
	// 8 (plan S9): attendee access credentials (API §2.4) — hashed at
	// rest, one instance each, expiring on their own.
	`create table access (
		id text primary key, instance text not null, name text not null,
		prefix text not null, hash text not null unique,
		created text not null, expires text not null, last_used text,
		seq integer not null);
	create index access_instance on access (instance, seq);`,
	// 9 (plan S9, review): where an instance's own audit rows begin. A
	// destroy leaves the rows — they are the security record — so a name
	// used twice needs a line between its generations.
	//
	// An instance that predates the column is moved to the *current*
	// high-water mark, not to zero. Zero means "everything", and a name
	// that had been destroyed and reused before this upgrade would then
	// have handed its attendees the older generation's joins and reveals
	// — the very leak the column exists to close, preserved across the
	// upgrade that closes it. The cost is stated where it lands: such an
	// instance shows none of its own earlier audit rows in its evidence
	// either, because nothing here can tell the two apart. The operator's
	// system audit stream is unchanged and holds all of them.
	`alter table instances add column audit_from integer not null default 0;
	update instances set audit_from = (select coalesce(max(seq), 0) from audit);`,

	// 10 (plan S9, review round 12): which generation a credential and
	// the session it opened belong to. The name alone was the binding,
	// and a name can come back: an attendee whose request was already
	// authenticated when the lab was destroyed and re-created went on to
	// act on the replacement.
	//
	// Rows that predate the column take their instance's *current*
	// generation, and that is not a guess — a destroy deletes an
	// instance's access rows and its sessions along with it (see
	// DeleteInstance), so a row that is still here belongs to the
	// generation that is still here. Zero is not usable as "unknown":
	// an instance created while the audit table was empty has
	// `audit_from = 0` legitimately.
	`alter table access add column gen integer not null default 0;
	alter table sessions add column gen integer not null default 0;
	update access set gen = coalesce((select audit_from from instances where name = access.instance), 0);
	update sessions set gen = coalesce((select audit_from from instances where name = sessions.instance), 0);`,

	// 11 (plan S9, review round 15): which generation a job belongs to.
	// Unlike credentials and sessions, a destroy *keeps* an instance's
	// jobs and their journals — they are the record of what happened —
	// so a name used twice carries jobs from more than one lab and the
	// name alone cannot tell them apart. An attendee of the replacement
	// could read the previous lab's job and its journal.
	//
	// Rows that predate the column are marked -1 rather than given the
	// current generation: here a surviving row proves nothing, because
	// jobs survive on purpose. An audit sequence is never negative, so
	// -1 matches no generation — the operator, entitled to none in
	// particular, still sees every one of them.
	`alter table jobs add column gen integer not null default -1;`,
	// 12 (plan S9, review round 23): the sentinel is right for a job
	// that has finished and wrong for one that has not. An upgrade
	// promises persistent jobs are reattached, and `Engine.Start`
	// resumes exactly the queued and running rows — against the instance
	// that is there now, whose generation the attendee's session
	// carries. Marked -1 they matched nothing, so the attendee could
	// neither poll the create they were watching nor follow its events
	// across the upgrade that promises it would not stop. A finished job
	// keeps the sentinel, and so does an active row whose instance is
	// gone: neither has a lab it can be known to belong to.
	`update jobs set gen = (select audit_from from instances where instances.name = jobs.instance)
	 where gen = -1 and state in ('queued', 'running')
	   and exists (select 1 from instances where instances.name = jobs.instance);`,
	// 13 and 14 (plan S9, review rounds 27, 28 and 29): the image and
	// the module a service was last seen *running*, as facts of the run
	// rather than of the plan. Both plan copies are refreshed on every
	// attempt, so an authoring retry after an edited image or module
	// left the new one on a row whose start time belonged to the run
	// before it.
	//
	// Neither is filled from the plan at the upgrade. Both were, at
	// first: `image` where a start time existed, then `module` where
	// that had left a value. For a row caught between an edited retry's
	// publish and its start that reproduces exactly the false pairing
	// these columns exist to prevent — and it reproduces it *worse*,
	// because a value here carries the claim "this ran" rather than
	// "the plan says this". A run fact that cannot
	// be proven is left unknown: an upgraded lab's "What ran" is empty
	// until it runs again, which says less and nothing untrue.
	//
	// Two statements rather than one because the schema version is the
	// count: a database already carrying the backfill can only exist on
	// this unmerged branch.
	`alter table services add column ran_image text not null default '';`,
	`alter table services add column ran_module text not null default '';`,
	// 15 (plan S14): the highest rung an instance's ladder has stood at.
	// A regression is a fall *from* ready (UX §5) and the stage alone
	// cannot say one happened — a lab at `seeded` may be climbing for
	// the first time or may have fallen back an hour ago.
	//
	// Existing rows are backfilled from the stage they stand at, which
	// is the most that can be claimed: nothing recorded where they had
	// been, so a lab that regressed before this column existed reads as
	// one that never reached ready. That says less and nothing untrue —
	// the same rule migration 14 settled for the run facts. Its own next
	// climb to ready records the mark, and from there the fall is
	// sayable.
	`alter table instances add column reached text not null default '';
	update instances set reached = stage;`,
	// 16 (the reconciliation plan's R3): why this release does not
	// operate an instance — "retired template", when an earlier build
	// created it from a template the owner has since retired — or empty.
	// A column and nothing else: no row is changed, nothing is deleted,
	// and nothing is backfilled here, because which templates are retired
	// is the retirement manifest's to say and a statement here would have
	// to spell the names (the plan's Q-R5). The engine marks an instance
	// the first time a start finds its template listed (MarkUnsupported),
	// and the mark is what keeps that report to one evidence entry.
	`alter table instances add column unsupported text not null default '';`,
}

// migrationSet returns the migrations to apply; tests append a pending
// one to exercise the backup path.
var migrationSet = func() []string { return migrations }

// OpenSQLite opens (creating if absent) the state database at path and
// brings its schema forward. When migrations are pending on an existing
// file, a timestamped backup is written first (state.db.bak-<version>-
// <time>); a failed migration leaves the backup and refuses to continue.
func OpenSQLite(path string) (*SQLite, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	existed := false
	if _, err := os.Stat(path); err == nil {
		existed = true
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &SQLite{db: db, path: path}
	if err := s.migrate(existed); err != nil {
		db.Close()
		return nil, err
	}
	if !existed {
		// A brand-new WAL database keeps its first pages in the log until
		// a checkpoint; SQLite discards the log of a zero-length main file
		// on the next open. Checkpoint once so an engine killed before its
		// first automatic checkpoint still finds its state.
		if _, err := db.Exec(`pragma wal_checkpoint(TRUNCATE)`); err != nil {
			db.Close()
			return nil, err
		}
		_ = os.Chmod(path, 0o600)
	}
	return s, nil
}

func (s *SQLite) migrate(existed bool) error {
	if _, err := s.db.Exec(`create table if not exists schema_migrations (version integer primary key, applied text not null)`); err != nil {
		return err
	}
	var current int
	if err := s.db.QueryRow(`select coalesce(max(version), 0) from schema_migrations`).Scan(&current); err != nil {
		return err
	}
	steps := migrationSet()
	if current > len(steps) {
		// A newer Podaro extended the schema: this engine would run
		// against tables and invariants it does not know. Refuse rather
		// than guess — nothing is read or written past this point.
		pe := pdr.New(pdr.CodeStateNewer, "%s is at schema version %d; this engine (%s) knows %d", s.path, current, podaro.Version(), len(steps))
		pe.Cause = fmt.Sprintf("a newer Podaro applied migration %d; migrations are forward-only", current)
		pe.Next = "run the Podaro version that wrote it · or roll back binary and state together: stop the engine, then restore the pre-migration backup beside state.db (state.db.bak-v<version>-<time>)"
		return pe
	}
	if current == len(steps) {
		return nil
	}
	if existed && current > 0 {
		backup := fmt.Sprintf("%s.bak-v%s-%s", s.path, podaro.Version(), time.Now().UTC().Format("20060102T150405Z"))
		if err := s.backupTo(backup); err != nil {
			return fmt.Errorf("state backup before migration: %w", err)
		}
	}
	for i := current; i < len(steps); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(steps[i]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d failed (state left at version %d; the backup beside state.db restores it): %w", i+1, i, err)
		}
		if _, err := tx.Exec(`insert into schema_migrations (version, applied) values (?, ?)`, i+1, time.Now().UTC().Format(time.RFC3339)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// SchemaVersion reports the applied migration count.
func (s *SQLite) SchemaVersion() (int, error) {
	var v int
	err := s.db.QueryRow(`select coalesce(max(version), 0) from schema_migrations`).Scan(&v)
	return v, err
}

// backupTo writes a complete, consistent copy of the database to dst
// through SQLite itself (VACUUM INTO), so rows that live only in the
// write-ahead log after an unclean stop are in the backup too — a file
// copy of state.db alone would miss them.
func (s *SQLite) backupTo(dst string) error {
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("%s already exists", dst)
	}
	if _, err := s.db.Exec(`vacuum into ?`, dst); err != nil {
		return err
	}
	return os.Chmod(dst, 0o600)
}

// Close closes the database.
func (s *SQLite) Close() error { return s.db.Close() }

const timeLayout = time.RFC3339Nano

func fmtTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(timeLayout, s)
	return t
}

func fmtTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return fmtTime(*t)
}

func parseTimePtr(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t := parseTime(s.String)
	return &t
}

func (s *SQLite) PutInstance(in Instance) error {
	licenses := ""
	if in.Licenses != nil {
		raw, err := json.Marshal(in.Licenses)
		if err != nil {
			return err
		}
		licenses = string(raw)
	}
	_, err := s.db.Exec(`insert into instances (name, template, version, profile, mode, source, created, updated, stage, reached, licenses, seed_salt, audit_from)
		values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		on conflict(name) do update set template=excluded.template, version=excluded.version, profile=excluded.profile,
		mode=excluded.mode, source=excluded.source, created=excluded.created, updated=excluded.updated, stage=excluded.stage,
		reached=excluded.reached, licenses=excluded.licenses, seed_salt=excluded.seed_salt, audit_from=excluded.audit_from`,
		in.Name, in.Template, in.Version, in.Profile, string(in.Mode), in.Source, fmtTime(in.Created), fmtTime(in.Updated), string(in.Stage), string(in.Reached), licenses, in.SeedSalt, in.AuditFrom)
	return err
}

// GatewayBackfill reports whether this instance still owes the ui facts
// the gateway routes on. Migration 4 sets it for every instance that
// existed before those columns did; an instance created since carries
// its facts from its create, so the flag is a record of the upgrade, not
// a reading of the data — a service that legitimately declares no ui
// endpoint looks exactly like a row the backfill never reached.
func (s *SQLite) GatewayBackfill(instance string) (bool, error) {
	var pending int
	err := s.db.QueryRow(`select gateway_backfill from instances where name = ?`, instance).Scan(&pending)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}
	return pending == 1, nil
}

// SetGatewayBackfill records whether those facts are still owed: cleared
// once the backfill has published them, so it happens once and never
// re-reads a source that may have changed since.
func (s *SQLite) SetGatewayBackfill(instance string, pending bool) error {
	v := 0
	if pending {
		v = 1
	}
	res, err := s.db.Exec(`update instances set gateway_backfill = ? where name = ?`, v, instance)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	return nil
}

// Unsupported reports why this release does not operate an instance, or
// "" (migration 16). Like the gateway backfill flag it is a record of
// what the engine found, kept apart from the instance's own columns:
// PutInstance never writes it, so no write of the instance can clear it.
func (s *SQLite) Unsupported(instance string) (string, error) {
	var reason string
	err := s.db.QueryRow(`select unsupported from instances where name = ?`, instance).Scan(&reason)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return reason, err
}

// MarkUnsupported records why this release does not operate an instance.
func (s *SQLite) MarkUnsupported(instance, reason string) error {
	res, err := s.db.Exec(`update instances set unsupported = ? where name = ?`, reason, instance)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanInstance(row interface{ Scan(...any) error }) (*Instance, error) {
	var in Instance
	var mode, stage, reached, created, updated, licenses string
	if err := row.Scan(&in.Name, &in.Template, &in.Version, &in.Profile, &mode, &in.Source, &created, &updated, &stage, &reached, &licenses, &in.SeedSalt, &in.AuditFrom); err != nil {
		return nil, err
	}
	in.Mode, in.Stage, in.Reached = Mode(mode), Stage(stage), Stage(reached)
	in.Created, in.Updated = parseTime(created), parseTime(updated)
	if licenses != "" {
		if err := json.Unmarshal([]byte(licenses), &in.Licenses); err != nil {
			return nil, fmt.Errorf("instance %s: licenses column: %w", in.Name, err)
		}
	}
	return &in, nil
}

const instanceCols = `name, template, version, profile, mode, source, created, updated, stage, reached, licenses, seed_salt, audit_from`

func (s *SQLite) GetInstance(name string) (*Instance, error) {
	in, err := scanInstance(s.db.QueryRow(`select `+instanceCols+` from instances where name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return in, err
}

func (s *SQLite) ListInstances() ([]Instance, error) {
	rows, err := s.db.Query(`select ` + instanceCols + ` from instances order by name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Instance
	for rows.Next() {
		in, err := scanInstance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *in)
	}
	return out, rows.Err()
}

// requireInstance refuses a row for an instance the store does not hold
// (ErrNotFound): a result or progress row never outlives, or precedes, its
// instance — the store's own wall behind the engine's guard.
func (s *SQLite) requireInstance(name string) error {
	var n int
	if err := s.db.QueryRow(`select count(*) from instances where name = ?`, name).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) DeleteInstance(name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, stmt := range []string{
		`delete from services where instance = ?`,
		`delete from checkpoint_results where instance = ?`,
		`delete from progress where instance = ?`,
		`delete from generated_secrets where instance = ?`,
		// An attendee credential names one instance and nothing else: it
		// goes with it, so a destroyed lab leaves no link that could be
		// joined (API §2.4, plan S9).
		`delete from access where instance = ?`,
		// And so does a session that link already opened. Nothing
		// re-checks the instance when a session is resolved — it is bound
		// by name — so a cookie left behind would have been valid against
		// the *next* lab of that name, reveals included, for the rest of
		// its idle window. Destroying the link without the sessions it
		// opened left the door it was meant to close.
		`delete from sessions where instance = ?`,
		`delete from instances where name = ?`,
	} {
		if _, err := tx.Exec(stmt, name); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLite) GeneratedSecrets(instance string) ([]string, error) {
	rows, err := s.db.Query(`select name from generated_secrets where instance = ? order by name`, instance)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// beforeAddGeneratedSecrets is a test seam: it runs before the history
// transaction begins, where a destroy may commit meanwhile.
var beforeAddGeneratedSecrets func()

// AddGeneratedSecrets adds names to an instance's history inside one
// transaction that also decides whether the instance exists: each insert
// is conditional on the instance row in the same statement, and the
// existence check reads under the write lock the first insert took, so a
// destroy committing between check and insert — a synchronous checkpoint
// remembering its secrets outside the instance guard while the instance
// goes — cannot leave orphaned history for a re-created name to inherit.
// ErrNotFound when the instance is gone.
func (s *SQLite) AddGeneratedSecrets(instance string, names []string) error {
	if beforeAddGeneratedSecrets != nil {
		beforeAddGeneratedSecrets()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, n := range names {
		if _, err := tx.Exec(`insert into generated_secrets (instance, name)
			select ?, ? where exists (select 1 from instances where name = ?)
			on conflict(instance, name) do nothing`, instance, n, instance); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	var present int
	if err := tx.QueryRow(`select count(*) from instances where name = ?`, instance).Scan(&present); err != nil {
		_ = tx.Rollback()
		return err
	}
	if present == 0 {
		_ = tx.Rollback()
		return ErrNotFound
	}
	return tx.Commit()
}

func (s *SQLite) PutCheckpointResult(r CheckpointResult) error {
	if err := s.requireInstance(r.Instance); err != nil {
		return err
	}
	_, err := s.db.Exec(`insert into checkpoint_results (instance, id, class, adapter, status, at, duration, job, evidence, observed, expected, message, hint, error, definition)
		values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		on conflict(instance, id) do update set class=excluded.class, adapter=excluded.adapter, status=excluded.status, at=excluded.at,
		duration=excluded.duration, job=excluded.job, evidence=excluded.evidence, observed=excluded.observed, expected=excluded.expected,
		message=excluded.message, hint=excluded.hint, error=excluded.error, definition=excluded.definition`,
		r.Instance, r.ID, r.Class, r.Adapter, r.Status, fmtTime(r.At), r.Duration, r.Job, r.Evidence, string(r.Observed), string(r.Expected), r.Message, r.Hint, envelopeText(r.Error), r.Definition)
	return err
}

func (s *SQLite) ListCheckpointResults(instance string) ([]CheckpointResult, error) {
	rows, err := s.db.Query(`select instance, id, class, adapter, status, at, duration, job, evidence, observed, expected, message, hint, error, definition
		from checkpoint_results where instance = ? order by id`, instance)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckpointResult
	for rows.Next() {
		var r CheckpointResult
		var at, observed, expected, errText string
		if err := rows.Scan(&r.Instance, &r.ID, &r.Class, &r.Adapter, &r.Status, &at, &r.Duration, &r.Job, &r.Evidence, &observed, &expected, &r.Message, &r.Hint, &errText, &r.Definition); err != nil {
			return nil, err
		}
		r.At = parseTime(at)
		if observed != "" {
			r.Observed = json.RawMessage(observed)
		}
		if expected != "" {
			r.Expected = json.RawMessage(expected)
		}
		if errText != "" {
			var pe pdr.Error
			if err := json.Unmarshal([]byte(errText), &pe); err != nil {
				return nil, fmt.Errorf("checkpoint result %s/%s: error envelope: %w", instance, r.ID, err)
			}
			r.Error = &pe
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLite) DeleteCheckpointResults(instance, class string) error {
	var err error
	if class == "" {
		_, err = s.db.Exec(`delete from checkpoint_results where instance = ?`, instance)
	} else {
		_, err = s.db.Exec(`delete from checkpoint_results where instance = ? and class = ?`, instance, class)
	}
	return err
}

func (s *SQLite) PutProgress(p Progress) error {
	steps := p.Steps
	if steps == nil {
		steps = map[string]StepProgress{}
	}
	raw, err := json.Marshal(steps)
	if err != nil {
		return err
	}
	if err := s.requireInstance(p.Instance); err != nil {
		return err
	}
	_, err = s.db.Exec(`insert into progress (instance, playbook, current_step, steps, updated) values (?, ?, ?, ?, ?)
		on conflict(instance, playbook) do update set current_step=excluded.current_step, steps=excluded.steps, updated=excluded.updated`,
		p.Instance, p.Playbook, p.CurrentStep, string(raw), fmtTime(p.Updated))
	return err
}

func (s *SQLite) GetProgress(instance, playbook string) (*Progress, error) {
	var p Progress
	var steps, updated string
	err := s.db.QueryRow(`select instance, playbook, current_step, steps, updated from progress where instance = ? and playbook = ?`, instance, playbook).
		Scan(&p.Instance, &p.Playbook, &p.CurrentStep, &steps, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Updated = parseTime(updated)
	p.Steps = map[string]StepProgress{}
	if err := json.Unmarshal([]byte(steps), &p.Steps); err != nil {
		return nil, fmt.Errorf("progress %s/%s: steps column: %w", instance, playbook, err)
	}
	return &p, nil
}

func (s *SQLite) DeleteProgress(instance string) error {
	_, err := s.db.Exec(`delete from progress where instance = ?`, instance)
	return err
}

func (s *SQLite) PutService(svc Service) error {
	ports, _ := json.Marshal(svc.Ports)
	if svc.Ports == nil {
		ports = []byte("{}")
	}
	_, err := s.db.Exec(`insert into services (instance, name, module, ran_module, image, ran_image, container, container_id, stage, ports, typical, budget, started_at, healthy_at, readiness, error, ui_port, ui_scheme, embed)
		values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		on conflict(instance, name) do update set module=excluded.module, ran_module=excluded.ran_module, image=excluded.image, ran_image=excluded.ran_image, container=excluded.container,
		container_id=excluded.container_id, stage=excluded.stage, ports=excluded.ports, typical=excluded.typical, budget=excluded.budget,
		started_at=excluded.started_at, healthy_at=excluded.healthy_at, readiness=excluded.readiness, error=excluded.error,
		ui_port=excluded.ui_port, ui_scheme=excluded.ui_scheme, embed=excluded.embed`,
		svc.Instance, svc.Name, svc.Module, svc.RanModule, svc.Image, svc.RanImage, svc.Container, svc.ContainerID, string(svc.Stage), string(ports),
		svc.Typical, svc.Budget, fmtTimePtr(svc.StartedAt), fmtTimePtr(svc.HealthyAt), svc.Readiness, svc.Error, svc.UIPort, svc.UIScheme, svc.Embed)
	return err
}

func (s *SQLite) ListServices(instance string) ([]Service, error) {
	rows, err := s.db.Query(`select instance, name, module, ran_module, image, ran_image, container, container_id, stage, ports, typical, budget, started_at, healthy_at, readiness, error, ui_port, ui_scheme, embed
		from services where instance = ? order by name`, instance)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Service
	for rows.Next() {
		var svc Service
		var stage, ports string
		var started, healthy sql.NullString
		if err := rows.Scan(&svc.Instance, &svc.Name, &svc.Module, &svc.RanModule, &svc.Image, &svc.RanImage, &svc.Container, &svc.ContainerID, &stage, &ports, &svc.Typical, &svc.Budget, &started, &healthy, &svc.Readiness, &svc.Error, &svc.UIPort, &svc.UIScheme, &svc.Embed); err != nil {
			return nil, err
		}
		svc.Stage = Stage(stage)
		_ = json.Unmarshal([]byte(ports), &svc.Ports)
		if len(svc.Ports) == 0 {
			svc.Ports = nil
		}
		svc.StartedAt, svc.HealthyAt = parseTimePtr(started), parseTimePtr(healthy)
		out = append(out, svc)
	}
	return out, rows.Err()
}

func (s *SQLite) DeleteService(instance, name string) error {
	_, err := s.db.Exec(`delete from services where instance = ? and name = ?`, instance, name)
	return err
}

func (s *SQLite) PutJob(j Job) error {
	_, err := s.db.Exec(`insert into jobs (id, kind, instance, state, stage, started, finished, error, target, gen, seq)
		values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, (select coalesce(max(seq), 0) + 1 from jobs))
		on conflict(id) do update set kind=excluded.kind, instance=excluded.instance, state=excluded.state, stage=excluded.stage,
		started=excluded.started, finished=excluded.finished, error=excluded.error, target=excluded.target, gen=excluded.gen`,
		j.ID, j.Kind, j.Instance, string(j.State), j.Stage, fmtTime(j.Started), fmtTimePtr(j.Finished), envelopeText(j.Error), j.Target, j.Gen)
	return err
}

// envelopeText is the error column: the envelope's JSON, or empty.
func envelopeText(pe *pdr.Error) string {
	if pe == nil {
		return ""
	}
	raw, _ := json.Marshal(pe)
	return string(raw)
}

const jobCols = `id, kind, instance, state, stage, started, finished, error, target, gen`

func scanJob(row interface{ Scan(...any) error }) (*Job, error) {
	var j Job
	var errText string
	var st, started string
	var finished sql.NullString
	if err := row.Scan(&j.ID, &j.Kind, &j.Instance, &st, &j.Stage, &started, &finished, &errText, &j.Target, &j.Gen); err != nil {
		return nil, err
	}
	j.State = JobState(st)
	j.Started = parseTime(started)
	j.Finished = parseTimePtr(finished)
	if errText != "" {
		var pe pdr.Error
		if err := json.Unmarshal([]byte(errText), &pe); err != nil {
			return nil, fmt.Errorf("job %s: error envelope: %w", j.ID, err)
		}
		j.Error = &pe
	}
	return &j, nil
}

func (s *SQLite) GetJob(id string) (*Job, error) {
	j, err := scanJob(s.db.QueryRow(`select `+jobCols+` from jobs where id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return j, err
}

func (s *SQLite) ListJobs(instance string) ([]Job, error) {
	var rows *sql.Rows
	var err error
	if instance == "" {
		rows, err = s.db.Query(`select ` + jobCols + ` from jobs order by seq desc`)
	} else {
		rows, err = s.db.Query(`select `+jobCols+` from jobs where instance = ? order by seq desc`, instance)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *j)
	}
	return out, rows.Err()
}

func (s *SQLite) ActiveJob(instance string) (*Job, error) {
	j, err := scanJob(s.db.QueryRow(`select `+jobCols+` from jobs where instance = ? and state in ('queued', 'running') order by seq desc limit 1`, instance))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return j, err
}

func (s *SQLite) AppendEvent(e Event) error {
	_, err := s.db.Exec(`insert into events (job, at, step, service, status, detail) values (?, ?, ?, ?, ?, ?)`,
		e.Job, fmtTime(e.At), e.Step, e.Service, e.Status, e.Detail)
	return err
}

func (s *SQLite) ListEvents(job string) ([]Event, error) {
	rows, err := s.db.Query(`select seq, job, at, step, service, status, detail from events where job = ? order by seq`, job)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var at string
		if err := rows.Scan(&e.Seq, &e.Job, &at, &e.Step, &e.Service, &e.Status, &e.Detail); err != nil {
			return nil, err
		}
		e.At = parseTime(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLite) PutSession(sess Session) error {
	_, err := s.db.Exec(`insert into sessions (id, subject, mechanism, instance, csrf, created, last_seen, expires, gen)
		values (?, ?, ?, ?, ?, ?, ?, ?, ?)
		on conflict(id) do update set subject=excluded.subject, mechanism=excluded.mechanism, instance=excluded.instance,
		csrf=excluded.csrf, created=excluded.created, last_seen=excluded.last_seen, expires=excluded.expires, gen=excluded.gen`,
		sess.ID, sess.Subject, sess.Mechanism, sess.Instance, sess.CSRF, fmtTime(sess.Created), fmtTime(sess.LastSeen), fmtTime(sess.Expires), sess.Gen)
	return err
}

func (s *SQLite) PutSessionAudited(sess Session, a Audit) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`insert into sessions (id, subject, mechanism, instance, csrf, created, last_seen, expires, gen)
		values (?, ?, ?, ?, ?, ?, ?, ?, ?)
		on conflict(id) do update set subject=excluded.subject, mechanism=excluded.mechanism, instance=excluded.instance,
		csrf=excluded.csrf, created=excluded.created, last_seen=excluded.last_seen, expires=excluded.expires, gen=excluded.gen`,
		sess.ID, sess.Subject, sess.Mechanism, sess.Instance, sess.CSRF, fmtTime(sess.Created), fmtTime(sess.LastSeen), fmtTime(sess.Expires), sess.Gen); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`insert into audit (at, instance, action, actor, mechanism, detail) values (?, ?, ?, ?, ?, ?)`,
		fmtTime(a.At), a.Instance, a.Action, a.Actor, a.Mechanism, a.Detail); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *SQLite) GetSession(id string) (*Session, error) {
	var sess Session
	var created, seen, expires string
	err := s.db.QueryRow(`select id, subject, mechanism, instance, csrf, created, last_seen, expires, gen from sessions where id = ?`, id).
		Scan(&sess.ID, &sess.Subject, &sess.Mechanism, &sess.Instance, &sess.CSRF, &created, &seen, &expires, &sess.Gen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.Created, sess.LastSeen, sess.Expires = parseTime(created), parseTime(seen), parseTime(expires)
	return &sess, nil
}

func (s *SQLite) TouchSession(id string, lastSeen, expires time.Time) error {
	// An update, never an upsert: a row a sign-out removed stays removed.
	res, err := s.db.Exec(`update sessions set last_seen = ?, expires = ? where id = ?`, fmtTime(lastSeen), fmtTime(expires), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) DeleteSession(id string) error {
	_, err := s.db.Exec(`delete from sessions where id = ?`, id)
	return err
}

func (s *SQLite) DeleteSessionAudited(id string, a Audit) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`delete from sessions where id = ?`, id); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`insert into audit (at, instance, action, actor, mechanism, detail) values (?, ?, ?, ?, ?, ?)`,
		fmtTime(a.At), a.Instance, a.Action, a.Actor, a.Mechanism, a.Detail); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *SQLite) PurgeSessions(t time.Time) (int, error) {
	res, err := s.db.Exec(`delete from sessions where expires <= ?`, fmtTime(t))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *SQLite) PutToken(tok Token) error {
	// One statement, no check-then-insert: the unique indexes on name and
	// hash are the arbiter, so two concurrent creations of the same name
	// cannot both pass a pre-check — the loser's constraint error is the
	// documented conflict (API §2.3: 409), never a raw store error.
	_, err := s.db.Exec(`insert into tokens (id, name, prefix, hash, scope, created, last_used, seq)
		values (?, ?, ?, ?, ?, ?, ?, (select coalesce(max(seq), 0) + 1 from tokens))
		on conflict(id) do update set name=excluded.name, prefix=excluded.prefix, hash=excluded.hash, scope=excluded.scope,
		created=excluded.created, last_used=excluded.last_used`,
		tok.ID, tok.Name, tok.Prefix, tok.Hash, tok.Scope, fmtTime(tok.Created), fmtTimePtr(tok.LastUsed))
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// isUniqueViolation recognizes SQLite's unique-index refusal
// (SQLITE_CONSTRAINT_UNIQUE, which the driver reports by message).
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

const tokenCols = `id, name, prefix, hash, scope, created, last_used`

func scanToken(row interface{ Scan(...any) error }) (*Token, error) {
	var t Token
	var created string
	var used sql.NullString
	if err := row.Scan(&t.ID, &t.Name, &t.Prefix, &t.Hash, &t.Scope, &created, &used); err != nil {
		return nil, err
	}
	t.Created = parseTime(created)
	t.LastUsed = parseTimePtr(used)
	return &t, nil
}

func (s *SQLite) PutTokenAudited(tok Token, a Audit) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`insert into tokens (id, name, prefix, hash, scope, created, last_used, seq)
		values (?, ?, ?, ?, ?, ?, ?, (select coalesce(max(seq), 0) + 1 from tokens))`,
		tok.ID, tok.Name, tok.Prefix, tok.Hash, tok.Scope, fmtTime(tok.Created), fmtTimePtr(tok.LastUsed)); err != nil {
		_ = tx.Rollback()
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	if _, err := tx.Exec(`insert into audit (at, instance, action, actor, mechanism, detail) values (?, ?, ?, ?, ?, ?)`,
		fmtTime(a.At), a.Instance, a.Action, a.Actor, a.Mechanism, a.Detail); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *SQLite) GetTokenByHash(hash string) (*Token, error) {
	t, err := scanToken(s.db.QueryRow(`select `+tokenCols+` from tokens where hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

func (s *SQLite) ListTokens() ([]Token, error) {
	rows, err := s.db.Query(`select ` + tokenCols + ` from tokens order by seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (s *SQLite) TouchToken(id string, lastUsed time.Time) error {
	// An update, never an upsert: a row a revocation removed stays removed.
	res, err := s.db.Exec(`update tokens set last_used = ? where id = ?`, fmtTime(lastUsed), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) DeleteToken(id string) error {
	res, err := s.db.Exec(`delete from tokens where id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) DeleteTokenAudited(id string, a Audit) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	res, err := tx.Exec(`delete from tokens where id = ?`, id)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return ErrNotFound
	}
	if _, err := tx.Exec(`insert into audit (at, instance, action, actor, mechanism, detail) values (?, ?, ?, ?, ?, ?)`,
		fmtTime(a.At), a.Instance, a.Action, a.Actor, a.Mechanism, a.Detail); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *SQLite) AppendAudit(a Audit) error {
	_, err := s.db.Exec(`insert into audit (at, instance, action, actor, mechanism, detail) values (?, ?, ?, ?, ?, ?)`,
		fmtTime(a.At), a.Instance, a.Action, a.Actor, a.Mechanism, a.Detail)
	return err
}

func (s *SQLite) LatestAuditSeq() (int64, error) {
	var seq int64
	if err := s.db.QueryRow(`select coalesce(max(seq), 0) from audit`).Scan(&seq); err != nil {
		return 0, err
	}
	return seq, nil
}

func (s *SQLite) ListAudit(instance string) ([]Audit, error) {
	rows, err := s.db.Query(`select seq, at, instance, action, actor, mechanism, detail from audit where instance = ? order by seq`, instance)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Audit
	for rows.Next() {
		var a Audit
		var at string
		if err := rows.Scan(&a.Seq, &at, &a.Instance, &a.Action, &a.Actor, &a.Mechanism, &a.Detail); err != nil {
			return nil, err
		}
		a.At = parseTime(at)
		out = append(out, a)
	}
	return out, rows.Err()
}

func scanLogin(row interface{ Scan(...any) error }) (*LoginState, error) {
	var ls LoginState
	var last string
	var locked sql.NullString
	if err := row.Scan(&ls.Source, &ls.Failures, &last, &locked); err != nil {
		return nil, err
	}
	if last != "" {
		ls.LastFailure = parseTime(last)
	}
	ls.LockedUntil = parseTimePtr(locked)
	return &ls, nil
}

func (s *SQLite) GetLoginState(source string) (*LoginState, error) {
	ls, err := scanLogin(s.db.QueryRow(`select source, failures, last_failure, locked_until from login_state where source = ?`, source))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return ls, err
}

func (s *SQLite) PutLoginState(ls LoginState) error {
	last := ""
	if !ls.LastFailure.IsZero() {
		last = fmtTime(ls.LastFailure)
	}
	_, err := s.db.Exec(`insert into login_state (source, failures, last_failure, locked_until) values (?, ?, ?, ?)
		on conflict(source) do update set failures=excluded.failures, last_failure=excluded.last_failure, locked_until=excluded.locked_until`,
		ls.Source, ls.Failures, last, fmtTimePtr(ls.LockedUntil))
	return err
}

func (s *SQLite) PutLoginStateAudited(ls LoginState, records ...Audit) error {
	last := ""
	if !ls.LastFailure.IsZero() {
		last = fmtTime(ls.LastFailure)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`insert into login_state (source, failures, last_failure, locked_until) values (?, ?, ?, ?)
		on conflict(source) do update set failures=excluded.failures, last_failure=excluded.last_failure, locked_until=excluded.locked_until`,
		ls.Source, ls.Failures, last, fmtTimePtr(ls.LockedUntil)); err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, a := range records {
		if _, err := tx.Exec(`insert into audit (at, instance, action, actor, mechanism, detail) values (?, ?, ?, ?, ?, ?)`,
			fmtTime(a.At), a.Instance, a.Action, a.Actor, a.Mechanism, a.Detail); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLite) ListLockedSources() ([]LoginState, error) {
	rows, err := s.db.Query(`select source, failures, last_failure, locked_until from login_state where locked_until is not null order by source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LoginState
	for rows.Next() {
		ls, err := scanLogin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ls)
	}
	return out, rows.Err()
}

// --- instance access credentials (API §2.4, plan S9) ------------------

const accessCols = `id, instance, name, prefix, hash, created, expires, last_used, gen`

func scanAccess(row interface{ Scan(...any) error }) (*Access, error) {
	var a Access
	var created, expires string
	var used sql.NullString
	if err := row.Scan(&a.ID, &a.Instance, &a.Name, &a.Prefix, &a.Hash, &created, &expires, &used, &a.Gen); err != nil {
		return nil, err
	}
	a.Created, a.Expires = parseTime(created), parseTime(expires)
	a.LastUsed = parseTimePtr(used)
	return &a, nil
}

func (s *SQLite) PutAccessAudited(a Access, gen int64, rec Audit) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	// The instance is checked by the insert itself rather than before it.
	// A destroy committing between an operator's check and this write
	// would otherwise leave a credential with no lab — joinable by name,
	// and a working attendee credential again the moment an instance of
	// that name is created.
	//
	// The check is on the *generation* the caller read, not on the name:
	// a name that was destroyed and created again between the two passes
	// an existence test, and the link meant for the lab that is gone
	// would open the one that replaced it.
	// `audit_from` is that generation — the audit high-water mark the
	// instance was created at — and it cannot repeat, because a destroy
	// appends its own audit row before the name can be taken again.
	res, err := tx.Exec(`insert into access (id, instance, name, prefix, hash, created, expires, last_used, gen, seq)
		select ?, ?, ?, ?, ?, ?, ?, ?, ?, (select coalesce(max(seq), 0) + 1 from access)
		where exists (select 1 from instances where name = ? and audit_from = ?)`,
		a.ID, a.Instance, a.Name, a.Prefix, a.Hash, fmtTime(a.Created), fmtTime(a.Expires), fmtTimePtr(a.LastUsed), gen, a.Instance, gen)
	if err != nil {
		_ = tx.Rollback()
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return ErrNotFound
	}
	if _, err := tx.Exec(`insert into audit (at, instance, action, actor, mechanism, detail) values (?, ?, ?, ?, ?, ?)`,
		fmtTime(rec.At), rec.Instance, rec.Action, rec.Actor, rec.Mechanism, rec.Detail); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *SQLite) GetAccessByHash(hash string) (*Access, error) {
	a, err := scanAccess(s.db.QueryRow(`select `+accessCols+` from access where hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// JoinAccessAudited records the use, stores the session and appends the
// audit records in one transaction. The update is the guard: if a
// revocation removed the row first, no rows change, nothing is written
// and the caller is told the credential is gone.
func (s *SQLite) JoinAccessAudited(id string, lastUsed time.Time, sess Session, recs ...Audit) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	res, err := tx.Exec(`update access set last_used = ? where id = ?`, fmtTime(lastUsed), id)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return ErrNotFound
	}
	if _, err := tx.Exec(`insert into sessions (id, subject, mechanism, instance, csrf, created, last_seen, expires, gen)
		values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.Subject, sess.Mechanism, sess.Instance, sess.CSRF,
		fmtTime(sess.Created), fmtTime(sess.LastSeen), fmtTime(sess.Expires), sess.Gen); err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, rec := range recs {
		if _, err := tx.Exec(`insert into audit (at, instance, action, actor, mechanism, detail) values (?, ?, ?, ?, ?, ?)`,
			fmtTime(rec.At), rec.Instance, rec.Action, rec.Actor, rec.Mechanism, rec.Detail); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLite) ListAccess(instance string) ([]Access, error) {
	rows, err := s.db.Query(`select `+accessCols+` from access where instance = ? order by seq`, instance)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Access
	for rows.Next() {
		a, err := scanAccess(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (s *SQLite) DeleteAccessAudited(instance, id string, rec Audit) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	res, err := tx.Exec(`delete from access where instance = ? and id = ?`, instance, id)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return ErrNotFound
	}
	if _, err := tx.Exec(`insert into audit (at, instance, action, actor, mechanism, detail) values (?, ?, ?, ?, ?, ?)`,
		fmtTime(rec.At), rec.Instance, rec.Action, rec.Actor, rec.Mechanism, rec.Detail); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// SchemaVersionOf reports the migration a state file stands at, without
// migrating it (INSTALL §6: `system upgrade` reports how many
// migrations a new binary applied, which it can only do by knowing
// where the file stood before). A file that does not exist is version
// zero; one with no migrations table is too.
func SchemaVersionOf(path string) (int, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var v int
	err = db.QueryRow(`select coalesce(max(version), 0) from schema_migrations`).Scan(&v)
	if err != nil {
		// No table yet: a database this engine has never opened.
		return 0, nil
	}
	return v, nil
}

// InstanceRow is what `system upgrade`'s preflight reads of an instance
// before anything is replaced: which template it runs and where its
// ladder stands (INSTALL §6; the reconciliation plan's R3).
type InstanceRow struct {
	Name     string
	Template string
	Stage    Stage
}

// InstanceRowsOf reads a state file's instance rows without migrating it
// and without writing to it. A file that does not exist holds none, and
// so does a database no engine has opened — without the migrations table
// there is no instances table either. Anything else that cannot be read
// is an error, a file that is not a database among them (which
// SchemaVersionOf, asked only for a number, calls version zero), and the
// preflight refuses on it rather than guess what the file holds.
func InstanceRowsOf(path string) ([]InstanceRow, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var migrated int
	if err := db.QueryRow(`select count(*) from sqlite_master where type = 'table' and name = 'schema_migrations'`).Scan(&migrated); err != nil {
		return nil, err
	}
	if migrated == 0 {
		return nil, nil
	}
	rows, err := db.Query(`select name, template, stage from instances order by name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InstanceRow
	for rows.Next() {
		var r InstanceRow
		var stage string
		if err := rows.Scan(&r.Name, &r.Template, &stage); err != nil {
			return nil, err
		}
		r.Stage = Stage(stage)
		out = append(out, r)
	}
	return out, rows.Err()
}

// BackupDatabase writes a consistent copy of a state file to dst, which
// must not exist. It is SQLite's own backup, not a file copy: the store
// runs in WAL mode, so rows committed since the last checkpoint live in
// `state.db-wal` and a copy of the main file alone can be missing them —
// or be torn, since the engine is still writing. `vacuum into` reads
// through the same snapshot machinery a reader uses, so what lands is
// every committed row and nothing half-written.
//
// The source is opened read-only: a rollback backup must never be the
// thing that changes the database it is protecting.
func BackupDatabase(src, dst string) error {
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("%s already exists", dst)
	}
	db, err := sql.Open("sqlite", "file:"+src+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec(`vacuum into ?`, dst); err != nil {
		return err
	}
	return os.Chmod(dst, 0o600)
}

// Migrations is how many migrations this binary carries — what a state
// file is brought forward to.
func Migrations() int { return len(migrationSet()) }
