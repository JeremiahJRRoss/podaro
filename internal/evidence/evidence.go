// SPDX-License-Identifier: AGPL-3.0-only

// Package evidence is an instance's append-only journal (plan S6; API
// §10; threat model B9): checkpoint results, lifecycle milestones, seed
// runs, and audit events, one immutable JSON file per entry under the
// instance's evidence directory — written once, never rewritten, gone
// only with destroy — plus the JUnit rendering of the latest results.
package evidence

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// ErrNotFound reports an entry the journal does not hold.
var ErrNotFound = errors.New("evidence not found")

// Type is an entry's kind (API §10: checkpoint | lifecycle | seed | audit).
type Type string

const (
	TypeCheckpoint Type = "checkpoint"
	TypeLifecycle  Type = "lifecycle"
	TypeSeed       Type = "seed"
	TypeAudit      Type = "audit"
)

// Entry is one journal record. Exactly one of the typed payloads is set.
type Entry struct {
	ID       string    `json:"id"`
	At       time.Time `json:"at"`
	Type     Type      `json:"type"`
	Instance string    `json:"instance"`
	// Authoring flags evidence recorded on an authoring instance (roadmap
	// §3.1): excluded from completion claims.
	Authoring bool   `json:"authoring,omitempty"`
	Job       string `json:"job,omitempty"`

	Checkpoint *state.CheckpointResult `json:"checkpoint,omitempty"`
	Lifecycle  *Lifecycle              `json:"lifecycle,omitempty"`
	Seed       *SeedRun                `json:"seed,omitempty"`
	Audit      *state.Audit            `json:"audit,omitempty"`
}

// Lifecycle is a milestone or a warning: the stage reached, a create's
// verdict, PDR-W101.
type Lifecycle struct {
	Event  string `json:"event"`
	Stage  string `json:"stage,omitempty"`
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// SeedRun is one seed's run: what was sent, deterministically.
type SeedRun struct {
	Name      string     `json:"name"`
	Generator string     `json:"generator"`
	Kind      string     `json:"kind"`
	Count     int        `json:"count,omitempty"`
	Sent      any        `json:"sent,omitempty"`
	SeedValue string     `json:"seed_value"`
	Duration  string     `json:"duration"`
	Message   string     `json:"message,omitempty"`
	Image     string     `json:"image,omitempty"`
	Secrets   []string   `json:"secrets,omitempty"`
	Error     *pdr.Error `json:"error,omitempty"`
}

// Journal is one instance's evidence directory.
type Journal struct {
	dir string
	mu  sync.Mutex
	// last is the previous id's time and random part, so ids stay
	// monotonic within one process even inside one millisecond — and
	// whatever the clock does: a clock that moved back keeps the last
	// millisecond and counts on.
	lastMillis int64
	lastRand   [10]byte
	// seeded reports that lastMillis was read from the newest entry on
	// disk once, so a journal reopened under a clock that moved back
	// continues after what it holds rather than before it.
	seeded bool
}

// Open addresses an instance's evidence directory (created on the first
// append).
func Open(dir string) *Journal { return &Journal{dir: dir} }

// Dir is the journal's directory.
func (j *Journal) Dir() string { return j.dir }

// Append records one entry, assigning its id and time when unset. The
// file is written whole to a temporary name, synced, and renamed into
// place, so the journal never holds a partial entry.
func (j *Journal) Append(e Entry) (Entry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	e.At = e.At.UTC()
	if e.ID == "" {
		j.seed()
		e.ID = j.newID(e.At)
	}
	if err := os.MkdirAll(j.dir, 0o700); err != nil {
		return e, err
	}
	raw, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return e, err
	}
	tmp, err := os.CreateTemp(j.dir, ".tmp-")
	if err != nil {
		return e, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return e, err
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return e, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return e, err
	}
	if err := tmp.Close(); err != nil {
		return e, err
	}
	final := filepath.Join(j.dir, e.ID+".json")
	if _, err := os.Lstat(final); err == nil {
		return e, fmt.Errorf("evidence %s already exists — the journal is append-only", e.ID)
	}
	if err := os.Rename(tmp.Name(), final); err != nil {
		return e, err
	}
	if d, err := os.Open(j.dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return e, nil
}

// crockford is the base32 alphabet ULIDs use: sortable as text.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// seed reads the newest id on disk once, so the next id follows it
// even when the clock has moved back since it was written: the listing
// sorts by id and the API defines that order as the append order (API
// §10), so no entry may ever sort before what was appended earlier.
func (j *Journal) seed() {
	if j.seeded {
		return
	}
	j.seeded = true
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return
	}
	newest := ""
	for _, en := range entries {
		name := en.Name()
		if strings.HasPrefix(name, "ev_") && strings.HasSuffix(name, ".json") && name > newest {
			newest = name
		}
	}
	if newest == "" {
		return
	}
	raw, ok := decodeBase32(strings.TrimSuffix(strings.TrimPrefix(newest, "ev_"), ".json"))
	if !ok {
		return
	}
	ms := int64(binary.BigEndian.Uint64(raw[:8]) >> 16)
	if ms >= j.lastMillis {
		// The sequence continues after the newest id: its millisecond and
		// its random part, which the next id increments.
		j.lastMillis = ms
		copy(j.lastRand[:], raw[6:])
	}
}

// idMillis reads the 48-bit millisecond prefix of a ULID-shaped id.
func idMillis(id string) (int64, bool) {
	raw, ok := decodeBase32(id)
	if !ok {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(raw[:8]) >> 16), true
}

// decodeBase32 reads 26 Crockford characters back into 128 bits — the
// inverse of encodeBase32 (the first character holds the top 3 bits).
func decodeBase32(s string) ([16]byte, bool) {
	var out [16]byte
	if len(s) != 26 {
		return out, false
	}
	var acc uint64
	bits := 0
	pos := 15
	for i := 25; i >= 0; i-- {
		v := strings.IndexByte(crockford, s[i])
		if v < 0 {
			return out, false
		}
		acc |= uint64(v) << bits
		bits += 5
		for bits >= 8 && pos >= 0 {
			out[pos] = byte(acc)
			acc >>= 8
			bits -= 8
			pos--
		}
	}
	return out, true
}

// newID makes a ULID-shaped id (`ev_` + 26 characters): 48 bits of
// milliseconds then 80 bits that are random for a new millisecond and
// incremented within one, so ids sort by time and creation order. A
// clock that stands still or moves back is the same case as the same
// millisecond: the id keeps the last millisecond and counts on, so the
// order of ids is the order of appends whatever the clock did.
func (j *Journal) newID(at time.Time) string {
	ms := at.UnixMilli()
	if ms <= j.lastMillis {
		ms = j.lastMillis
		for i := len(j.lastRand) - 1; i >= 0; i-- {
			j.lastRand[i]++
			if j.lastRand[i] != 0 {
				break
			}
		}
	} else {
		j.lastMillis = ms
		_, _ = rand.Read(j.lastRand[:])
	}
	var raw [16]byte
	binary.BigEndian.PutUint64(raw[:8], uint64(ms)<<16)
	copy(raw[6:], j.lastRand[:])
	return "ev_" + encodeBase32(raw)
}

// encodeBase32 renders 128 bits as 26 Crockford characters (ULID layout).
func encodeBase32(b [16]byte) string {
	var out [26]byte
	// The first character holds the top 3 bits, then 5 bits each.
	var acc uint64
	bits := 0
	pos := 25
	for i := len(b) - 1; i >= 0; i-- {
		acc |= uint64(b[i]) << bits
		bits += 8
		for bits >= 5 && pos >= 0 {
			out[pos] = crockford[acc&31]
			acc >>= 5
			bits -= 5
			pos--
		}
	}
	for pos >= 0 {
		out[pos] = crockford[acc&31]
		acc >>= 5
		pos--
	}
	return string(out[:])
}

// Filter narrows a listing.
type Filter struct {
	Type Type
	// Since keeps entries at or after the instant.
	Since time.Time
	// Job keeps entries of one job.
	Job string
	// Checkpoint keeps checkpoint entries of one id.
	Checkpoint string
}

// List returns the journal's entries in id order, filtered.
func (j *Journal) List(f Filter) ([]Entry, error) {
	entries, err := os.ReadDir(j.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, en := range entries {
		if !en.IsDir() && strings.HasPrefix(en.Name(), "ev_") && strings.HasSuffix(en.Name(), ".json") {
			names = append(names, en.Name())
		}
	}
	sort.Strings(names)
	out := []Entry{}
	for _, n := range names {
		e, err := j.read(filepath.Join(j.dir, n))
		if err != nil {
			return nil, err
		}
		if f.Type != "" && e.Type != f.Type {
			continue
		}
		if !f.Since.IsZero() && e.At.Before(f.Since) {
			continue
		}
		if f.Job != "" && e.Job != f.Job {
			continue
		}
		if f.Checkpoint != "" && (e.Checkpoint == nil || e.Checkpoint.ID != f.Checkpoint) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// Get returns one entry by id.
func (j *Journal) Get(id string) (*Entry, error) {
	if !strings.HasPrefix(id, "ev_") || strings.ContainsAny(id, "/\\.") {
		return nil, ErrNotFound
	}
	e, err := j.read(filepath.Join(j.dir, id+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (j *Journal) read(path string) (Entry, error) {
	var e Entry
	raw, err := os.ReadFile(path)
	if err != nil {
		return e, err
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return e, fmt.Errorf("evidence %s: %w", filepath.Base(path), err)
	}
	return e, nil
}

// --- JUnit ---------------------------------------------------------------

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Errors   int          `xml:"errors,attr"`
	Skipped  int          `xml:"skipped,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name      string      `xml:"name,attr"`
	Tests     int         `xml:"tests,attr"`
	Failures  int         `xml:"failures,attr"`
	Errors    int         `xml:"errors,attr"`
	Skipped   int         `xml:"skipped,attr"`
	Timestamp string      `xml:"timestamp,attr,omitempty"`
	Cases     []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitMessage `xml:"failure,omitempty"`
	Error     *junitMessage `xml:"error,omitempty"`
	Skipped   *junitMessage `xml:"skipped,omitempty"`
	SystemOut string        `xml:"system-out,omitempty"`
}

type junitMessage struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr,omitempty"`
	Body    string `xml:",chardata"`
}

// JUnit renders the latest results as JUnit XML (API §10): one suite per
// class, one case per checkpoint. A fail is a <failure> carrying the
// hint; an error an <error> carrying the anatomy; an attested result is
// <skipped> — a human claim is never laundered into a machine pass (UX
// §6); pending results (never run) are skipped too. Values never appear:
// observed and expected travel as JSON in system-out only when the result
// recorded them, and results are recorded redaction-filtered.
func JUnit(instance, template string, results []state.CheckpointResult) []byte {
	byClass := map[string][]state.CheckpointResult{}
	for _, r := range results {
		byClass[r.Class] = append(byClass[r.Class], r)
	}
	suites := junitSuites{Name: instance + " · " + template}
	for _, class := range []string{"baseline", "objective"} {
		list := byClass[class]
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		suite := junitSuite{Name: class}
		var latest time.Time
		for _, r := range list {
			if r.At.After(latest) {
				latest = r.At
			}
			c := junitCase{Name: r.ID, ClassName: class + "." + r.Adapter, Time: seconds(r.Duration)}
			var out []string
			if len(r.Observed) > 0 {
				out = append(out, "observed: "+string(r.Observed))
			}
			if len(r.Expected) > 0 {
				out = append(out, "expected: "+string(r.Expected))
			}
			if r.Message != "" {
				out = append(out, r.Message)
			}
			c.SystemOut = strings.Join(out, "\n")
			switch r.Status {
			case "pass":
			case "fail":
				suite.Failures++
				c.Failure = &junitMessage{Message: firstLine(r.Message, "assertion failed"), Type: "fail", Body: r.Hint}
			case "error":
				suite.Errors++
				msg := "checkpoint could not be evaluated"
				body := ""
				if r.Error != nil {
					msg = r.Error.Code + " " + r.Error.Message
					body = strings.TrimSpace("cause: " + r.Error.Cause + "\nnext: " + r.Error.Next)
				}
				c.Error = &junitMessage{Message: msg, Type: "error", Body: body}
			case "attested":
				suite.Skipped++
				c.Skipped = &junitMessage{Message: "◇ attested — self-verified by a human, never a machine pass"}
			default:
				suite.Skipped++
				c.Skipped = &junitMessage{Message: "not evaluated"}
			}
			suite.Tests++
			suite.Cases = append(suite.Cases, c)
		}
		if !latest.IsZero() {
			suite.Timestamp = latest.UTC().Format(time.RFC3339)
		}
		suites.Tests += suite.Tests
		suites.Failures += suite.Failures
		suites.Errors += suite.Errors
		suites.Skipped += suite.Skipped
		suites.Suites = append(suites.Suites, suite)
	}
	raw, _ := xml.MarshalIndent(suites, "", "  ")
	return append([]byte(xml.Header), append(raw, '\n')...)
}

func seconds(d string) string {
	dur, err := time.ParseDuration(d)
	if err != nil {
		return "0"
	}
	return fmt.Sprintf("%.3f", dur.Seconds())
}

func firstLine(s, fallback string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
