// SPDX-License-Identifier: AGPL-3.0-only

// Package secrets is the per-instance secrets store (plan S6; spec 0003
// §6; roadmap invariant 6): values are generated at create to the kind's
// policy, live in 0600 files under the instance directory and nowhere
// else, are rendered into container configuration engine-side, and are
// revealed only through the audited console action. Everything that
// leaves the engine as text passes a Redactor built from them (threat
// model B9).
package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ErrNotFound reports a secret the store does not hold.
var ErrNotFound = errors.New("secret not found")

// Kinds (spec 0003 §6): password (generated to engine policy), token
// (opaque 256-bit), uuid.
const (
	KindPassword = "password"
	KindToken    = "token"
	KindUUID     = "uuid"
)

// passwordAlphabet leaves out the characters that read alike (0/O, 1/l/I)
// — a revealed credential is typed by a human at a product's login.
const passwordAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// PasswordLength is the engine's password policy: 24 characters of the
// alphabet, about 140 bits.
const PasswordLength = 24

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Generate produces a value of the kind.
func Generate(kind string) (string, error) {
	switch kind {
	case KindPassword, "":
		var b strings.Builder
		for b.Len() < PasswordLength {
			var raw [32]byte
			if _, err := rand.Read(raw[:]); err != nil {
				return "", err
			}
			for _, x := range raw {
				// Reject beyond the largest multiple of the alphabet so every
				// character is equally likely.
				if int(x) >= 256-256%len(passwordAlphabet) {
					continue
				}
				b.WriteByte(passwordAlphabet[int(x)%len(passwordAlphabet)])
				if b.Len() == PasswordLength {
					break
				}
			}
		}
		return b.String(), nil
	case KindToken:
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return "", err
		}
		return hex.EncodeToString(raw[:]), nil
	case KindUUID:
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return "", err
		}
		raw[6] = (raw[6] & 0x0f) | 0x40 // version 4
		raw[8] = (raw[8] & 0x3f) | 0x80 // variant
		h := hex.EncodeToString(raw[:])
		return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
	}
	return "", fmt.Errorf("unknown secret kind %q", kind)
}

// Store holds one instance's secret files: <dir>/<name>, 0600, the
// directory 0700.
type Store struct {
	dir string
}

// NewStore addresses an instance's secrets directory (it need not exist).
func NewStore(dir string) *Store { return &Store{dir: dir} }

// Dir is the store's directory.
func (s *Store) Dir() string { return s.dir }

// Path is where a secret's value lives — what a run mounts (Spec 0002 §2).
func (s *Store) Path(name string) string { return filepath.Join(s.dir, name) }

// KindError reports a declaration whose kind changed after the value was
// generated. Values are kept across resets
// by design, so the kind on record is what the containers were configured
// with; a kind change means a new instance, not a silent mismatch.
type KindError struct {
	Name, Generated, Declared string
}

func (e *KindError) Error() string {
	return fmt.Sprintf("secret %s was generated as a %s; the declaration now says %s", e.Name, e.Generated, e.Declared)
}

// kindPath is the record of a secret's kind: a dotfile beside the value,
// which Names skips (a DNS label never starts with a dot).
func (s *Store) kindPath(name string) string { return filepath.Join(s.dir, "."+name+".kind") }

// Kind reports the kind a secret was generated as; ErrNotFound when it
// was never generated, or predates the record.
func (s *Store) Kind(name string) (string, error) {
	if !nameRe.MatchString(name) {
		return "", ErrNotFound
	}
	raw, err := os.ReadFile(s.kindPath(name))
	if errors.Is(err, fs.ErrNotExist) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// Ensure generates the secret once: an existing value is kept (a resumed
// create keeps the credentials its containers were configured with) and
// its recorded kind must equal the declared one — a value from before
// kinds were recorded adopts the declaration; a missing value is
// generated to the kind, its kind recorded, and both written 0600 through
// temporary files. created reports whether a value was made.
func (s *Store) Ensure(name, kind string) (created bool, err error) {
	if !nameRe.MatchString(name) {
		return false, fmt.Errorf("secret name %q is not a DNS label", name)
	}
	if _, err := s.Value(name); err == nil {
		have, kerr := s.Kind(name)
		switch {
		case errors.Is(kerr, ErrNotFound):
			return false, s.writeFile(s.kindPath(name), kind)
		case kerr != nil:
			return false, kerr
		case have != kind:
			return false, &KindError{Name: name, Generated: have, Declared: kind}
		}
		return false, nil
	} else if !errors.Is(err, ErrNotFound) {
		return false, err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return false, err
	}
	_ = os.Chmod(s.dir, 0o700)
	value, err := Generate(kind)
	if err != nil {
		return false, err
	}
	// The kind first: a crash between the two leaves a record without a
	// value, which the next Ensure regenerates and re-records.
	if err := s.writeFile(s.kindPath(name), kind); err != nil {
		return false, err
	}
	if err := s.writeFile(s.Path(name), value); err != nil {
		return false, err
	}
	return true, nil
}

// writeFile lands content at path atomically: a 0600 temporary file in the
// store, synced, renamed into place, the directory synced.
func (s *Store) writeFile(path, content string) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if d, err := os.Open(s.dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// Value reads a secret's value; ErrNotFound when it was never generated.
func (s *Store) Value(name string) (string, error) {
	if !nameRe.MatchString(name) {
		return "", ErrNotFound
	}
	raw, err := os.ReadFile(s.Path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// Names lists the secrets the store holds, sorted.
func (s *Store) Names() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && nameRe.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// Recorded lists the secrets the store keeps a kind record for — every
// secret generated here, whether or not its value is still present: a
// value file deleted leaves its record, so the redaction filter can tell
// a value it lost from one that never was.
func (s *Store) Recorded() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".kind") {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(n, "."), ".kind")
		if nameRe.MatchString(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// Values reads every secret the store holds — for rendering and for the
// redactor, never for output.
func (s *Store) Values() (map[string]string, error) {
	names, err := s.Names()
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(names))
	for _, n := range names {
		v, err := s.Value(n)
		if err != nil {
			return nil, err
		}
		out[n] = v
	}
	return out, nil
}

// Remove deletes every secret (destroy).
func (s *Store) Remove() error {
	return os.RemoveAll(s.dir)
}

var secretRef = regexp.MustCompile(`\$\{secret:([^}]*)\}`)

// Render replaces every ${secret:<name>} in s with the value; a reference
// to a secret the values do not hold is an error (validation resolved it,
// so this is a store that lost a file).
func Render(s string, values map[string]string) (string, error) {
	var missing []string
	out := secretRef.ReplaceAllStringFunc(s, func(m string) string {
		name := secretRef.FindStringSubmatch(m)[1]
		v, ok := values[name]
		if !ok {
			missing = append(missing, name)
			return m
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("secret %s has no value in the instance store", strings.Join(missing, ", "))
	}
	return out, nil
}

// Redactor replaces secret values in text with [redacted:<name>] — the
// filter every log line, journal detail, evidence field, and export
// passes (threat model B9, B10). Longer values are replaced first so a
// value that contains another is not half-redacted.
type Redactor struct {
	pairs []pair
}

type pair struct{ name, value string }

// MinRedactLength is the shortest value the redactor looks for: anything
// shorter would match ordinary text; every generated kind is longer.
const MinRedactLength = 6

// NewRedactor builds a filter for the values (name → value).
func NewRedactor(values map[string]string) *Redactor {
	r := &Redactor{}
	for name, v := range values {
		if len(v) >= MinRedactLength {
			r.pairs = append(r.pairs, pair{name, v})
		}
	}
	sort.Slice(r.pairs, func(i, j int) bool {
		if len(r.pairs[i].value) != len(r.pairs[j].value) {
			return len(r.pairs[i].value) > len(r.pairs[j].value)
		}
		return r.pairs[i].name < r.pairs[j].name
	})
	return r
}

// Redact filters one string.
func (r *Redactor) Redact(s string) string {
	if r == nil {
		return s
	}
	for _, p := range r.pairs {
		if strings.Contains(s, p.value) {
			s = strings.ReplaceAll(s, p.value, "[redacted:"+p.name+"]")
		}
	}
	return s
}

// TrimPartial drops from the end of b the fragment of a value that a cut
// left behind: a stream the cap cut may end with the first bytes of a
// secret — too few for the filter to recognise, enough to leak. Only a
// prefix of a value can end a cut stream, so prefixes are what it looks
// for.
func (r *Redactor) TrimPartial(b []byte) []byte {
	if r == nil {
		return b
	}
	for changed := true; changed; {
		changed = false
		for _, p := range r.pairs {
			for k := len(p.value) - 1; k >= 1; k-- {
				if k <= len(b) && bytes.HasSuffix(b, []byte(p.value[:k])) {
					b = b[:len(b)-k]
					changed = true
					break
				}
			}
		}
	}
	return b
}

// RedactBytes filters a byte slice.
func (r *Redactor) RedactBytes(b []byte) []byte {
	if r == nil || len(r.pairs) == 0 {
		return b
	}
	return []byte(r.Redact(string(b)))
}

// RedactValue filters a decoded JSON value recursively — strings, string
// slices and maps, []any and map[string]any as encoding/json produces
// them, and raw JSON — so a value an extension returned (a verdict's
// observed, a capture, a seed's sent counts) can be stored whatever its
// shape. Numbers, booleans and nulls pass through.
func (r *Redactor) RedactValue(v any) any {
	if r == nil || len(r.pairs) == 0 {
		return v
	}
	switch t := v.(type) {
	case string:
		return r.Redact(t)
	case []string:
		out := make([]string, len(t))
		for i, s := range t {
			out[i] = r.Redact(s)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(t))
		for k, s := range t {
			out[r.Redact(k)] = r.Redact(s)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = r.RedactValue(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[r.Redact(k)] = r.RedactValue(e)
		}
		return out
	case json.RawMessage:
		return json.RawMessage(r.RedactBytes(t))
	case []byte:
		return r.RedactBytes(t)
	}
	return v
}

// Empty reports whether the redactor knows no values.
func (r *Redactor) Empty() bool { return r == nil || len(r.pairs) == 0 }
