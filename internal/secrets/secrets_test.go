// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestGenerateKinds(t *testing.T) {
	pw, err := Generate(KindPassword)
	if err != nil || len(pw) != PasswordLength || !regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString(pw) || strings.ContainsAny(pw, "0O1lI") {
		t.Fatalf("password: %q %v", pw, err)
	}
	if pw2, _ := Generate(""); len(pw2) != PasswordLength || pw2 == pw {
		t.Fatalf("default kind is password, random: %q", pw2)
	}
	tok, err := Generate(KindToken)
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(tok) {
		t.Fatalf("token: %q %v", tok, err)
	}
	id, err := Generate(KindUUID)
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(id) {
		t.Fatalf("uuid: %q %v", id, err)
	}
	if _, err := Generate("rsa-key"); err == nil {
		t.Fatal("unknown kind accepted")
	}
}

// The store: generated once (a second Ensure keeps the value), 0600 under
// a 0700 directory, listed by name, read for rendering, removed whole.
func TestStoreLifecycle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "instances", "lab", "secrets")
	s := NewStore(dir)
	if _, err := s.Value("grafana"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if names, err := s.Names(); err != nil || len(names) != 0 {
		t.Fatalf("empty store: %v %v", names, err)
	}
	created, err := s.Ensure("grafana", KindPassword)
	if err != nil || !created {
		t.Fatalf("ensure: %v %v", created, err)
	}
	v1, _ := s.Value("grafana")
	created, err = s.Ensure("grafana", KindPassword)
	if err != nil || created {
		t.Fatalf("second ensure must keep the value: %v %v", created, err)
	}
	if v2, _ := s.Value("grafana"); v2 != v1 || len(v1) != PasswordLength {
		t.Fatalf("value changed: %q %q", v1, v2)
	}
	if _, err := s.Ensure("hec-token", KindUUID); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(s.Path("grafana"))
	di, _ := os.Stat(dir)
	if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatalf("modes: file %o dir %o", fi.Mode().Perm(), di.Mode().Perm())
	}
	if names, _ := s.Names(); strings.Join(names, ",") != "grafana,hec-token" {
		t.Fatalf("names: %v", names)
	}
	values, err := s.Values()
	if err != nil || len(values) != 2 || values["grafana"] != v1 {
		t.Fatalf("values: %v %v", values, err)
	}
	if _, err := s.Ensure("Bad Name", KindPassword); err == nil {
		t.Fatal("bad name accepted")
	}
	if _, err := s.Value("../../etc/passwd"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a path is not a name: %v", err)
	}
	// Temporary files never linger and are never listed; the kind records
	// (.<name>.kind) stay beside their values, unlisted too.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") && !strings.HasSuffix(e.Name(), ".kind") {
			t.Fatalf("leftover %s", e.Name())
		}
	}
	if err := s.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("remove must take the directory")
	}
}

// The kind a secret was generated as is recorded beside the value and a
// declaration that changes kind is refused — the value is kept, the
// mismatch named (secrets.go:113). A value
// from before kinds were recorded adopts the declared kind.
func TestEnsureRecordsTheKindAndRefusesAChange(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	s := NewStore(dir)
	if _, err := s.Ensure("grafana", KindPassword); err != nil {
		t.Fatal(err)
	}
	v1, _ := s.Value("grafana")
	if k, err := s.Kind("grafana"); err != nil || k != KindPassword {
		t.Fatalf("kind on record: %q %v", k, err)
	}
	fi, err := os.Stat(filepath.Join(dir, ".grafana.kind"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the kind record is a 0600 dotfile: %v %v", fi, err)
	}
	created, err := s.Ensure("grafana", KindUUID)
	var ke *KindError
	if !errors.As(err, &ke) || created || ke.Name != "grafana" || ke.Generated != KindPassword || ke.Declared != KindUUID {
		t.Fatalf("a kind change must be refused, naming both kinds: %v %v", err, created)
	}
	if !strings.Contains(err.Error(), "generated as a password") || !strings.Contains(err.Error(), "now says uuid") {
		t.Fatalf("message: %v", err)
	}
	if v2, _ := s.Value("grafana"); v2 != v1 {
		t.Fatal("the refused change must not touch the value")
	}
	if names, _ := s.Names(); strings.Join(names, ",") != "grafana" {
		t.Fatalf("the kind record is never listed as a secret: %v", names)
	}
	if values, _ := s.Values(); len(values) != 1 || values["grafana"] != v1 {
		t.Fatalf("the kind record is never a value: %v", values)
	}
	// A store from before kinds were recorded: the value stands, the
	// declared kind is adopted.
	if err := os.Remove(filepath.Join(dir, ".grafana.kind")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Kind("grafana"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no record: %v", err)
	}
	if created, err := s.Ensure("grafana", KindUUID); err != nil || created {
		t.Fatalf("adoption: %v %v", err, created)
	}
	if k, _ := s.Kind("grafana"); k != KindUUID {
		t.Fatalf("adopted kind: %q", k)
	}
	if v3, _ := s.Value("grafana"); v3 != v1 {
		t.Fatal("adoption keeps the value")
	}
}

func TestRenderAndRedact(t *testing.T) {
	values := map[string]string{"grafana": "Abcdefghijklmnopqrstuvwx", "hec-token": "0123456789abcdef0123456789abcdef", "short": "ab"}
	out, err := Render("GF_SECURITY_ADMIN_PASSWORD=${secret:grafana} token=${secret:hec-token}", values)
	if err != nil || out != "GF_SECURITY_ADMIN_PASSWORD=Abcdefghijklmnopqrstuvwx token=0123456789abcdef0123456789abcdef" {
		t.Fatalf("render: %q %v", out, err)
	}
	if _, err := Render("x=${secret:missing}", values); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing secret: %v", err)
	}
	if out, _ := Render("plain", values); out != "plain" {
		t.Fatal("plain text untouched")
	}
	r := NewRedactor(values)
	got := r.Redact("login admin/Abcdefghijklmnopqrstuvwx sent 0123456789abcdef0123456789abcdef and ab")
	if got != "login admin/[redacted:grafana] sent [redacted:hec-token] and ab" {
		t.Fatalf("redact: %s", got)
	}
	if string(r.RedactBytes([]byte("Abcdefghijklmnopqrstuvwx"))) != "[redacted:grafana]" {
		t.Fatal("redact bytes")
	}
	var nilR *Redactor
	if nilR.Redact("x") != "x" || !nilR.Empty() || !NewRedactor(map[string]string{"s": "ab"}).Empty() {
		t.Fatal("nil and empty redactors pass text through")
	}
	// A value containing another is replaced whole, longest first.
	nested := NewRedactor(map[string]string{"outer": "secretvalue-and-more", "inner": "secretvalue"})
	if got := nested.Redact("secretvalue-and-more secretvalue"); got != "[redacted:outer] [redacted:inner]" {
		t.Fatalf("nested: %s", got)
	}
}

// RedactValue reaches every string inside a decoded JSON value — nested
// maps, []any, string slices and maps, raw JSON — and leaves numbers,
// booleans and nulls alone.
func TestRedactValueIsRecursive(t *testing.T) {
	r := NewRedactor(map[string]string{"tok": "s3cr3tvalue0000", "pw": "hunter2hunter2"})
	in := map[string]any{
		"echo":   "s3cr3tvalue0000",
		"nested": map[string]any{"deep": []any{"prefix s3cr3tvalue0000 suffix", 1.5, true, nil, map[string]any{"pw": "hunter2hunter2"}}},
		"list":   []string{"hunter2hunter2", "plain"},
		"kv":     map[string]string{"k": "s3cr3tvalue0000"},
		"raw":    json.RawMessage(`{"t":"s3cr3tvalue0000"}`),
		"n":      42,
	}
	out := r.RedactValue(in).(map[string]any)
	enc, _ := json.Marshal(out)
	for _, v := range []string{"s3cr3tvalue0000", "hunter2hunter2"} {
		if strings.Contains(string(enc), v) {
			t.Fatalf("value %q survived: %s", v, enc)
		}
	}
	for _, want := range []string{`"echo":"[redacted:tok]"`, `"prefix [redacted:tok] suffix"`, `1.5,true,null`, `{"pw":"[redacted:pw]"}`, `"list":["[redacted:pw]","plain"]`, `"kv":{"k":"[redacted:tok]"}`, `"raw":{"t":"[redacted:tok]"}`, `"n":42`} {
		if !strings.Contains(string(enc), want) {
			t.Fatalf("missing %s in %s", want, enc)
		}
	}
	if (*Redactor)(nil).RedactValue("s3cr3tvalue0000") != "s3cr3tvalue0000" {
		t.Fatal("a nil redactor passes values through")
	}
}

// A kind record outlives its value: Recorded still names a secret whose
// file was deleted, so a filter can tell a value it lost from one that
// never was.
func TestRecordedOutlivesTheValue(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "secrets"))
	if got, err := s.Recorded(); err != nil || len(got) != 0 {
		t.Fatalf("an absent store records nothing: %v %v", got, err)
	}
	for _, n := range []string{"tok", "pw"} {
		if _, err := s.Ensure(n, "token"); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(s.Path("tok")); err != nil {
		t.Fatal(err)
	}
	names, err := s.Names()
	if err != nil || strings.Join(names, ",") != "pw" {
		t.Fatalf("Names lists the values present: %v %v", names, err)
	}
	rec, err := s.Recorded()
	if err != nil || strings.Join(rec, ",") != "pw,tok" {
		t.Fatalf("Recorded lists every secret generated, the lost one included: %v %v", rec, err)
	}
}

// A stream the cap cut may end with the first bytes of a value: too few for
// the filter to see, enough to leak. TrimPartial drops that fragment.
func TestTrimPartialDropsATrailingSecretFragment(t *testing.T) {
	r := NewRedactor(map[string]string{"tok": "s3cretVALUE99", "pw": "p4ssw0rdXYZ"})
	for in, want := range map[string]string{
		"diag s3cretVALU":      "diag ",
		"diag s3cretVALUE99":   "diag s3cretVALUE99", // the whole value is the filter's to replace, not the trimmer's
		"diag p4ssw0rdXYZs3cr": "diag p4ssw0rdXYZ",
		"nothing to trim":      "nothing to trim",
		"ends with p":          "ends with ",
		"":                     "",
	} {
		if got := string(r.TrimPartial([]byte(in))); got != want {
			t.Errorf("TrimPartial(%q) = %q, want %q", in, got, want)
		}
	}
	var nilR *Redactor
	if string(nilR.TrimPartial([]byte("x"))) != "x" {
		t.Fatal("a nil redactor trims nothing")
	}
}
