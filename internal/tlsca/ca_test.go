// SPDX-License-Identifier: AGPL-3.0-only

package tlsca

import (
	"crypto/x509"
	"errors"
	"github.com/jeremiahjrross/podaro/internal/fsx"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The CA is created once and reused; the leaf covers the wildcard and the
// apex, obeys the 825-day ceiling, and renews inside the 30-day window.
func TestCAAndWildcardLeaf(t *testing.T) {
	dir := t.TempDir()
	p := NewPaths(dir)
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	ca, created, err := EnsureCA(p, now)
	if err != nil || !created {
		t.Fatalf("EnsureCA: created=%v err=%v", created, err)
	}
	if fi, _ := os.Stat(p.CAKey()); fi.Mode().Perm() != 0o600 {
		t.Fatalf("ca.key mode %04o", fi.Mode().Perm())
	}
	if !ca.Cert.IsCA || ca.Cert.Subject.CommonName != CAName || ca.Cert.NotAfter.Sub(now) < 9*365*24*time.Hour {
		t.Fatalf("CA shape: %+v", ca.Cert.Subject)
	}
	ca2, created, err := EnsureCA(p, now.Add(time.Hour))
	if err != nil || created || !ca2.Cert.Equal(ca.Cert) {
		t.Fatalf("second EnsureCA should reuse: created=%v err=%v", created, err)
	}

	leaf, err := ca.IssueWildcard(p, "lab.example.com", LeafValidity, now)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p.LeafKey()); fi.Mode().Perm() != 0o600 {
		t.Fatalf("wildcard.key mode %04o", fi.Mode().Perm())
	}
	for _, host := range []string{"lab.example.com", "pii-lab.lab.example.com", "beta-pii-lab.lab.example.com"} {
		if err := leaf.VerifyHostname(host); err != nil {
			t.Errorf("leaf does not cover %s: %v", host, err)
		}
	}
	if leaf.VerifyHostname("deep.pii-lab.lab.example.com") == nil {
		t.Error("wildcard must not cover a second level")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "x.lab.example.com", CurrentTime: now}); err != nil {
		t.Fatalf("chain: %v", err)
	}
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got > MaxLeafValidity {
		t.Fatalf("leaf validity %s exceeds 825 days", got)
	}
	if _, err := ca.IssueWildcard(p, "lab.example.com", MaxLeafValidity+24*time.Hour, now); err == nil {
		t.Fatal("826-day leaf must be refused")
	}
	pair, parsed, err := LoadLeaf(p.LeafCert(), p.LeafKey())
	if err != nil || pair.Leaf == nil || !parsed.Equal(leaf) {
		t.Fatalf("LoadLeaf: %v", err)
	}

	if NeedsRenewal(leaf, "lab.example.com", now) {
		t.Error("fresh leaf should not need renewal")
	}
	if !NeedsRenewal(leaf, "lab.example.com", leaf.NotAfter.Add(-RenewBefore+time.Hour)) {
		t.Error("leaf inside the renewal window should renew")
	}
	if !NeedsRenewal(leaf, "other.example", now) {
		t.Error("leaf for another domain should renew")
	}
	if !NeedsRenewal(nil, "lab.example.com", now) {
		t.Error("absent leaf should renew")
	}
	if _, err := LoadCA(NewPaths(filepath.Join(dir, "nope"))); !os.IsNotExist(err) {
		t.Fatalf("missing CA: %v", err)
	}
}

// A leaf never outlives its CA, an expired CA signs nothing, and setup
// rotates a CA with less than a leaf's validity left — or none (S5
// Review round 4).
func TestLeafNeverOutlivesTheCA(t *testing.T) {
	dir := t.TempDir()
	p := NewPaths(dir)
	t0 := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	ca, created, err := EnsureCA(p, t0)
	if err != nil || !created {
		t.Fatalf("EnsureCA: created=%v err=%v", created, err)
	}
	late := ca.Cert.NotAfter.Add(-100 * 24 * time.Hour)
	leaf, err := ca.IssueWildcard(p, "lab.test", LeafValidity, late)
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.NotAfter.Equal(ca.Cert.NotAfter) {
		t.Fatalf("a leaf issued 100 days before the CA's end must end with it: leaf %s, CA %s", leaf.NotAfter, ca.Cert.NotAfter)
	}
	if _, err := ca.IssueWildcard(p, "lab.test", LeafValidity, ca.Cert.NotAfter.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("an expired CA must sign nothing: %v", err)
	}
	// Plenty of life left: reused. Under a leaf's validity left: rotated.
	if same, created, err := EnsureCA(p, t0.AddDate(5, 0, 0)); err != nil || created || !same.Cert.Equal(ca.Cert) {
		t.Fatalf("a CA with years left must be reused: created=%v err=%v", created, err)
	}
	rotated, created, err := EnsureCA(p, ca.Cert.NotAfter.Add(-LeafValidity/2))
	if err != nil || !created || rotated.Cert.Equal(ca.Cert) {
		t.Fatalf("a CA with under a leaf's validity left must be replaced: created=%v err=%v", created, err)
	}
	if rotated.Cert.NotAfter.Sub(ca.Cert.NotAfter.Add(-LeafValidity/2)) < 9*365*24*time.Hour {
		t.Fatalf("the new CA must carry the full validity: %s", rotated.Cert.NotAfter)
	}
	// An expired CA on disk is replaced too.
	dir2 := t.TempDir()
	p2 := NewPaths(dir2)
	old, _, err := EnsureCA(p2, t0)
	if err != nil {
		t.Fatal(err)
	}
	if fresh, created, err := EnsureCA(p2, old.Cert.NotAfter.Add(24*time.Hour)); err != nil || !created || fresh.Cert.Equal(old.Cert) {
		t.Fatalf("an expired CA must be replaced: created=%v err=%v", created, err)
	}
}

// The managed leaf is one file, replaced by one rename:
// a renewal that cannot land — its temporary path blocked here, as a
// full disk or a crash would — leaves the pair that was serving exactly
// as it was, never a new key beside an old certificate.
func TestARefusedRenewalLeavesTheServingPairIntact(t *testing.T) {
	dir := t.TempDir()
	p := NewPaths(dir)
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	ca, _, err := EnsureCA(p, now)
	if err != nil {
		t.Fatal(err)
	}
	first, err := ca.IssueWildcard(p, "lab.example.com", LeafValidity, now)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p.LeafKey()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the leaf's key file must be 0600: %v %v", fi, err)
	}
	// The certificate cannot land: every path a certificate write could
	// take is blocked, the key's is not.
	for _, blocked := range []string{"wildcard.pem.tmp", "wildcard.crt.tmp"} {
		if err := os.Mkdir(filepath.Join(p.Dir, blocked), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ca.IssueWildcard(p, "lab.example.com", LeafValidity, now.Add(time.Hour)); err == nil {
		t.Fatal("a renewal that cannot land must fail")
	}
	_, leaf, err := LoadLeaf(p.LeafCert(), p.LeafKey())
	if err != nil {
		t.Fatalf("the serving pair must still load: %v", err)
	}
	if leaf.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatal("the serving pair must be the one that was serving")
	}
}

// A staged set is published as one unit: after
// Publish the live directory holds the new CA and leaf and the previous
// set waits beside it until Commit drops it or Rollback puts it back
// (round 9) — by the atomic exchange, and by the two-rename path a
// filesystem without one gets, whose interruption Recover completes
// either way. A cleanup that fails never fails a publish that happened.
func TestPublishSwapsTheWholeSetAndRecoverCompletesIt(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	build := func(t *testing.T, dir, domain string) (Paths, *x509.Certificate) {
		t.Helper()
		p := Paths{Dir: dir}
		ca, _, err := EnsureCA(p, now)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := ca.IssueWildcard(p, domain, LeafValidity, now)
		if err != nil {
			t.Fatal(err)
		}
		return p, leaf
	}
	serving := func(t *testing.T, p Paths) string {
		t.Helper()
		_, leaf, err := LoadLeaf(p.LeafCert(), p.LeafKey())
		if err != nil {
			t.Fatalf("the live set must load: %v", err)
		}
		return leaf.DNSNames[1]
	}
	for _, exchangeWorks := range []bool{true, false} {
		root := t.TempDir()
		live, _ := build(t, filepath.Join(root, "ca"), "old.example.com")
		staging, _ := build(t, filepath.Join(root, "ca.staging"), "new.example.com")
		if !exchangeWorks {
			saved := exchangeDirs
			exchangeDirs = func(a, b string) error { return errors.ErrUnsupported }
			defer func() { exchangeDirs = saved }()
		}
		previous, err := Publish(staging, live)
		if err != nil {
			t.Fatalf("publish (exchange %v): %v", exchangeWorks, err)
		}
		if got := serving(t, live); got != "new.example.com" {
			t.Fatalf("the live set must be the staged one, got %s", got)
		}
		// The previous set sits where the swap left it — no rename after
		// the swap is needed for the rollback to find it.
		if want := map[bool]string{true: staging.Dir, false: live.Dir + ".previous"}[exchangeWorks]; previous != want {
			t.Fatalf("previous set at %s, want %s", previous, want)
		}
		if got := serving(t, Paths{Dir: previous}); got != "old.example.com" {
			t.Fatalf("the previous set must wait at %s, got %s", previous, got)
		}
		// Rollback puts the previous set back; a second publish then
		// commits, and a cleanup that fails does not fail it.
		if err := Rollback(live, previous); err != nil {
			t.Fatalf("rollback (exchange %v): %v", exchangeWorks, err)
		}
		if got := serving(t, live); got != "old.example.com" {
			t.Fatalf("rollback must restore the previous set, got %s", got)
		}
		for _, gone := range []string{previous, live.Dir + ".rollback"} {
			if _, err := os.Stat(gone); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s must be gone after rollback: %v", gone, err)
			}
		}
		staging, _ = build(t, filepath.Join(root, "ca.staging"), "new.example.com")
		previous, err = Publish(staging, live)
		if err != nil {
			t.Fatal(err)
		}
		savedRemove := removeAll
		removeAll = func(string) error { return errors.New("immutable") }
		Commit(previous)
		removeAll = savedRemove
		if got := serving(t, live); got != "new.example.com" {
			t.Fatalf("a cleanup that fails must leave the published set live, got %s", got)
		}
		if got := serving(t, Paths{Dir: previous}); got != "old.example.com" {
			t.Fatalf("a cleanup that fails leaves the previous set where it was, got %s", got)
		}
		Commit(previous)
		if _, err := os.Stat(previous); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("the next cleanup must drop it")
		}
		if exchangeWorks {
			continue
		}
		// The two-rename path interrupted after its first rename: the live
		// set is aside and nothing replaced it; Recover moves it back.
		if err := os.Rename(live.Dir, live.Dir+".previous"); err != nil {
			t.Fatal(err)
		}
		if err := Recover(live); err != nil {
			t.Fatal(err)
		}
		if got := serving(t, live); got != "new.example.com" {
			t.Fatalf("recover must restore the set that was aside, got %s", got)
		}
		// Interrupted after its second rename: the previous set was never
		// removed. Recover keeps it beside the live one — it may be a
		// running setup's way back — and Tidy, which only setup runs,
		// drops it.
		build(t, live.Dir+".previous", "stale.example.com")
		if err := Recover(live); err != nil {
			t.Fatal(err)
		}
		if got := serving(t, live); got != "new.example.com" {
			t.Fatalf("recover must keep the live set, got %s", got)
		}
		if got := serving(t, Paths{Dir: live.Dir + ".previous"}); got != "stale.example.com" {
			t.Fatalf("recover must keep the previous set beside the live one, got %s", got)
		}
		if err := Tidy(live); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(live.Dir + ".previous"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("tidy must remove the previous set")
		}
	}
	// A first publish, with no live set yet, simply lands the staged one.
	root := t.TempDir()
	staging, _ := build(t, filepath.Join(root, "ca.staging"), "first.example.com")
	live := Paths{Dir: filepath.Join(root, "ca")}
	previous, err := Publish(staging, live)
	if err != nil || previous != "" {
		t.Fatalf("first publish: previous %q err %v", previous, err)
	}
	if got := serving(t, live); got != "first.example.com" {
		t.Fatalf("first publish: %s", got)
	}
	// Rolling a first publish back leaves what was there: nothing.
	if err := Rollback(live, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(live.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rolling back a first publish must remove the set")
	}
}

// A CA key must be its certificate's: a pair from
// two different CAs — a partial restore — is refused by LoadCA, and
// EnsureCA reports it rather than quietly rotating.
func TestACAKeyMustMatchItsCertificate(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	a, b := NewPaths(t.TempDir()), NewPaths(t.TempDir())
	if _, _, err := EnsureCA(a, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := EnsureCA(b, now); err != nil {
		t.Fatal(err)
	}
	other, err := os.ReadFile(b.CAKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.CAKey(), other, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(a); err == nil || !strings.Contains(err.Error(), "not the key of") {
		t.Fatalf("a key from another CA must be refused: %v", err)
	}
	if _, _, err := EnsureCA(a, now); err == nil {
		t.Fatal("EnsureCA must report the mismatch, not rotate over it")
	}
}

// The engine's recovery never discards a setup's way back:
// on the two-rename path the previous set waits beside the
// live one until setup commits, and the engine's reload — that setup's
// next step — runs Recover first. Recover leaves the set where it is,
// so a reload that then fails can still be rolled back.
func TestRecoverKeepsAPreviousSetBesideALiveOne(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	build := func(dir, domain string) Paths {
		t.Helper()
		p := Paths{Dir: dir}
		ca, _, err := EnsureCA(p, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ca.IssueWildcard(p, domain, LeafValidity, now); err != nil {
			t.Fatal(err)
		}
		return p
	}
	live := build(filepath.Join(root, "ca"), "old.example.com")
	staging := build(filepath.Join(root, "ca.staging"), "new.example.com")
	saved := exchangeDirs
	exchangeDirs = func(a, b string) error { return errors.ErrUnsupported }
	defer func() { exchangeDirs = saved }()
	previous, err := Publish(staging, live)
	if err != nil || previous != live.Dir+".previous" {
		t.Fatalf("publish on the two-rename path: %q %v", previous, err)
	}
	if err := Recover(live); err != nil { // what the engine's reload runs first
		t.Fatal(err)
	}
	if err := Rollback(live, previous); err != nil {
		t.Fatalf("the previous set must survive the engine's recovery so a failed reload can roll back: %v", err)
	}
	_, leaf, err := LoadLeaf(live.LeafCert(), live.LeafKey())
	if err != nil || leaf.DNSNames[1] != "old.example.com" {
		t.Fatalf("rollback must restore the set that served: %v %v", leaf, err)
	}
}

// A certificate write is durable, not merely atomic: the temporary file
// is synced before the rename that puts it in place and the directory
// after it, so a set a setup reported published survives a power loss.
func TestCertificateWritesAreDurable(t *testing.T) {
	dir := t.TempDir()
	p := NewPaths(filepath.Join(dir, "ca"))
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	var synced []string
	saved := fsx.Sync
	fsx.Sync = func(f *os.File) error {
		synced = append(synced, f.Name())
		return saved(f)
	}
	defer func() { fsx.Sync = saved }()
	ca, _, err := EnsureCA(p, now)
	if err != nil {
		t.Fatal(err)
	}
	synced = nil
	if _, err := ca.IssueWildcard(p, "lab.example.com", LeafValidity, now); err != nil {
		t.Fatal(err)
	}
	want := []string{p.LeafFile() + ".tmp", p.Dir}
	if len(synced) != len(want) {
		t.Fatalf("the leaf's file and its directory are synced, in that order: %v", synced)
	}
	for i, w := range want {
		if synced[i] != w {
			t.Fatalf("sync %d: %s, want %s", i, synced[i], w)
		}
	}
	// The swap a publish makes is durable too, as its own step: the
	// directory holding the set is synced once the renames are done.
	staging := NewPaths(filepath.Join(dir, "ca.staging"))
	sca, _, err := EnsureCA(staging, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sca.IssueWildcard(staging, "new.example.com", LeafValidity, now); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(staging, p); err != nil {
		t.Fatal(err)
	}
	synced = nil
	if err := Durable(p); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 1 || synced[0] != filepath.Dir(p.Dir) {
		t.Fatalf("the set's parent directory is synced: %v", synced)
	}
}
