// SPDX-License-Identifier: AGPL-3.0-only

// Package tlsca is the local certificate authority `podaro setup` creates
// (INSTALL §2 step 4): an ECDSA P-256 CA valid ten years whose key never
// leaves the machine, and a wildcard leaf for `*.<domain>` plus the apex
// that the engine re-issues before expiry. The leaf is kept at most 825
// days for Apple-platform trust rules; the product issues one year.
package tlsca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/jeremiahjrross/podaro/internal/fsx"
)

const (
	// CAValidity is the CA's lifetime (INSTALL: "valid 10 years").
	CAValidity = 10 * 365 * 24 * time.Hour
	// LeafValidity is what setup issues ("valid 1 year · auto-renews").
	LeafValidity = 365 * 24 * time.Hour
	// MaxLeafValidity is the ≤ 825-day rule; IssueLeaf refuses more.
	MaxLeafValidity = 825 * 24 * time.Hour
	// RenewBefore is how long before expiry the engine re-issues the leaf.
	RenewBefore = 30 * 24 * time.Hour

	// CAName is the issuer's common name.
	CAName = "Podaro Local CA"
)

// Paths are the files under the state directory's ca/ (INSTALL §3).
type Paths struct {
	Dir string
}

// NewPaths returns the ca/ layout under stateDir.
func NewPaths(stateDir string) Paths { return Paths{Dir: filepath.Join(stateDir, "ca")} }

func (p Paths) CACert() string { return filepath.Join(p.Dir, "ca.crt") }
func (p Paths) CAKey() string  { return filepath.Join(p.Dir, "ca.key") }

// LeafFile is the managed wildcard leaf: one file holding the key and
// the certificate, so the pair is replaced by one atomic rename and a
// renewal interrupted at any point leaves the serving pair intact.
func (p Paths) LeafFile() string { return filepath.Join(p.Dir, "wildcard.pem") }

// LeafCert and LeafKey both name the one leaf file: a loader that takes
// a certificate path and a key path reads the pair from it.
func (p Paths) LeafCert() string { return p.LeafFile() }
func (p Paths) LeafKey() string  { return p.LeafFile() }

// CA is the loaded authority.
type CA struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// EnsureCA loads the CA at paths or creates it; created reports which.
// A CA with less than a leaf's validity left — or none — is replaced by
// a new one (the rotation path, INSTALL step 4): a leaf never outlives
// its CA, so the last year of a CA would otherwise shrink every leaf,
// and an expired CA can sign nothing a browser accepts.
func EnsureCA(p Paths, now time.Time) (ca *CA, created bool, err error) {
	if ca, err := LoadCA(p); err == nil {
		if ca.Cert.NotAfter.Sub(now) >= LeafValidity {
			return ca, false, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return nil, false, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, false, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, false, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: CAName, Organization: []string{"Podaro"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, false, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, false, err
	}
	if err := writePEM(p.CACert(), "CERTIFICATE", der, 0o644); err != nil {
		return nil, false, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, false, err
	}
	if err := writePEM(p.CAKey(), "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		return nil, false, err
	}
	return &CA{Cert: cert, key: key}, true, nil
}

// LoadCA reads an existing CA; os.ErrNotExist when either file is absent.
func LoadCA(p Paths) (*CA, error) {
	certDER, err := readPEM(p.CACert(), "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	keyDER, err := readPEM(p.CAKey(), "EC PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.CACert(), err)
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.CAKey(), err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("%s is not a CA certificate", p.CACert())
	}
	// The key must be the certificate's: a pair from two different CAs —
	// a partial restore — would sign leaves no client can verify while
	// naming this certificate as their issuer.
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("%s is not the key of %s", p.CAKey(), p.CACert())
	}
	return &CA{Cert: cert, key: key}, nil
}

// IssueWildcard writes a leaf for `*.<domain>` and `<domain>` valid for
// validity (refused above MaxLeafValidity) and returns the parsed leaf.
func (ca *CA) IssueWildcard(p Paths, domain string, validity time.Duration, now time.Time) (*x509.Certificate, error) {
	if validity <= 0 || validity > MaxLeafValidity {
		return nil, fmt.Errorf("leaf validity %s exceeds the 825-day rule", validity)
	}
	// A leaf never outlives its CA: clients stop trusting the chain at
	// the CA's end whatever the leaf says. An expired CA signs nothing;
	// setup replaces it (EnsureCA).
	if !now.Before(ca.Cert.NotAfter) {
		return nil, fmt.Errorf("the local CA expired at %s; re-run podaro setup to create a new one", ca.Cert.NotAfter.UTC().Format(time.RFC3339))
	}
	notAfter := now.Add(validity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "*." + domain},
		DNSNames:     []string{"*." + domain, domain},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	// One file, one rename: the certificate and its key land together or
	// not at all, so a renewal interrupted at any point — a crash, a full
	// disk — leaves the pair that was serving exactly as it was.
	data := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	if err := writeAtomic(p.LeafFile(), data, 0o600); err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// Publish moves a staged certificate set into place as one unit: an
// atomic exchange of the two directories where the filesystem offers
// one (Linux renameat2), otherwise two renames through a `.previous`
// copy that Recover completes after an interruption. The set that was
// live is kept where the swap left it — the staging path after an
// exchange, `.previous` after two renames — and its path is returned
// ("" when there was none) for Rollback to put back or Commit to drop:
// nothing after the swap can fail the publish, and nothing after it is
// needed for the rollback.
func Publish(staging, live Paths) (previous string, err error) {
	aside := live.Dir + ".previous"
	if err := removeAll(aside); err != nil { // an earlier run's, before anything changes
		return "", err
	}
	if _, err := os.Stat(live.Dir); errors.Is(err, os.ErrNotExist) {
		return "", os.Rename(staging.Dir, live.Dir) // the first set
	} else if err != nil {
		return "", err
	}
	if err := exchangeDirs(staging.Dir, live.Dir); err == nil {
		return staging.Dir, nil // the set that was live sits where the staged one was
	}
	if err := os.Rename(live.Dir, aside); err != nil {
		return "", err
	}
	if err := os.Rename(staging.Dir, live.Dir); err != nil {
		_ = os.Rename(aside, live.Dir)
		return "", err
	}
	return aside, nil
}

// Commit drops the previous set a Publish kept at previous. Cleanup
// only, best effort: a failure leaves it for the next run to clear and
// never unpublishes anything.
func Commit(previous string) {
	if previous != "" {
		_ = removeAll(previous)
	}
}

// Rollback puts the previous set a Publish kept at previous back in
// place of the published one — the same exchange, or two renames through
// a `.rollback` copy — for a caller whose next step failed after the
// publish. With no previous set (a first publish) the published one is
// removed: what was there before was nothing.
func Rollback(live Paths, previous string) error {
	if previous == "" {
		return os.RemoveAll(live.Dir)
	}
	if _, err := os.Stat(previous); err != nil {
		return err
	}
	if err := exchangeDirs(previous, live.Dir); err == nil {
		_ = removeAll(previous)
		return fsx.SyncDir(filepath.Dir(live.Dir))
	}
	aside := live.Dir + ".rollback"
	if err := removeAll(aside); err != nil {
		return err
	}
	if err := os.Rename(live.Dir, aside); err != nil {
		return err
	}
	if err := os.Rename(previous, live.Dir); err != nil {
		_ = os.Rename(aside, live.Dir)
		return err
	}
	_ = removeAll(aside)
	return fsx.SyncDir(filepath.Dir(live.Dir))
}

// exchangeDirs swaps two directories atomically where the platform can;
// removeAll is the cleanup. Tests replace them to exercise the
// two-rename path and a cleanup that fails.
var (
	exchangeDirs = exchange
	removeAll    = os.RemoveAll
)

// Recover completes a Publish or Rollback interrupted between its two
// renames: a live set moved aside and not replaced is moved back. Every
// loader of the managed set runs it first, so an interruption never
// leaves the gateway without its certificate at the next start. It
// removes nothing: a previous set beside a live one may be a running
// setup's rollback generation — the engine's reload is that setup's
// next step, and a reload that fails is what the set is kept for —
// so only setup, holding its lock, drops leftovers (Tidy).
func Recover(p Paths) error {
	previous := p.Dir + ".previous"
	if _, err := os.Stat(p.Dir); errors.Is(err, os.ErrNotExist) {
		if _, perr := os.Stat(previous); perr == nil {
			if err := os.Rename(previous, p.Dir); err != nil {
				return err
			}
			return fsx.SyncDir(filepath.Dir(p.Dir))
		}
		return nil
	} else if err != nil {
		return err
	}
	return nil
}

// Tidy drops what a finished Publish or Rollback left beside the live
// set — a previous or rolled-back set. Setup runs it at its start, under
// its lock, after Recover; nothing else does.
func Tidy(p Paths) error {
	for _, leftover := range []string{p.Dir + ".previous", p.Dir + ".rollback"} {
		if err := os.RemoveAll(leftover); err != nil {
			return err
		}
	}
	return nil
}

// LoadLeaf reads a certificate/key pair (managed or bring-your-own).
func LoadLeaf(certFile, keyFile string) (tls.Certificate, *x509.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pair.Leaf = leaf
	return pair, leaf, nil
}

// NeedsRenewal reports whether a managed leaf should be re-issued: it is
// within RenewBefore of expiry, already expired, or does not cover the
// domain (setup ran again with a new one).
// CoversDomain reports whether leaf serves the apex and *.domain — the
// console at <domain> and every lab hostname beneath it. A wildcard alone
// leaves the console's own hostname uncovered; the error names the
// hostname that is not covered.
func CoversDomain(leaf *x509.Certificate, domain string) error {
	for _, h := range []string{domain, "podaro-wildcard-check." + domain} {
		if err := leaf.VerifyHostname(h); err != nil {
			return fmt.Errorf("%s is not covered: %w", h, err)
		}
	}
	return nil
}

// Serves reports whether leaf can serve the console at domain now: inside
// its validity window and covering the apex and *.domain. An expired or
// not-yet-valid certificate would otherwise be accepted, stored and
// reported as listening while every browser refused the handshake.
func Serves(leaf *x509.Certificate, domain string, now time.Time) error {
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("the certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return fmt.Errorf("the certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	// A certificate whose extended key usage names other purposes only (a
	// client or code-signing certificate) is refused by every browser for
	// a server; an absent extension permits any use.
	if len(leaf.ExtKeyUsage) > 0 {
		server := false
		for _, u := range leaf.ExtKeyUsage {
			if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
				server = true
			}
		}
		if !server {
			return fmt.Errorf("the certificate's extended key usage does not allow server authentication")
		}
	}
	return CoversDomain(leaf, domain)
}

// NeedsReissue reports whether a managed leaf must be re-issued from the
// CA now in place: NeedsRenewal's reasons, or a leaf that CA did not
// sign. A partial restore can leave a matching ca.crt/ca.key pair beside
// a leaf the CA before it signed — still inside its validity, still
// covering the domain, and refused by every client that trusts this
// ca.crt, for as long as a year.
func NeedsReissue(leaf, ca *x509.Certificate, domain string, now time.Time) bool {
	if NeedsRenewal(leaf, domain, now) {
		return true
	}
	return ca == nil || leaf.CheckSignatureFrom(ca) != nil
}

func NeedsRenewal(leaf *x509.Certificate, domain string, now time.Time) bool {
	if leaf == nil {
		return true
	}
	if now.Add(RenewBefore).After(leaf.NotAfter) {
		return true
	}
	return leaf.VerifyHostname("x."+domain) != nil || leaf.VerifyHostname(domain) != nil
}

func serialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return writeAtomic(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

// writeAtomic lands data at path durably: a temporary file synced before
// the one rename, the directory synced after (fsx.WriteFile), so a
// certificate reported written survives a power loss.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return fsx.WriteFile(path, data, mode)
}

// Durable flushes the swap a Publish made — the renames in the set's
// parent directory — to stable storage. The caller runs it as its step
// after the publish, before the engine is asked to open the door: a
// failure rolls the publish back like any failed next step, and a set
// the engine then serves, and a setup reported done, survive a power
// loss.
func Durable(p Paths) error {
	return fsx.SyncDir(filepath.Dir(p.Dir))
}

func readPEM(path, typ string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != typ {
		return nil, fmt.Errorf("%s: expected a %s PEM block", path, typ)
	}
	return block.Bytes, nil
}

// Fingerprint identifies a certificate: "sha256:" + the hex SHA-256 of
// its DER encoding. The gateway reports the leaf it serves by it, and
// setup settles a lost reload answer by it: an expiry is shared by
// leaves issued in the same second, a fingerprint by none.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
