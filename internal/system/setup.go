// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jeremiahjrross/podaro/internal/client"
	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/fsx"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
	"github.com/jeremiahjrross/podaro/internal/sysinfo"
	"github.com/jeremiahjrross/podaro/internal/tlsca"
)

// setupColumn is the step-4 block's detail column (INSTALL §2).
const setupColumn = 24

// SetupOptions are `podaro setup`'s inputs.
type SetupOptions struct {
	Domain string
	// Port overrides gateway.port. Every value the operator gave is a port
	// they asked for and is validated like one (1–65535); only the flag's
	// absence keeps the configured or default port.
	Port int
	// PortGiven says --port was passed at all. Zero is a port like any
	// other — an out-of-range one — so a client that can tell the flag's
	// absence from an explicit zero says which this is; a caller that
	// leaves it false gets the old meaning of zero: keep what is
	// configured.
	PortGiven bool
	// IP overrides the detected host address printed in the DNS block.
	IP string
	// Socket is the engine socket path; "" uses the default.
	Socket string
	// Now overrides the clock (tests).
	Now func() time.Time
	// ReloadTimeout bounds each call to the engine — the reload, and the
	// calls that settle an answer that never arrived; 0 is 30 seconds.
	ReloadTimeout time.Duration
}

// SetupFacts are the host facts the step-4 block prints.
type SetupFacts struct {
	Domain   string
	IP       string
	CAPath   string
	Port     int
	BYO      bool
	Existing bool
}

// Setup is INSTALL §2 step 4: write config.yaml, create (or reuse) the
// local CA, issue the wildcard leaf, and ask the running engine to open
// the gateway. Idempotent: the CA is reused; the leaf is re-issued.
func Setup(p *render.Printer, o SetupOptions) error {
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	stateDir := config.StateDir()
	// One setup at a time: the staged set, the previous set and
	// config.yaml's temporary file are paths every setup shares, so a
	// second setup overlapping the first could publish the other's
	// candidate or roll back a set that had succeeded. The lock is held
	// for the whole transaction — from reading the configuration to the
	// reload — so a run's candidate is derived from what the run before
	// it committed, never from a file read while that run was writing
	// it; a second setup meanwhile is refused, not queued.
	unlock, err := lockSetup(stateDir)
	if err != nil {
		return err
	}
	defer unlock()
	if afterSetupLock != nil {
		afterSetupLock()
	}
	cfg, err := config.Load(config.Path())
	if err != nil {
		return err
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(o.Domain), "."))
	if domain == "" {
		domain = cfg.Domain
	}
	if domain == "" {
		e := pdr.New(pdr.CodeSetupFailed, "no domain given")
		e.Cause = "instances live at <instance>.<domain> (User Manual §5); setup needs the parent domain"
		e.Next = "podaro setup --domain lab.example.com"
		return e
	}
	port := cfg.Gateway.Port
	// A port the operator gave is never read as no port at all: only the
	// flag's absence keeps what is configured, so a nonsensical --port=-1
	// or --port=0 meets the documented 1–65535 in the preflight below
	// rather than being dropped and setup reporting success on a port
	// nobody asked for. Absence is the flag's
	// own state, not a value: an explicit zero is out of range, and only a
	// caller that never set the flag leaves both fields at their zero.
	if o.PortGiven || o.Port != 0 {
		port = o.Port
	}
	byo := cfg.TLS != nil
	paths := tlsca.NewPaths(stateDir)

	var results []StepResult
	fail := func(label string, err error) error {
		results = append(results, StepResult{Label: label, Err: err})
		RenderSetupBlock(p, results, nil)
		e := pdr.New(pdr.CodeSetupFailed, "setup failed at %q", label)
		e.Cause = err.Error()
		e.Next = "fix the cause above, then re-run podaro setup (idempotent; the CA is reused)"
		return e
	}

	// Preflight, before anything on disk is replaced: the candidate
	// configuration must validate, and a bring-your-own certificate must
	// load and cover the apex and the wildcard — a typo in --domain or
	// --port must never take a working config.yaml with it.
	candidate := *cfg
	candidate.Domain, candidate.Gateway.Port = domain, port
	if err := config.Validate(&candidate); err != nil {
		return fail("config", err)
	}
	if port != cfg.Gateway.Port {
		// A changed port must be free now: the engine would otherwise keep
		// its working door on the old port (gateway E024) with a config
		// that names one it cannot open.
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			return fail("gateway", fmt.Errorf("port :%d is not free: %v", port, err))
		}
		l.Close()
	}
	var byoLeaf *x509.Certificate
	var candidateLeaf *x509.Certificate // the leaf the engine must serve once the reload has happened
	if byo {
		_, leaf, err := tlsca.LoadLeaf(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return fail("wildcard certificate", err)
		}
		if err := tlsca.Serves(leaf, domain, o.Now()); err != nil {
			return fail("wildcard certificate", fmt.Errorf("%s: %v", cfg.TLS.CertFile, err))
		}
		byoLeaf = leaf
		candidateLeaf = leaf
	}

	// 2–3 are prepared before 1 is written and published only after it:
	// the local CA and the wildcard leaf are staged in a directory beside
	// the live one (a copy of the live CA, rotated there when due; the
	// leaf signed there) and swapped into place as one set — one atomic
	// exchange, or two renames the next start completes — once
	// config.yaml holds the domain they serve. A certificate that cannot be prepared — a damaged
	// CA, a state directory that refuses the write — never leaves
	// config.yaml naming a domain no leaf serves, and a config.yaml that
	// cannot be written never leaves a live leaf for a domain the
	// configuration does not name: both change together or neither does.
	// Skipped entirely when the operator brings their own certificate
	// (User Manual §4).
	facts := SetupFacts{Domain: domain, Port: port, BYO: byo, CAPath: tildify(paths.CACert())}
	staging := tlsca.Paths{Dir: paths.Dir + ".staging"}
	var certSteps []StepResult
	if byo {
		certSteps = append(certSteps, StepResult{Label: "certificate authority", Skipped: true, Detail: "bringing your own certificate (tls.cert_file)"})
		certSteps = append(certSteps, StepResult{Label: "wildcard certificate", Detail: fmt.Sprintf("%s · covers %s and *.%s · valid until %s", tildify(cfg.TLS.CertFile), domain, domain, byoLeaf.NotAfter.UTC().Format("2006-01-02"))})
	} else {
		if err := stageCA(paths, staging); err != nil {
			return fail("certificate authority", err)
		}
		defer os.RemoveAll(staging.Dir) // whatever was not published
		ca, created, err := tlsca.EnsureCA(staging, o.Now())
		if err != nil {
			return fail("certificate authority", err)
		}
		facts.Existing = !created
		if created {
			certSteps = append(certSteps, StepResult{Label: "certificate authority", Detail: "Podaro Local CA · valid 10 years"})
		} else {
			certSteps = append(certSteps, StepResult{Label: "certificate authority", Detail: "Podaro Local CA · existing · valid until " + ca.Cert.NotAfter.UTC().Format("2006-01-02")})
		}
		leaf, err := ca.IssueWildcard(staging, domain, tlsca.LeafValidity, o.Now())
		if err != nil {
			results = append(results, certSteps...)
			return fail("wildcard certificate", err)
		}
		candidateLeaf = leaf
		certSteps = append(certSteps, StepResult{Label: "wildcard certificate", Detail: "*." + domain + " · valid 1 year · auto-renews"})
	}

	// 1. config.yaml — the file is the source of truth for the engine;
	// printed first, as the manual's block reads. The staged certificates
	// follow it into place; should that fail, the previous configuration
	// is written back so the file and the live leaf still agree.
	// The file as it was is what a rollback puts back — byte for byte,
	// or absent when there was none.
	previous := *cfg
	original, readErr := readFile(config.Path())
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		// Nothing is replaced without a snapshot to put back: a read that
		// fails for any other reason would leave the rollback writing
		// nothing over a working configuration.
		return fail("config", fmt.Errorf("%s cannot be read, so nothing could be put back: %w", tildify(config.Path()), readErr))
	}
	restoreConfig := func() error {
		*cfg = previous
		if errors.Is(readErr, os.ErrNotExist) {
			// There was no file: removing the candidate is the restore.
			// A candidate that never landed is already restored, and the
			// removal is flushed like every write on this path — a power
			// loss must not bring back a name the rollback reported gone.
			if err := os.Remove(config.Path()); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return fsx.SyncDir(filepath.Dir(config.Path()))
		}
		return writeRaw(config.Path(), original)
	}
	// failRestoring is how every failure past this point reports itself:
	// the snapshot goes back first, and when it cannot, the operator is
	// told in the same breath — a `config.yaml` that is not the file the
	// run started with must never be reported as merely a failed step.
	failRestoring := func(label string, cause error) error {
		if rerr := restoreConfig(); rerr != nil {
			return fail(label, fmt.Errorf("%v; and %s could not be put back: %v", cause, tildify(config.Path()), rerr))
		}
		return fail(label, cause)
	}
	*cfg = candidate
	if err := writeConfig(config.Path(), cfg); err != nil {
		// A write can fail after the rename that puts the candidate in
		// place — the directory sync that makes it durable is the last
		// step — so this failure is rolled back like any other past the
		// write, not reported over a file that has already changed. A
		// failure before the rename leaves the same file, and putting it
		// back is a write of the bytes already there.
		return failRestoring("config", err)
	}
	if _, err := loadConfig(config.Path()); err != nil {
		// The candidate is on disk but cannot be read back — another
		// process wrote the file between the two, a transient read fault.
		// It is put back: a `config.yaml` naming a domain the live
		// certificates do not serve outlives a setup that reported
		// failure, and the next start refuses the gateway.
		return failRestoring("config", err)
	}
	var previousSet string // where the set that served sits until the door opens
	if !byo {
		set, err := tlsca.Publish(staging, paths)
		if err != nil {
			return failRestoring("wildcard certificate", err)
		}
		previousSet = set
		// The swap is made durable before the door is asked to open: a
		// sync that fails is a failed next step, rolled back like one.
		if err := tlsca.Durable(paths); err != nil {
			cause := fmt.Errorf("sync %s: %w", tildify(filepath.Dir(paths.Dir)), err)
			if rerr := tlsca.Rollback(paths, previousSet); rerr != nil {
				// The same fault can stop the way back, leaving the
				// candidate set live under a restored configuration: the
				// operator hears it here, as the reload path already says
				// it.
				cause = fmt.Errorf("%v; and the certificate set that served could not be put back: %v", cause, rerr)
			}
			return failRestoring("wildcard certificate", cause)
		}
	}
	results = append(results, StepResult{Label: "config", Detail: tildify(config.Path())})
	results = append(results, certSteps...)

	// 4. The gateway: the running engine re-reads config and listens.
	sock := o.Socket
	if sock == "" {
		sock = filepath.Join(config.RuntimeDir(), "api.sock")
	}
	// Each call to the engine has a time limit of its own: an answer
	// that never arrives spends the reload's, and the calls that settle
	// it — what the engine serves, the re-read after a rollback — must
	// not start with a deadline already gone, or the disk is rolled
	// back under a gateway that is serving the candidate.
	timeout := o.ReloadTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	call := func(f func(ctx context.Context) error) error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return f(ctx)
	}
	cl := client.New(sock)
	var gw sysinfo.Gateway
	err = call(func(ctx context.Context) (rerr error) {
		gw, rerr = cl.Reload(ctx)
		return rerr
	})
	// serves reports whether what the engine says it opened is this run's
	// candidate. A door that is merely open proves nothing: another
	// writer may have replaced config.yaml between this run's write and
	// the engine's read of it, and the engine would then have applied
	// *that* configuration — setup would commit its certificates and
	// report a port nothing listens on. The leaf is
	// checked whenever the answer names one; a response that carries no
	// fingerprint is judged by the domain and port alone.
	serves := func(g sysinfo.Gateway) bool {
		if !g.Listening || g.Domain != domain || g.Address != ":"+strconv.Itoa(port) {
			return false
		}
		return g.Fingerprint == "" || g.Fingerprint == tlsca.Fingerprint(candidateLeaf)
	}
	if err == nil && !gw.Listening {
		err = fmt.Errorf("engine did not open the gateway")
	} else if err == nil && !serves(gw) {
		err = fmt.Errorf("the engine opened %s on %s, not %s on :%d — the configuration it read is not the one written here", gw.Domain, gw.Address, domain, port)
	}
	ambiguous := err != nil && !definitiveAnswer(err)
	if ambiguous {
		// The answer never arrived — the socket dropped before or after
		// the engine applied the candidate. What the engine serves now
		// decides: the candidate's door open means the reload happened
		// and the answer was lost; anything else means it did not.
		// The door alone proves nothing when only the certificate changed
		// (a re-issue, a CA rotation): the engine must be serving the
		// candidate leaf itself — its fingerprint is the posture's; an
		// expiry is shared by leaves issued in the same second — not the
		// one it had in memory before.
		var sys map[string]any
		if serr := call(func(ctx context.Context) (rerr error) {
			sys, rerr = cl.System(ctx)
			return rerr
		}); serr == nil {
			if g := gatewayOf(sys); serves(g) && g.Fingerprint != "" {
				gw, err = g, nil
			}
		}
	}
	if err != nil {
		// Nothing changes unless the door opens: a reload that fails — the
		// port taken since the preflight, the engine not running — puts
		// config.yaml and the previous certificate set back, so the next
		// engine start finds exactly what served before, never a
		// configuration naming a door it cannot open.
		restored := "config.yaml and the certificates were restored"
		if werr := restoreConfig(); werr != nil {
			restored = "config.yaml could not be restored: " + werr.Error()
		}
		if !byo {
			if rerr := tlsca.Rollback(paths, previousSet); rerr != nil {
				restored += "; the certificates could not be restored: " + rerr.Error()
			}
		}
		if ambiguous {
			// An engine whose answer was lost is asked to re-read the
			// restored configuration, so what it serves matches the disk
			// again even if it had applied the candidate.
			if rerr := call(func(ctx context.Context) error {
				_, err := cl.Reload(ctx)
				return err
			}); rerr == nil {
				restored += "; the engine re-read the restored configuration"
			} else {
				// What the engine serves is in its own journal: it logs
				// the gateway posture at every start and reload, and no
				// CLI command prints it (plan S10 drift audit — this line
				// named `podaro system`, which is a group with nothing to
				// run).
				restored += "; the engine could not be asked to re-read it (what it serves is in journalctl --user -u podaro)"
			}
		}
		var pe *pdr.Error
		if errors.As(err, &pe) && pe.Code == pdr.CodeEngineUnavailable {
			return fail("gateway", fmt.Errorf("engine not running — podaro system install (%s)", restored))
		}
		return fail("gateway", fmt.Errorf("%v (%s)", err, restored))
	}
	if !byo {
		tlsca.Commit(previousSet) // kept for the rollback above; the door is open
	}
	results = append(results, StepResult{Label: "gateway", Detail: fmt.Sprintf("listening on %s (TLS)", gw.Address)})

	facts.IP = o.IP
	if facts.IP == "" {
		facts.IP = DetectIP()
	}
	RenderSetupBlock(p, results, &facts)
	return nil
}

// RenderSetupBlock renders step-4 results in the INSTALL layout; facts
// non-nil appends the trust, DNS, and next-action lines.
func RenderSetupBlock(p *render.Printer, results []StepResult, facts *SetupFacts) {
	for _, r := range results {
		switch {
		case r.Err != nil:
			p.Check(render.Fail, r.Label, setupColumn, r.Err.Error())
		case r.Skipped:
			p.Check(render.Skip, r.Label, setupColumn, r.Detail)
		default:
			p.Check(render.Pass, r.Label, setupColumn, r.Detail)
		}
	}
	if facts == nil {
		return
	}
	p.Blank()
	if !facts.BYO {
		p.Plain("trust the CA on machines that will browse labs:")
		p.Indent("Linux", 9, "sudo trust anchor "+facts.CAPath)
		p.Indent("macOS", 9, "open ca.crt → Keychain → always trust")
		p.Indent("Windows", 9, "certutil -addstore -user Root ca.crt")
		p.Blank()
	}
	p.Plain("point dns at this host (one wildcard record covers every lab):")
	p.Indent("*."+facts.Domain, 21, "A    "+facts.IP)
	p.Blank()
	p.NextAction("podaro auth setup")
}

// writeConfig marshals the configuration surface (User Manual §4) at
// mode 0600, keeping any observability or tls block the operator set.
// definitiveAnswer reports whether an error from the engine is its answer
// — an envelope it wrote, or a gateway it reported closed — rather than a
// transport failure after which its outcome is unknown.
func definitiveAnswer(err error) bool {
	var pe *pdr.Error
	if errors.As(err, &pe) {
		return pe.Code != pdr.CodeEngineUnavailable
	}
	return err.Error() == "engine did not open the gateway"
}

// gatewayOf reads the gateway posture out of GET /system's body.
func gatewayOf(sys map[string]any) sysinfo.Gateway {
	var g sysinfo.Gateway
	host, _ := sys["host"].(map[string]any)
	raw, err := json.Marshal(host["gateway"])
	if err == nil {
		_ = json.Unmarshal(raw, &g)
	}
	return g
}

// stageCA prepares the staging directory with a copy of the live CA (when
// there is one), so EnsureCA reuses or rotates it there and nothing live
// changes until publishCA. A publish an earlier run left half done is
// completed first.
func stageCA(live, staging tlsca.Paths) error {
	if err := tlsca.Recover(live); err != nil {
		return err
	}
	// Leftovers of a finished publish or rollback are dropped here, under
	// the setup lock, where no transaction can be in flight — never by
	// the engine, whose reload is a running setup's next step and whose
	// previous set is that setup's way back.
	if err := tlsca.Tidy(live); err != nil {
		return err
	}
	if err := os.RemoveAll(staging.Dir); err != nil { // a crash's leftover
		return err
	}
	if err := os.MkdirAll(staging.Dir, 0o700); err != nil {
		return err
	}
	for _, f := range [][2]string{{live.CACert(), staging.CACert()}, {live.CAKey(), staging.CAKey()}} {
		raw, err := os.ReadFile(f[0])
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		info, err := os.Stat(f[0])
		if err != nil {
			return err
		}
		if err := fsx.WriteFile(f[1], raw, info.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

func writeConfig(path string, cfg *config.Config) error {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	header := "# Podaro configuration (User Manual §4) — written by podaro setup\n"
	return writeRaw(path, append([]byte(header), raw...))
}

// writeRaw lands bytes at path (0600) durably: a temporary file synced
// before the one rename, the directory synced after (fsx.WriteFile).
func writeRaw(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return fsx.WriteFile(path, data, 0o600)
}

// DetectIP finds the address the host would use toward the internet — a
// routing decision only; no packet is sent (UDP connect just picks the
// source). Falls back to the first global unicast interface address.
func DetectIP() string {
	if conn, err := net.Dial("udp4", "203.0.113.1:9"); err == nil {
		ip := conn.LocalAddr().(*net.UDPAddr).IP
		conn.Close()
		if ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
			return ip.String()
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && ipn.IP.IsGlobalUnicast() {
				return ipn.IP.String()
			}
		}
	}
	return "<this host's address>"
}

// GatewayStatus is re-exported for the CLI's status line.
type GatewayStatus = sysinfo.Gateway

// authColumn is the step-5 block's detail column (INSTALL §2).
const authColumn = 20

// RenderAuthSetupBlock renders INSTALL §2 step 5's outcome: the two rows,
// then the console URL last and alone (UX §7). consoleURL empty means
// setup has not run yet.
func RenderAuthSetupBlock(p *render.Printer, reset bool, consoleURL string) {
	if reset {
		p.Check(render.Pass, "operator account reset", 0, "")
	} else {
		p.Check(render.Pass, "operator account created", 0, "")
	}
	p.Check(render.Pass, "audit", authColumn, "recorded to system evidence")
	p.Blank()
	if consoleURL != "" {
		p.Plain("console: " + consoleURL)
	} else {
		p.Plain("console: not yet — podaro setup --domain <domain> opens the gateway")
	}
}

// ConsoleURL renders https://<domain>[:port].
func ConsoleURL(domain string, port int) string {
	if port == 443 {
		return "https://" + domain
	}
	return fmt.Sprintf("https://%s:%d", domain, port)
}

// readFile reads config.yaml for the rollback snapshot. A test seam: an
// I/O fault here must stop setup before anything is replaced.
var readFile = os.ReadFile

// loadConfig reads a written configuration back; a seam so a test can
// make that read fail after the write has landed.
var loadConfig = config.Load

// lockSetup takes the state directory's setup lock for the life of the
// call. Advisory (flock) and released by the kernel when the process
// ends, so an interrupted run never leaves it behind; a second setup
// while it is held is PDR-E023.
func lockSetup(stateDir string) (func(), error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	unlock, err := tlsca.Lock(stateDir)
	if errors.Is(err, tlsca.ErrLocked) {
		// The same lock a gateway renewal takes: a run that finds it held
		// is refused, not queued (round 32 shares it with the renewal).
		e := pdr.New(pdr.CodeSetupFailed, "another podaro setup is running")
		e.Cause = "setup.lock is held by a live process"
		e.Next = "wait for it to finish, then re-run podaro setup"
		return nil, e
	}
	if err != nil {
		return nil, err
	}
	return unlock, nil
}

func setupLockPath(stateDir string) string { return tlsca.LockPath(stateDir) }

// afterSetupLock is a test seam: called once the lock is held, before
// the configuration is read.
var afterSetupLock func()
