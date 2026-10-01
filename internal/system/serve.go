// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/api"
	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/console"
	"github.com/jeremiahjrross/podaro/internal/doctor"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/gateway"
	"github.com/jeremiahjrross/podaro/internal/legal"
	"github.com/jeremiahjrross/podaro/internal/observe"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
	"github.com/jeremiahjrross/podaro/internal/sysinfo"
)

// EnvRuntime selects the container runtime: "podman" (default) or "fake"
// — the on-disk fake used by the S4 acceptance scripts and by hosts
// without Podman. Never a product setting; it exists so the job engine's
// resumption and reconcile paths can be proven where containers cannot.
const EnvRuntime = "PODARO_RUNTIME"

// Serve is `podaro engine serve`: open state, pick the runtime, resume
// and reconcile (roadmap §9: reconcile-on-start), hold the local socket
// door (API §1), and — once `podaro setup` has given it a domain and
// certificates — the TLS gateway on the network door (plan S5), until
// SIGINT/SIGTERM.
func Serve(out io.Writer) error {
	stateDir := config.StateDir()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	lock, err := lockEngine(stateDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	store, err := state.OpenSQLite(filepath.Join(stateDir, "state.db"))
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	defer store.Close()

	rt, rtName, err := SelectRuntime(stateDir)
	if err != nil {
		return err
	}
	if closer, ok := rt.(interface{ Close() }); ok {
		defer closer.Close()
	}
	if err := requireRootless(context.Background(), rtName, rt.Info); err != nil {
		return err
	}

	logf := func(format string, args ...any) { fmt.Fprintf(out, format+"\n", args...) }
	var gw *gateway.Gateway
	var eng *engine.Engine
	// The observability export, if the operator configured one (Manual
	// §4). A config that cannot be read leaves it off — the engine
	// serves; a config that names a destination it cannot build refuses
	// to start, because an export the operator asked for and did not get
	// is worse than a refusal that says why.
	cfg, cfgErr := config.Load(config.Path())
	var exporter *observe.Exporter
	if cfgErr == nil && cfg != nil {
		exporter, err = observe.New(observe.Options{
			Config: cfg.Observability,
			Filter: func() (func(string) string, error) { return eng.ExportFilter() },
		})
		if err != nil {
			return fmt.Errorf("observability export: %w", err)
		}
	}
	if exporter != nil {
		// Armed before anything exists that can log. `observe.Journal`
		// queues from the moment the logger is wrapped, and a queue
		// nobody flushes is a line that never leaves: a start-up that
		// logged a resumed job and then failed on a later store read
		// wrote to the journal and never attempted the export it was
		// configured for. The deferred flush runs
		// on every return, including that one.
		go exporter.Run()
		defer exporter.Close()
	}
	// One logger from here on. The engine, the authentication sweeper,
	// the gateway and this function all write through it, so wrapping it
	// here is what makes the documented promise true for all of them —
	// and leaves no unwrapped logger in scope to pass by mistake.
	logf = observe.Journal(logf, exporter)
	eng = engine.New(engine.Options{
		Store: store, Runtime: rt, StateDir: stateDir,
		CatalogDir: filepath.Join(stateDir, "catalog"),
		Logf:       logf,
		Address:    func() (string, int) { return gw.Address() },
		Observe:    exporter,
	})
	authSvc := auth.NewService(store, filepath.Join(stateDir, "auth.json"))
	authSvc.Logf = logf
	renderer := console.Must()

	system := func() sysinfo.Info {
		cfg, _ := config.Load(config.Path())
		var pf *doctor.PodmanFacts
		if info, err := rt.Info(context.Background()); err == nil {
			pf = &doctor.PodmanFacts{Version: info.Version, Rootless: info.Rootless}
		}
		info := BuildInfo(cfg, pf)
		info.Runtime = rtName
		info.Host.Gateway = gw.Status()
		return info
	}
	// The legal summary the two public routes serve (GET /system/legal,
	// /legal): built once from the binary and the operator's
	// legal.source_url, and rebuilt when a reload re-reads the
	// configuration — static in between, so a public request reads no
	// file and no state.
	var legalInfo atomic.Pointer[legal.Info]
	setLegal := func(c *config.Config) {
		info, err := legal.Build(operatorSourceURL(c))
		if err != nil {
			logf("legal: %v", err)
			return
		}
		legalInfo.Store(&info)
	}
	setLegal(cfg)
	refreshLegalFiles(stateDir, logf)
	reload := newReloader(func() *gateway.Gateway { return gw }, stateDir, setLegal)
	apiSrv := api.New(api.Options{
		Engine: eng, System: system, Auth: authSvc, Console: renderer,
		Address: func() (string, int) { return gw.Address() },
		Reload:  reload,
		Observe: exporter,
		Legal: func() legal.Info {
			if p := legalInfo.Load(); p != nil {
				return *p
			}
			info, _ := legal.Build("")
			return info
		},
	})
	gw = gateway.New(gateway.Options{API: apiSrv, Engine: eng, Console: renderer, Assets: podaro.ConsoleAssets(), Logf: logf})
	defer gw.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dir := config.RuntimeDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sock := filepath.Join(dir, "api.sock")
	if err := claimSocket(sock); err != nil {
		return err
	}
	// Bind and secure the socket first — every fallible step of startup
	// happens before any job is launched, so a failure here tears down a
	// process with no work in flight — then resume and reconcile, and
	// only then serve: a request that reaches the engine finds its jobs
	// already queued, never a pre-reconcile picture of the instances
	// (connections made in between wait in the listen backlog).
	l, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	defer os.Remove(sock)
	if err := os.Chmod(sock, 0o600); err != nil {
		l.Close()
		return err
	}
	srv := &http.Server{Handler: apiSrv.SocketHandler(), ReadHeaderTimeout: 10 * time.Second}
	// Resume and reconcile before either door answers (D38: "the engine
	// answers" means "the engine is ready" for every client, the network
	// door included): a Start that fails launches nothing and the process
	// stops with nothing in flight.
	if err := eng.Start(ctx); err != nil {
		l.Close()
		return fmt.Errorf("reconcile-on-start: %w", err)
	}
	// The network door opens only when setup has run; a gateway that
	// cannot bind is logged loudly and the socket door still serves, so
	// the operator can fix the port and re-run setup.
	// The configuration is read again here rather than reused: the
	// gateway opens after reconcile, and `podaro setup` may have written
	// between this process's start and now.
	posture := "socket-only"
	if cfg, err := config.Load(config.Path()); err != nil {
		logf("config: %v", err)
	} else if st, err := gw.Apply(cfg, stateDir); err != nil {
		var pe *pdr.Error
		if errors.As(err, &pe) {
			logf("gateway: %s %s · %s · next: %s", pe.Code, pe.Message, pe.Cause, pe.Next)
		} else {
			logf("gateway: %v", err)
		}
	} else if st.Listening {
		posture = fmt.Sprintf("gateway %s (TLS) for *.%s", st.Address, st.Domain)
	}
	// Through the shared logger, like every other operational line: the
	// banner and the stop lines below were written straight to the
	// journal writer and so reached no configured destination, which is
	// the same gap round 20 closed one level up.
	logf("podaro engine v%s · runtime %s · %s · %s", podaro.Version(), rtName, posture, sock)
	if exporter != nil {
		p := exporter.Posture()
		for _, sig := range []struct {
			name string
			s    observe.SignalPosture
		}{{"logs", p.Logs}, {"metrics", p.Metrics}, {"traces", p.Traces}} {
			if sig.s.Exporter == "off" {
				continue
			}
			line := fmt.Sprintf("observability export · %s → %s %s", sig.name, sig.s.Exporter, sig.s.Endpoint)
			if sig.s.Insecure {
				// The warned half of "explicit and warned" (threat model
				// B10): an unverified destination says so every start.
				line += " · WARNING: insecure — this destination's certificate is not verified"
			}
			logf("%s", line)
		}
	}
	done := make(chan struct{})
	go authSvc.Run(done, 30*time.Second)
	go gw.Run(done)

	errc := make(chan error, 1)
	go func() {
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
		// A server that stopped accepting is still an engine with jobs in
		// flight: the same orderly stop as a signal, then the error.
	}
	close(done)
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	gw.Close()
	if err := eng.Shutdown(shutdown); err != nil {
		// The dependencies close now regardless (the process is stopping);
		// the jobs' records stay running and resume on the next start.
		logf("podaro engine stop: %v; their records resume on the next start", err)
	}
	if serveErr != nil {
		return fmt.Errorf("serve: %w", serveErr)
	}
	logf("podaro engine stopped · jobs are journaled and resume on the next start")
	return nil
}

// SelectRuntime returns the configured runtime and its name.
func SelectRuntime(stateDir string) (runtime.Runtime, string, error) {
	switch os.Getenv(EnvRuntime) {
	case "", "podman":
		return runtime.NewPodman(), "podman", nil
	case "fake":
		f, err := runtime.NewFake(FakeWorldPath(stateDir))
		if err != nil {
			return nil, "", err
		}
		return f, "fake", nil
	default:
		return nil, "", fmt.Errorf("%s=%q: podman or fake", EnvRuntime, os.Getenv(EnvRuntime))
	}
}

// requireRootless is the engine-side half of invariant 8 (roadmap §1;
// threat model B4): with the Podman runtime the engine refuses to serve
// unless `podman info` answers and reports rootless. The fake runtime is
// exempt (it has no privilege to speak of).
func requireRootless(ctx context.Context, name string, info func(context.Context) (runtime.Info, error)) error {
	if name != "podman" {
		return nil
	}
	i, err := info(ctx)
	if err != nil {
		e := pdr.New(pdr.CodeRuntimeFailed, "cannot talk to Podman")
		e.Cause = err.Error()
		e.Next = "podaro doctor · podman info"
		return e
	}
	if !i.Rootless {
		return pdr.New(pdr.CodeRuntimeRootful, "Podman %s is running rootful; the engine will not serve labs as root", i.Version)
	}
	return nil
}

// lockEngine takes the state directory's exclusive lock for the life of
// the process. One engine per state directory is what makes the
// exclusive-job slot (API §4) a fact: a second `engine serve` would
// otherwise resume the same journaled jobs beside the first. The lock is
// advisory (flock) and released by the kernel when the process dies, so
// an unclean stop never leaves it behind.
func lockEngine(stateDir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(stateDir, "engine.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		pe := pdr.New(pdr.CodeEngineRunning, "another engine already serves %s", stateDir)
		pe.Cause = "engine.lock is held by a live process"
		pe.Next = "systemctl --user status podaro · stop that engine before starting another"
		return nil, pe
	}
	return f, nil
}

// claimSocket removes a socket file only when nothing answers on it — the
// leftover of an unclean stop. A socket that accepts a connection belongs
// to a live engine and is never unlinked from under it.
func claimSocket(sock string) error {
	if _, err := os.Lstat(sock); err != nil {
		return nil // nothing there
	}
	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err == nil {
		conn.Close()
		pe := pdr.New(pdr.CodeEngineRunning, "an engine is already answering on %s", sock)
		pe.Cause = "the socket accepted a connection"
		pe.Next = "systemctl --user status podaro · stop that engine before starting another"
		return pe
	}
	return os.Remove(sock)
}

// FakeWorldPath is where the fake runtime keeps its world.
func FakeWorldPath(stateDir string) string {
	return filepath.Join(stateDir, "fake-runtime.json")
}

// newReloader is POST /system/reload's act: re-read config.yaml and apply
// it. Reloads are applied one at a time, in the order they read the
// configuration — the read and the apply are one step under a lock — so
// a reload whose answer was lost on the socket can never apply, late, a
// configuration a later reload has replaced: a handler delayed before
// its read reads what the restore wrote; one that read the candidate
// applies it before the restorative reload does, never after. What
// setup then reads from GET /system is therefore what the last reload
// applied, and the live gateway ends where the disk is.
func newReloader(gw func() *gateway.Gateway, stateDir string, onConfig func(*config.Config)) func(context.Context) (sysinfo.Gateway, error) {
	var mu sync.Mutex
	return func(ctx context.Context) (sysinfo.Gateway, error) {
		mu.Lock()
		defer mu.Unlock()
		cfg, err := config.Load(config.Path())
		if err != nil {
			return sysinfo.Gateway{}, err
		}
		if afterReloadRead != nil {
			afterReloadRead()
		}
		if onConfig != nil {
			onConfig(cfg)
		}
		return gw().Apply(cfg, stateDir)
	}
}

// operatorSourceURL is config.yaml's legal.source_url, or "" when the
// configuration holds none or could not be read.
func operatorSourceURL(c *config.Config) string {
	if c == nil || c.Legal == nil {
		return ""
	}
	return c.Legal.SourceURL
}

// refreshLegalFiles keeps the legal files on disk the running binary's:
// <state>/legal/, when `system install` wrote it, and the notices
// install.sh placed beside the binary, when it placed them — so after
// `system upgrade` replaced the binary, both say what the new one says.
// Neither is created here: that is the install's act, and doctor names a
// missing <state>/legal/. A failure is logged and the engine serves on:
// `podaro legal` and /legal read the binary itself.
func refreshLegalFiles(stateDir string, logf func(string, ...any)) {
	dir := filepath.Join(stateDir, "legal")
	if _, err := os.Stat(dir); err == nil {
		if err := legal.WriteDir(dir); err != nil {
			logf("legal: refreshing %s: %v", dir, err)
		}
	}
	if exe, err := os.Executable(); err == nil {
		if exe, err = filepath.EvalSymlinks(exe); err == nil {
			if _, err := legal.RefreshBeside(exe); err != nil {
				logf("legal: refreshing the notices beside %s: %v", exe, err)
			}
		}
	}
}

// afterReloadRead is a test seam: called by a reload between reading the
// configuration and applying it.
var afterReloadRead func()
