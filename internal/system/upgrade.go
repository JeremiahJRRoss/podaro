// SPDX-License-Identifier: AGPL-3.0-only

package system

// `podaro system upgrade` (INSTALL §6, plan S9): fetch a release, prove
// it is the release, put the state somewhere safe, and swap the binary.
//
// It is the same act INSTALL §1's install script performs, minus the
// part about finding a home for the binary: resolve the version,
// download it and the release's `SHA256SUMS`, verify the digest
// *locally* before anything is replaced, and move it into place. Nothing
// here runs as root, and nothing is fetched that the operator did not
// ask for — this is the one command in Podaro that reaches the network
// on its own behalf, and it reaches it only when run.
//
// The order is chosen so that every failure leaves a working engine:
// the download and the verification happen first, into a temporary file
// beside the binary; the state backup happens next, because it is the
// way back; the binary is replaced by one rename; and only then is the
// service restarted. A failure before the rename has changed nothing at
// all.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/fsx"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
	podruntime "github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// DefaultReleaseBase is where a release lives: the releases of the
// repository the root SOURCE file names — the destination the owner gave
// on 2026-09-23 (the reconciliation plan's R7) — which is where `podaro
// legal` says official releases are published; a test holds the two to
// one coordinate. An operator on a host with no route out points `--from`
// at a mirror they filled themselves — an air-gapped lab is a first-class
// citizen (INSTALL §5), and an upgrade that could only reach the internet
// would make it a second-class one. A development build from before R7
// names an earlier location, where nothing was ever published; `--from`
// with this one upgrades it (INSTALL §6).
const DefaultReleaseBase = "https://github.com/JeremiahJRRoss/podaro/releases"

// upgradeColumn is the detail column of the §6 block.
const upgradeColumn = 30

// UpgradeOptions narrow an upgrade.
type UpgradeOptions struct {
	// Base is the release location; empty means DefaultReleaseBase.
	Base string
	// Version pins what to install; empty means whatever the release
	// location calls latest.
	Version string
	// Client fetches; nil means a plain client with a timeout.
	Client *http.Client
	// Exe is the binary to replace; empty means the running one.
	Exe string
	// Restart restarts the service; nil means systemctl --user.
	Restart func() error
	// Now is the clock (tests).
	Now func() time.Time
	// Containers opens the runtime for the preflight's read of an
	// unsupported instance's containers; nil means the runtime the
	// engine is configured with, read-only (readContainers).
	Containers func() (podruntime.ContainerReader, error)
}

// Upgrade performs the §6 sequence, rendering the board the manual
// shows.
func Upgrade(p *render.Printer, o UpgradeOptions) error {
	if o.Base == "" {
		o.Base = DefaultReleaseBase
	}
	o.Base = strings.TrimRight(o.Base, "/")
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 10 * time.Minute}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Restart == nil {
		o.Restart = restartService
	}
	if o.Containers == nil {
		o.Containers = func() (podruntime.ContainerReader, error) { return readContainers(config.StateDir()) }
	}
	// One upgrade at a time, for the whole sequence. Two invocations of
	// the old binary can overlap: the slower one is still downloading
	// while the first replaces the binary, restarts it and lets the new
	// engine migrate the state — and it then runs its own backup step
	// and writes the *migrated* database over `state.db.bak-v<old>`.
	// That file is half of the rollback §6 documents, since an older
	// binary refuses a schema a newer one migrated (PDR-E211), so
	// overwriting it leaves no backup the old binary can open anywhere.
	// Held until Upgrade returns, which is past
	// the restart.
	lock, err := lockUpgrade(config.StateDir())
	if err != nil {
		return err
	}
	defer lock.Close()

	exe := o.Exe
	if exe == "" {
		found, err := os.Executable()
		if err != nil {
			return upgradeFailed("locate this binary", err)
		}
		if resolved, err := filepath.EvalSymlinks(found); err == nil {
			found = resolved
		}
		exe = found
	}
	current := podaro.Version()

	// 0. The preflight (the reconciliation plan's R3): what an earlier
	// build left that this release does not operate — a retired template
	// in the catalog, an instance created from one and its running
	// containers — is listed before anything is fetched. It is reported,
	// not refused: the engine isolates such an instance from reconcile
	// whichever release serves it. A state database whose instance rows
	// cannot be read is refused, because then nothing can say what is
	// isolated, and nothing has been replaced.
	inv, err := inventoryRetired(context.Background(), config.StateDir(), o.Containers)
	if err != nil {
		return upgradeFailed("read the instance rows of "+filepath.Join(config.StateDir(), "state.db"), err)
	}
	inv.render(p)

	// 1. Which version. A pinned one is taken as written; otherwise the
	// release location is asked, and its answer is what it says.
	target := o.Version
	if target == "" {
		v, err := latestVersion(o)
		if err != nil {
			return upgradeFailed("ask "+shownURL(o.Base)+" for the latest release", err)
		}
		target = v
	}
	target = strings.TrimPrefix(target, "v")
	if target == current {
		p.Check(render.Pass, "already current", upgradeColumn, "engine v"+current)
		p.Blank()
		p.Plain("nothing to do.")
		return nil
	}
	if older(target, current) {
		e := pdr.New(pdr.CodeUpgradeRefused, "v%s is older than the running v%s", target, current)
		e.Cause = "migrations are forward-only: an older binary refuses a state database a newer one migrated (PDR-E211)"
		e.Next = "to roll back, restore the binary and the pre-upgrade state backup together — " +
			filepath.Join(config.StateDir(), "state.db.bak-v"+current)
		return e
	}

	// 2. Download and verify, both before anything is replaced. The
	// download's row is written when it finishes, carrying what it
	// fetched: the alternative is a row that claims a size before it
	// knows one.
	asset := AssetName(target)
	tmp, size, err := download(o, releaseURL(o.Base, target, asset), filepath.Dir(exe))
	if err != nil {
		return upgradeFailed("download "+asset, err)
	}
	defer os.Remove(tmp)
	p.Check(render.Progress, "downloading podaro v"+target, upgradeColumn, humanSize(size))

	sums, err := fetch(o, releaseURL(o.Base, target, "SHA256SUMS"))
	if err != nil {
		return upgradeFailed("download SHA256SUMS", err)
	}
	want, ok := digestOf(string(sums), asset)
	if !ok {
		e := pdr.New(pdr.CodeUpgradeRefused, "the release manifest does not name %s", asset)
		e.Cause = "SHA256SUMS carries no line for this platform's binary"
		e.Next = "check the release at " + shownURL(o.Base) + " · or --from a mirror that carries it"
		return e
	}
	got, err := digestFile(tmp)
	if err != nil {
		return upgradeFailed("hash the download", err)
	}
	if got != want {
		// The one refusal that matters. Nothing has been replaced, and
		// the download is removed with the deferred cleanup.
		e := pdr.New(pdr.CodeUpgradeRefused, "the download of podaro v%s does not match the release manifest", target)
		e.Cause = fmt.Sprintf("SHA256SUMS says %s, the file is %s", short(want), short(got))
		e.Next = "the download is discarded and nothing was replaced · re-run, or fetch the release by hand and verify it yourself"
		return e
	}
	p.Check(render.Pass, "checksum verified", upgradeColumn, "")

	// 3. The way back, before the way forward.
	stateDB := filepath.Join(config.StateDir(), "state.db")
	before, err := state.SchemaVersionOf(stateDB)
	if err != nil {
		return upgradeFailed("read the state schema version", err)
	}
	backup := stateDB + ".bak-v" + current
	switch copied, err := backupState(stateDB, backup); {
	case err != nil:
		return upgradeFailed("back up "+stateDB, err)
	case !copied:
		p.Check(render.Skip, "state backed up", upgradeColumn, "no state database yet")
	default:
		p.Check(render.Pass, "state backed up", upgradeColumn, "state.db → "+filepath.Base(backup))
	}

	// 4. One rename, flushed. Until this line the running install is
	// untouched, and past it the replacement is durable — the restart
	// below hands the new engine the state, which it migrates forward.
	switch replaced, err := replaceBinary(tmp, exe); {
	case err != nil && !replaced:
		return upgradeFailed("replace "+exe, err)
	case err != nil:
		// The rename landed and only its flush did not: saying nothing
		// was replaced would be false, and would send an operator to the
		// wrong recovery.
		e := upgradeFailed("flush the replacement of "+exe, err)
		e.(*pdr.Error).Next = "the new binary is in place but not yet durable and the service was not restarted · fix the cause and re-run podaro system upgrade"
		return e
	}
	if err := o.Restart(); err != nil {
		e := upgradeFailed("restart the service", err)
		e.(*pdr.Error).Next = "the new binary is in place: systemctl --user restart podaro · journalctl --user -u podaro"
		return e
	}
	p.Check(render.Pass, "binary replaced · service restarted", upgradeColumn, "")

	// 5. What the new engine did with the state it found.
	after, serr := state.SchemaVersionOf(stateDB)
	switch {
	case serr != nil:
		p.Check(render.Warn, "migrations", upgradeColumn, "cannot be read: "+serr.Error())
	case after > before:
		p.Check(render.Pass, "migrations", upgradeColumn,
			fmt.Sprintf("%d applied, forward-only", after-before))
	default:
		p.Check(render.Pass, "migrations", upgradeColumn, "none pending")
	}
	// An engine that cannot be read is a warning on the board, not a
	// row that quietly disappears: the restart wait is what should have
	// caught it, and if it did not, the operator is told.
	switch names, unsupported, err := reattached(); {
	case err != nil:
		p.Check(render.Warn, "instances", upgradeColumn, "cannot be read: "+err.Error())
	case len(names) == 0 && len(unsupported) == 0:
		p.Check(render.Pass, "instances", upgradeColumn, "none")
	default:
		// An unsupported instance is not "reattached": the new engine
		// left it as it found it, and the row says that instead.
		var parts []string
		if len(names) > 0 {
			parts = append(parts, strings.Join(names, ", ")+" reattached · unaffected")
		}
		if len(unsupported) > 0 {
			parts = append(parts, strings.Join(unsupported, ", ")+" unsupported · left as they are")
		}
		p.Check(render.Pass, "instances", upgradeColumn, strings.Join(parts, " · "))
	}
	p.Blank()
	p.Plain("engine v" + target + " · api v1alpha1")
	return nil
}

// AssetName is the release asset for this host: the same name INSTALL
// §1's script resolves.
func AssetName(version string) string {
	return "podaro-" + version + "-linux-" + runtime.GOARCH
}

func releaseURL(base, version, asset string) string {
	return base + "/download/v" + version + "/" + asset
}

// latestVersion asks the release location what it calls latest. The two
// shapes are answered as what they are, rather than by looking for a
// substring in whatever came back:
//
//   - GitHub redirects `/releases/latest` to `/releases/tag/vX.Y.Z`, so
//     the answer is in the `Location` header. Following that redirect —
//     which the default client does — lands on the release *page*, whose
//     HTML carries a `/tag/` link for every release the repository has;
//     reading "the text after the last /tag/" then named some other
//     version, or none.
//   - A mirror answers 200 with a one-line file holding the version, or
//     the same `/tag/vX.Y.Z` line GitHub would have redirected to (which
//     is what §5's `--from` mirror and hack/upgrade_test.sh write).
//
// Redirects are therefore not followed here, and each answer is read
// where its own version lives. The 200 branch reads the *first line*
// and refuses anything with markup in it, so a page that arrives where
// a one-line answer was expected is an error rather than a version
// scraped out of whatever links it carries.
// shownURL is the release location — or any URL built from it — as it
// may be printed. `--from` may
// point at a private mirror behind basic auth, so the credential is real
// and belongs in the request — but not in an error, a hint, or the bug
// report they get pasted into (invariant 6). It is the same rule that
// keeps an observability endpoint's userinfo out of the posture, asked
// of the other URL an operator hands this engine (found sweeping that fix).
//
// It takes any URL, not just the base, because the location also travels
// as a value derived from it: `releaseURL(o.Base, …)` is what `fetch` and
// `download` print on a non-200. Round 9 redacted the five places that
// name `o.Base` and missed the four that do not, which is what asking
// "where is this variable mentioned" gets you instead of "where can this
// value reach a message".
//
// Go's own client already replaces the password in a transport error's
// URL with `***`, keeping the user name; these are our strings, where
// nothing replaced anything.
func shownURL(raw string) string {
	if s := config.WithoutUserinfo(raw); s != "" {
		return s
	}
	return "the release location"
}

func latestVersion(o UpgradeOptions) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, o.Base+"/latest", nil)
	if err != nil {
		return "", err
	}
	client := *o.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var text string
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		loc := resp.Header.Get("Location")
		i := strings.LastIndex(loc, "/tag/")
		if i < 0 {
			return "", fmt.Errorf("%s/latest redirected somewhere that names no tag", shownURL(o.Base))
		}
		text = loc[i+len("/tag/"):]
	case resp.StatusCode == http.StatusOK:
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return "", err
		}
		line, _, _ := strings.Cut(strings.TrimSpace(string(raw)), "\n")
		if strings.ContainsAny(line, "<>") {
			return "", fmt.Errorf("%s/latest answered with a page, not a version", shownURL(o.Base))
		}
		if i := strings.LastIndex(line, "/tag/"); i >= 0 {
			line = line[i+len("/tag/"):]
		}
		text = line
	default:
		return "", fmt.Errorf("%s/latest answered %s", shownURL(o.Base), resp.Status)
	}
	// An empty answer is a refusal, not a panic. The `+ " "` here was
	// meant to guarantee a field; `strings.Fields` ignores whitespace, so
	// a mirror still being filled — an empty `latest` file — indexed [0]
	// of an empty slice and took the command down instead of leaving the
	// installation untouched with PDR-E025.
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return "", fmt.Errorf("%s/latest answered with nothing", shownURL(o.Base))
	}
	text = strings.TrimSpace(strings.TrimPrefix(fields[0], "v"))
	if text == "" || strings.ContainsAny(text, "/ <>") {
		return "", fmt.Errorf("%s/latest did not answer with a version", shownURL(o.Base))
	}
	return text, nil
}

func fetch(o UpgradeOptions, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", shownURL(url), resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// download writes the asset beside the binary it will replace, so the
// rename that installs it is on one filesystem and therefore atomic.
func download(o UpgradeOptions, url, dir string) (path string, size int64, err error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := o.Client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("%s answered %s", shownURL(url), resp.Status)
	}
	f, err := os.CreateTemp(dir, ".podaro-upgrade-*")
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(resp.Body, 512<<20))
	if err != nil {
		os.Remove(f.Name())
		return "", 0, err
	}
	if err := f.Sync(); err != nil {
		os.Remove(f.Name())
		return "", 0, err
	}
	return f.Name(), n, nil
}

// digestOf finds an asset's line in a SHA256SUMS file. The format is the
// one sha256sum writes: the digest, two spaces, the name.
func digestOf(sums, asset string) (string, bool) {
	sc := bufio.NewScanner(strings.NewReader(sums))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		if strings.TrimPrefix(fields[1], "*") == asset {
			return strings.ToLower(fields[0]), true
		}
	}
	return "", false
}

func digestFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// backupState copies the state database beside itself. It is a copy and
// not a rename: the engine is still running and still holds the file,
// and the point of the backup is to have both.
//
// It is SQLite's own backup rather than a file copy. The store runs in
// WAL mode, so rows committed since the last checkpoint are in
// `state.db-wal` and not in `state.db` at all: copying the main file
// while the engine runs produces a backup that is missing the newest
// instances, jobs, credentials and evidence, or one torn mid-write —
// and an operator following the rollback instructions would restore it
// believing otherwise.
func backupState(src, dst string) (bool, error) {
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	// The new backup is made beside the old one and renamed over it only
	// when it is whole. Removing the old one first — which `vacuum into`
	// needs, since it refuses an existing file — meant a retried upgrade
	// destroyed the only rollback copy it had before making its
	// replacement: an interruption in that window left the binary intact
	// and the recovery point gone.
	tmp := dst + ".partial"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := state.BackupDatabase(src, tmp); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return false, err
	}
	// The rename is flushed the way every other rename onto a recovery
	// path in this tree is (`internal/auth`, `internal/tlsca`,
	// `system/setup.go`): a backup a power loss can undo is not a
	// backup. Failing here is safe — the backup is made before the
	// binary is touched, so the engine still runs the version it ran a
	// moment ago.
	if err := fsx.SyncDir(filepath.Dir(dst)); err != nil {
		return false, err
	}
	return true, nil
}

// replaceBinary puts the verified download where the old one was, mode
// 0755, by one rename — a partially written binary is never a binary
// anyone can run — and flushes the directory that now names it. The
// first return says whether the rename landed, so a caller can tell a
// replacement that never happened from one that is not yet durable.
//
// Round 8 flushed the backup's rename and left this one alone, on the
// reasoning that losing the replacement leaves the old binary in place,
// which is the safe direction. That was incomplete: the restart that
// follows runs the new engine, which migrates `state.db` forward, and
// then losing the rename leaves the *old* binary against a schema it
// refuses (PDR-E211) — the downgrade this command will not perform,
// arrived at by a power cut. The download's own
// bytes are already synced before the rename, so the name and the
// content become durable in that order.
func replaceBinary(tmp, exe string) (bool, error) {
	if err := os.Chmod(tmp, 0o755); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, exe); err != nil {
		return false, err
	}
	return true, fsx.SyncDir(filepath.Dir(exe))
}

// lockUpgrade takes the state directory's upgrade lock: advisory
// (flock), released by the kernel if the process dies, and a different
// file from the engine's own — the engine is running throughout an
// upgrade and holds `engine.lock` for its whole life.
func lockUpgrade(stateDir string) (*os.File, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, upgradeFailed("open "+stateDir, err)
	}
	f, err := os.OpenFile(filepath.Join(stateDir, "upgrade.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, upgradeFailed("open the upgrade lock", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		pe := pdr.New(pdr.CodeUpgradeRefused, "another upgrade is already running")
		pe.Cause = filepath.Join(stateDir, "upgrade.lock") + " is held by a live process"
		pe.Next = "wait for it to finish, then podaro system upgrade · a second upgrade beside the first would write the migrated state over the backup the first made"
		return nil, pe
	}
	return f, nil
}

func restartService() error {
	out, err := systemctl("restart", "podaro.service").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl --user restart podaro: %v: %s", err, strings.TrimSpace(string(out)))
	}
	_, err = awaitSocket()
	return err
}

// reattached names the instances the restarted engine found, and apart
// from them the ones it reports unsupported — an earlier build's
// instances of a retired template, which it neither reattaches to nor
// reconciles (the reconciliation plan's R3). Their containers belong to
// Podman, not to the engine process: a restart reattaches to them rather
// than disturbing them (INSTALL §6).
func reattached() (names, unsupported []string, err error) {
	sock := filepath.Join(config.RuntimeDir(), "api.sock")
	if _, err := os.Stat(sock); err != nil {
		return nil, nil, err
	}
	// Read over the socket rather than the state file: what matters is
	// what the running engine says it has.
	resp, err := socketClient(sock).Get(engineProbeURL)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	// The status first: the API's error envelope decodes into the
	// instance struct without complaint — unknown fields are ignored and
	// `instances` is simply absent — so a fault came back as an empty
	// list and the board printed "instances … none" as a pass, in the
	// one situation the warning row exists for.
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("the engine answered %s", resp.Status)
	}
	var out struct {
		Instances []struct {
			Name        string `json:"name"`
			Unsupported string `json:"unsupported"`
		} `json:"instances"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, nil, err
	}
	names = make([]string, 0, len(out.Instances))
	for _, i := range out.Instances {
		if i.Unsupported != "" {
			unsupported = append(unsupported, i.Name)
			continue
		}
		names = append(names, i.Name)
	}
	return names, unsupported, nil
}

// engineProbeURL is the read both the restart wait and the reattach
// report make: the cheapest thing the socket door answers.
const engineProbeURL = "http://podaro/api/v1alpha1/instances"

// socketClient dials the engine's local door and nothing else.
func socketClient(sock string) *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
}

// engineAnswers reports whether the engine is serving on that door. A
// bound socket is not an answer: the listener exists before reconcile
// runs, and reconcile is what can fail.
func engineAnswers(client *http.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, engineProbeURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the engine answered %s", resp.Status)
	}
	return nil
}

// older compares two versions by semantic-version precedence; a version
// this cannot read is not called older, because refusing an upgrade over
// a parse is worse than performing one.
//
// Pre-releases are compared, not discarded. Dropping the suffix made
// 1.0.0 and 1.0.0-rc1 equal, so `--to 1.0.0-rc1` from a released 1.0.0
// was not a downgrade and went ahead — installing older code over state
// the newer release had migrated, which is the one thing this guard
// exists to prevent.
func older(candidate, current string) bool {
	a, apre, aok := parseVersion(candidate)
	b, bpre, bok := parseVersion(current)
	if !aok || !bok {
		return false
	}
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return prereleaseLess(apre, bpre)
}

// prereleaseLess orders two pre-release suffixes by SemVer §11: a
// version with a pre-release is lower than one without; identifiers are
// compared field by field, numeric ones numerically and below
// alphanumeric ones, and a shorter run of equal fields is lower.
func prereleaseLess(a, b string) bool {
	if a == b {
		return false
	}
	if a == "" {
		return false // a release is never lower than its own pre-release
	}
	if b == "" {
		return true // …and its pre-release always is
	}
	af, bf := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(af) && i < len(bf); i++ {
		if af[i] == bf[i] {
			continue
		}
		an, aNum := allDigits(af[i])
		bn, bNum := allDigits(bf[i])
		switch {
		case aNum && bNum:
			return an < bn
		case aNum:
			return true // numeric identifiers rank below alphanumeric ones
		case bNum:
			return false
		default:
			return af[i] < bf[i]
		}
	}
	return len(af) < len(bf)
}

func allDigits(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// parseVersion reads MAJOR.MINOR.PATCH and returns the pre-release
// suffix beside it. Build metadata (+…) is ignored, as SemVer §10 says
// it must be: it takes no part in precedence.
func parseVersion(v string) ([3]int, string, bool) {
	var out [3]int
	var pre string
	if i := strings.IndexByte(v, "+"[0]); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre, v = v[i+1:], v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, "", false
	}
	for i, p := range parts {
		n, ok := allDigits(p)
		if !ok {
			return out, "", false
		}
		out[i] = n
	}
	return out, pre, true
}

func humanSize(n int64) string {
	const mb = 1 << 20
	if n >= mb {
		return fmt.Sprintf("%.1f MB", float64(n)/mb)
	}
	return fmt.Sprintf("%.1f KB", float64(n)/1024)
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12] + "…"
	}
	return digest
}

func upgradeFailed(what string, err error) error {
	e := pdr.New(pdr.CodeUpgradeRefused, "system upgrade could not %s", what)
	e.Cause = err.Error()
	e.Next = "nothing was replaced · fix the cause and re-run podaro system upgrade"
	return e
}
