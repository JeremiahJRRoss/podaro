// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/api"
	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// dropAfterCommit is a door that, when armed, lets a token creation run
// to completion and then closes the connection without answering — the
// engine's outcome unknown to the caller.
type dropAfterCommit struct {
	h       http.Handler
	armed   *bool
	foreign *bool // mint the name under another client's secret, then drop
	late    *bool // drop first, run the creation afterwards (round 17)
	wg      *sync.WaitGroup
	auth    *auth.Service // the door's own service, for the foreign mint
}

func (d dropAfterCommit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if *d.late && r.Method == http.MethodPost && r.URL.Path == api.Prefix+"/auth/tokens" {
		// The connection drops while the creation is still to run: a
		// list the client sends meanwhile finds nothing yet.
		*d.late = false
		raw, _ := io.ReadAll(r.Body)
		r2 := r.Clone(context.Background())
		r2.Body = io.NopCloser(bytes.NewReader(raw))
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			time.Sleep(300 * time.Millisecond)
			d.h.ServeHTTP(httptest.NewRecorder(), r2)
		}()
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close()
				return
			}
		}
		panic(http.ErrAbortHandler)
	}
	if *d.foreign && r.Method == http.MethodPost && r.URL.Path == api.Prefix+"/auth/tokens" {
		*d.foreign = false
		var req struct{ Name, Scope string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		if _, _, err := d.auth.CreateToken(req.Name, req.Scope, "other", auth.MechanismSocket); err != nil {
			panic(err)
		}
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close()
				return
			}
		}
		panic(http.ErrAbortHandler)
	}
	if *d.armed && r.Method == http.MethodPost && r.URL.Path == api.Prefix+"/auth/tokens" {
		d.h.ServeHTTP(httptest.NewRecorder(), r)
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close()
				return
			}
		}
		panic(http.ErrAbortHandler)
	}
	d.h.ServeHTTP(w, r)
}

// serveSocket runs the engine's socket door at the CLI's socket path.
func serveSocket(t *testing.T) *auth.Service {
	svc, _, _ := serveSocketDropping(t)
	return svc
}

// serveSocketDropping is serveSocket with a switch that makes the next
// token creation's answer never arrive.
func serveSocketDropping(t *testing.T) (*auth.Service, *bool, *bool) {
	t.Helper()
	svc, door := serveDoor(t)
	return svc, door.armed, door.foreign
}

// serveDoor is serveSocketDropping handing back the door itself, every
// switch included.
func serveDoor(t *testing.T) (*auth.Service, *dropAfterCommit) {
	t.Helper()
	armed, foreign, late := new(bool), new(bool), new(bool)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	store := state.NewMemory()
	authSvc := auth.NewService(store, filepath.Join(t.TempDir(), "auth.json"))
	srv := api.New(api.Options{Engine: engine.New(engine.Options{Store: store}), Auth: authSvc})
	if err := os.MkdirAll(filepath.Dir(socketPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", socketPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	door := &dropAfterCommit{h: srv.SocketHandler(), armed: armed, foreign: foreign, late: late, wg: &sync.WaitGroup{}, auth: authSvc}
	go func() {
		_ = http.Serve(l, *door)
	}()
	return authSvc, door
}

// A token whose secret is not durable is never live (API §2.3):
// the secret is made by the CLI and saved before the token
// is minted with it, so a tokens directory that refuses stops the command
// before any credential exists; a stale file from an interrupted run —
// one no token matches — is reclaimed; a file whose token exists is left
// alone; a token the engine refuses takes its file with it; and the saved
// secret authenticates.
func TestTokenCreateNeverLeavesASecretlessToken(t *testing.T) {
	authSvc, drop, foreign := serveSocketDropping(t)
	tokensDir := filepath.Join(config.StateDir(), "tokens")
	if err := os.MkdirAll(config.StateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	// The name is judged before it becomes a path: one that would escape
	// the tokens directory is refused before any file is looked at, and a
	// file at the escaped path survives.
	outside := filepath.Join(config.StateDir(), "x.token")
	if err := os.WriteFile(outside, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := run(t, "auth", "token", "create", "--name", "../x", "--scope", "read")
	if code != 2 || !strings.Contains(errOut, "PDR-E307") {
		t.Fatalf("a name that escapes the directory: code=%d err=%q", code, errOut)
	}
	if raw, _ := os.ReadFile(outside); string(raw) != "keep\n" {
		t.Fatalf("a file at the escaped path must survive: %q", raw)
	}
	if list, _ := authSvc.ListTokens(); len(list) != 0 {
		t.Fatalf("a token was minted under an escaping name: %+v", list)
	}
	// The tokens directory cannot exist: a file sits at its path.
	if err := os.WriteFile(tokensDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = run(t, "auth", "token", "create", "--name", "ci", "--scope", "read")
	if code != 1 || !strings.Contains(errOut, "PDR-E204") || !strings.Contains(errOut, "tokens") {
		t.Fatalf("a tokens directory that refuses: code=%d err=%q", code, errOut)
	}
	if list, _ := authSvc.ListTokens(); len(list) != 0 {
		t.Fatalf("a token was minted although its secret could not be saved: %+v", list)
	}
	if err := os.Remove(tokensDir); err != nil {
		t.Fatal(err)
	}
	// Something at the path that cannot be read is left exactly as it is
	// (round 12): it may be a live token's only secret.
	unreadable := filepath.Join(tokensDir, "ci.token")
	if err := os.MkdirAll(unreadable, 0o700); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = run(t, "auth", "token", "create", "--name", "ci", "--scope", "read")
	if code != 1 || !strings.Contains(errOut, "PDR-E204") {
		t.Fatalf("a path that cannot be read: code=%d err=%q", code, errOut)
	}
	if fi, err := os.Stat(unreadable); err != nil || !fi.IsDir() {
		t.Fatalf("what could not be read must be left alone: %v", err)
	}
	if list, _ := authSvc.ListTokens(); len(list) != 0 {
		t.Fatalf("no token may be minted over it: %+v", list)
	}
	if err := os.Remove(unreadable); err != nil {
		t.Fatal(err)
	}
	// A stale file from an interrupted run — a secret no token matches —
	// is reclaimed: the new secret replaces it and the token is minted.
	if err := os.MkdirAll(tokensDir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(tokensDir, "ci.token")
	if err := os.WriteFile(file, []byte("pdr_stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A token the engine refuses takes its file with it: nothing durable
	// and no credential remain (the scope is not one of the three).
	code, _, errOut = run(t, "auth", "token", "create", "--name", "ci", "--scope", "root")
	if code != 2 || !strings.Contains(errOut, "PDR-E307") { // a usage-shaped refusal exits 2
		t.Fatalf("a refused token: code=%d err=%q", code, errOut)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused token must take its file with it: %v", err)
	}
	if list, _ := authSvc.ListTokens(); len(list) != 0 {
		t.Fatalf("a refused token exists: %+v", list)
	}
	if err := os.WriteFile(file, []byte("pdr_stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := run(t, "auth", "token", "create", "--name", "ci", "--scope", "read")
	if code != 0 || errOut != "" || !strings.Contains(out, "token written to") {
		t.Fatalf("create over a stale file: code=%d out=%q err=%q", code, out, errOut)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode %04o", fi.Mode().Perm())
	}
	secret := strings.TrimSpace(string(raw))
	if secret == "pdr_stale" {
		t.Fatal("the stale secret must be replaced")
	}
	tok, err := authSvc.TokenFromBearer("Bearer " + secret)
	if err != nil || tok.Name != "ci" {
		t.Fatalf("the saved secret must authenticate: %+v %v", tok, err)
	}
	// A file whose token exists is left alone: the name is taken, and the
	// file still holds the live secret.
	code, _, errOut = run(t, "auth", "token", "create", "--name", "ci", "--scope", "read")
	if code != 1 || !strings.Contains(errOut, "PDR-E308") {
		t.Fatalf("an existing token: code=%d err=%q", code, errOut)
	}
	if again, _ := os.ReadFile(file); string(again) != string(raw) {
		t.Fatalf("the live secret's file must be untouched: %q", again)
	}
	if list, _ := authSvc.ListTokens(); len(list) != 1 || list[0].ID != tok.ID {
		t.Fatalf("exactly the one token: %+v", list)
	}
	// The engine's answer never arrives (the connection drops after it
	// minted the token): the file — the only copy of the secret — stays,
	// the engine is asked which it was, and the token it lists is
	// reported written.
	*drop = true
	code, out, errOut = run(t, "auth", "token", "create", "--name", "ci2", "--scope", "read")
	*drop = false
	if code != 0 || errOut != "" || !strings.Contains(out, "token written to") {
		t.Fatalf("an answer that never arrived: code=%d out=%q err=%q", code, out, errOut)
	}
	raw2, err := os.ReadFile(filepath.Join(tokensDir, "ci2.token"))
	if err != nil {
		t.Fatalf("the secret must be kept: %v", err)
	}
	if tok2, err := authSvc.TokenFromBearer("Bearer " + strings.TrimSpace(string(raw2))); err != nil || tok2.Name != "ci2" {
		t.Fatalf("the kept secret must authenticate: %+v %v", tok2, err)
	}
	if list, _ := authSvc.ListTokens(); len(list) != 2 {
		t.Fatalf("exactly two tokens: %+v", list)
	}
	// The name alone proves nothing (round 11): the answer is lost and the
	// name exists meanwhile under another client's secret — the listed
	// prefix does not match this file's, so nothing is claimed: the file
	// goes, the other client's token stays.
	*foreign = true
	code, _, errOut = run(t, "auth", "token", "create", "--name", "ci3", "--scope", "read")
	if code != 1 || !strings.Contains(errOut, "PDR-E308") || !strings.Contains(errOut, "another secret") {
		t.Fatalf("a foreign token under the name: code=%d err=%q", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(tokensDir, "ci3.token")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a secret that is no token's must not be kept: %v", err)
	}
	list, _ := authSvc.ListTokens()
	names := 0
	for _, t3 := range list {
		if t3.Name == "ci3" {
			names++
		}
	}
	if names != 1 || len(list) != 3 {
		t.Fatalf("the other client's token must stand, alone under its name: %+v", list)
	}
	// A file whose secret is not the listed token's is not "its secret":
	// the name is taken, the file is removed rather than pointed at.
	mismatched := filepath.Join(tokensDir, "ci3.token")
	if err := os.WriteFile(mismatched, []byte("pdr_"+strings.Repeat("A", 43)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = run(t, "auth", "token", "create", "--name", "ci3", "--scope", "read")
	if code != 1 || !strings.Contains(errOut, "PDR-E308") || !strings.Contains(errOut, "did not hold its secret") {
		t.Fatalf("a mismatched file under a taken name: code=%d err=%q", code, errOut)
	}
	if _, err := os.Stat(mismatched); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the mismatched file must be removed: %v", err)
	}
	// A file carrying the listed prefix but not a secret's shape —
	// truncated by a partial restore, or corrupted — holds no usable
	// credential: the prefix alone must not be taken for the secret. The
	// command says so and leaves the file exactly as it is (round 21).
	*foreign = false
	*drop = false
	code, _, errOut = run(t, "auth", "token", "create", "--name", "ci4", "--scope", "read")
	if code != 0 {
		t.Fatalf("a plain create: code=%d err=%q", code, errOut)
	}
	live := filepath.Join(tokensDir, "ci4.token")
	whole, rerr := os.ReadFile(live)
	if rerr != nil {
		t.Fatal(rerr)
	}
	truncated := strings.TrimSpace(string(whole))[:len(auth.TokenPrefix)+8]
	if err := os.WriteFile(live, []byte(truncated+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = run(t, "auth", "token", "create", "--name", "ci4", "--scope", "read")
	if code != 1 || !strings.Contains(errOut, "PDR-E308") || !strings.Contains(errOut, "usable secret") {
		t.Fatalf("a truncated secret under a live token's name: code=%d err=%q", code, errOut)
	}
	if raw, _ := os.ReadFile(live); strings.TrimSpace(string(raw)) != truncated {
		t.Fatalf("the file must be left exactly as it is: %q", raw)
	}
}

// --show and --json mint the token with a secret made here,
// as the file-backed path does: an answer lost on the socket
// loses no credential — the list says the engine minted the token under
// this secret's prefix, and the secret is printed; a name another client
// took meanwhile is E308 with nothing printed; a refused token prints
// nothing.
// TestTheTokensRowNamesTheModesCreateMakes couples INSTALL §3's file
// inventory to what a real `auth token create` leaves on disk: the
// directory must stay reachable (0700) while the secret inside it is
// 0600, so the row names both. An operator reading one mode off the row
// and applying it to the directory would strip the execute bit every
// token file needs.
func TestTheTokensRowNamesTheModesCreateMakes(t *testing.T) {
	serveSocket(t)
	if err := os.MkdirAll(config.StateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := run(t, "auth", "token", "create", "--name", "ci", "--scope", "read"); code != 0 {
		t.Fatalf("create: code=%d err=%q", code, errOut)
	}
	dir := filepath.Join(config.StateDir(), "tokens")
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Stat(filepath.Join(dir, "ci.token"))
	if err != nil {
		t.Fatal(err)
	}
	dirMode := fmt.Sprintf("%#o", dirInfo.Mode().Perm())
	fileMode := fmt.Sprintf("%#o", fileInfo.Mode().Perm())
	if dirMode != "0700" || fileMode != "0600" {
		t.Fatalf("create left dir %s and file %s", dirMode, fileMode)
	}
	raw, err := os.ReadFile("../../public-docs/INSTALL.md")
	if err != nil {
		t.Fatal(err)
	}
	row := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "`tokens/`") && strings.HasPrefix(strings.TrimSpace(line), "|") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("INSTALL.md §3 has no tokens/ row")
	}
	mode := row[strings.LastIndex(row[:len(row)-1], "|"):]
	if !strings.Contains(mode, dirMode) || !strings.Contains(mode, fileMode) {
		t.Fatalf("the tokens row must name the directory's %s and the file's %s: %s", dirMode, fileMode, mode)
	}
}

func TestShowNeverLosesTheSecret(t *testing.T) {
	authSvc, drop, foreign := serveSocketDropping(t)
	*drop = true
	code, out, errOut := run(t, "auth", "token", "create", "--name", "ci", "--scope", "read", "--show")
	if code != 0 {
		t.Fatalf("a lost answer with the token minted must still print the secret: code=%d err=%q", code, errOut)
	}
	if tok, err := authSvc.TokenFromBearer("Bearer " + strings.TrimSpace(out)); err != nil || tok.Name != "ci" {
		t.Fatalf("the printed secret must be the minted token's: %v", err)
	}
	*drop = true
	code, out, errOut = run(t, "auth", "token", "create", "--name", "ci2", "--scope", "read", "--show", "--json")
	var got struct {
		Token  *state.Token `json:"token"`
		Secret string       `json:"secret"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &got) != nil || got.Token == nil || got.Token.Name != "ci2" {
		t.Fatalf("--json after a lost answer: code=%d out=%q err=%q", code, out, errOut)
	}
	if tok, err := authSvc.TokenFromBearer("Bearer " + got.Secret); err != nil || tok.Name != "ci2" {
		t.Fatalf("the JSON secret must be the minted token's: %v", err)
	}
	*drop = false
	*foreign = true
	code, out, errOut = run(t, "auth", "token", "create", "--name", "ci3", "--scope", "read", "--show")
	if code != 1 || !strings.Contains(errOut, "PDR-E308") || strings.Contains(out, "pdr_") {
		t.Fatalf("a name another client took meanwhile: code=%d out=%q err=%q", code, out, errOut)
	}
	if list, _ := authSvc.ListTokens(); len(list) != 3 {
		t.Fatalf("ci, ci2 and the other client's ci3: %+v", list)
	}
	code, out, errOut = run(t, "auth", "token", "create", "--name", "ci4", "--scope", "root", "--show")
	if code != 2 || strings.Contains(out, "pdr_") || !strings.Contains(errOut, "PDR-E307") {
		t.Fatalf("a refused token prints nothing: code=%d out=%q err=%q", code, out, errOut)
	}
}

// No token listed after a lost answer settles nothing:
// the list may have overtaken the creation still running on the
// engine, so the secret stays — the file kept, the --show secret printed
// with the answer that it is unknown — and once the creation lands, that
// secret is the token's.
func TestALostAnswerKeepsTheSecretUntilTheEngineHasSettled(t *testing.T) {
	authSvc, door := serveDoor(t)
	tokensDir := filepath.Join(config.StateDir(), "tokens")
	*door.late = true
	code, _, errOut := run(t, "auth", "token", "create", "--name", "ci", "--scope", "read")
	if code != 1 || !strings.Contains(errOut, "PDR-E204") {
		t.Fatalf("an answer the list cannot settle yet must be reported unknown: code=%d err=%q", code, errOut)
	}
	raw, err := os.ReadFile(filepath.Join(tokensDir, "ci.token"))
	if err != nil {
		t.Fatalf("the file must stay — the creation may still be running: %v", err)
	}
	door.wg.Wait()
	if tok, err := authSvc.TokenFromBearer("Bearer " + strings.TrimSpace(string(raw))); err != nil || tok.Name != "ci" {
		t.Fatalf("the kept secret must be the late-minted token's: %v", err)
	}
	*door.late = true
	code, out, errOut := run(t, "auth", "token", "create", "--name", "ci2", "--scope", "read", "--show")
	if code != 1 || !strings.Contains(errOut, "PDR-E204") {
		t.Fatalf("--show after an unsettled answer: code=%d out=%q err=%q", code, out, errOut)
	}
	secret := regexp.MustCompile(`pdr_[A-Za-z0-9_-]+`).FindString(errOut)
	if secret == "" {
		t.Fatalf("the secret must be in the answer, never suppressed: %q", errOut)
	}
	door.wg.Wait()
	if tok, err := authSvc.TokenFromBearer("Bearer " + secret); err != nil || tok.Name != "ci2" {
		t.Fatalf("the printed secret must be the late-minted token's: %v", err)
	}
}

// A --password-file readable by others is refused before it is read (S5
// Review round 18): the documented 0600 is enforced on the descriptor the
// password would be read from — a group- or world-readable file, or one
// that is not a regular file, stops auth setup with nothing created.
func TestPasswordFileMustBePrivate(t *testing.T) {
	authSvc := serveSocket(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "password")
	if err := os.WriteFile(file, []byte("correct horse battery\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := run(t, "auth", "setup", "--username", "jross", "--password-file", file)
	if code != 2 || !strings.Contains(errOut, "PDR-E307") || !strings.Contains(errOut, "readable by others") {
		t.Fatalf("a world-readable password file must be refused: code=%d err=%q", code, errOut)
	}
	if authSvc.HasOperator() {
		t.Fatal("no operator may be created from a password others could read")
	}
	code, _, errOut = run(t, "auth", "setup", "--username", "jross", "--password-file", dir)
	if code != 2 || !strings.Contains(errOut, "PDR-E307") || !strings.Contains(errOut, "not a regular file") {
		t.Fatalf("a directory as the password file must be refused: code=%d err=%q", code, errOut)
	}
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := run(t, "auth", "setup", "--username", "jross", "--password-file", file); code != 0 {
		t.Fatalf("a 0600 password file must be accepted: code=%d out=%q err=%q", code, out, errOut)
	}
	if !authSvc.HasOperator() {
		t.Fatal("the operator must be created from the private file")
	}
}
