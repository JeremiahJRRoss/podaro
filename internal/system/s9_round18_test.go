// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/fsx"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// syncLog records the paths flushed, in order.
type syncLog struct {
	mu   sync.Mutex
	seen []string
}

func (s *syncLog) install(t *testing.T) {
	t.Helper()
	real := fsx.Sync
	fsx.Sync = func(f *os.File) error {
		s.mu.Lock()
		s.seen = append(s.seen, f.Name())
		s.mu.Unlock()
		return real(f)
	}
	t.Cleanup(func() { fsx.Sync = real })
}

func (s *syncLog) has(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Contains(s.seen, path)
}

// Review round 18, third finding — and a reversal of
// what round 8 decided.
//
// Round 8 flushed the backup's rename and deliberately left the binary's
// alone, reasoning that losing the replacement leaves the old binary in
// place, which is the safe direction. That reasoning was incomplete: the
// restart that follows runs the *new* engine, which migrates `state.db`
// forward. Lose the rename after that and the next boot runs the old
// binary against a schema it refuses (PDR-E211) — the downgrade the
// upgrade command refuses to perform, arrived at by a power cut.
func TestTheReplacedBinaryIsFlushedBeforeTheRestart(t *testing.T) {
	exe, _ := upgradeEnv(t)
	rel := newRelease(t, "9.9.9", "the new binary")
	bin := filepath.Dir(exe)
	log := &syncLog{}
	log.install(t)

	var restarted bool
	err := Upgrade(render.New(io.Discard, false, false), UpgradeOptions{
		Base: rel.srv.URL, Exe: exe,
		Restart: func() error {
			// The restart is the point of no return: after it the new
			// engine has the state, so the name must already be durable.
			if !log.has(bin) {
				t.Errorf("the service was restarted before the directory naming the new binary was flushed")
			}
			restarted = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if !restarted {
		t.Fatal("the service was not restarted")
	}
	if !log.has(bin) {
		t.Errorf("the replacement was never flushed: a power loss undoes it and the old binary meets the new schema")
	}
}

// And a flush that fails says what actually happened. The rename has
// landed by then — the new binary is on disk — so the refusal that says
// "nothing was replaced" would send an operator to the wrong recovery.
func TestAFlushThatFailsAfterTheReplacementSaysWhatHappened(t *testing.T) {
	exe, _ := upgradeEnv(t)
	rel := newRelease(t, "9.9.9", "the new binary")
	bin := filepath.Dir(exe)
	real := fsx.Sync
	fsx.Sync = func(f *os.File) error {
		if f.Name() == bin {
			return errors.New("sync: input/output error")
		}
		return real(f)
	}
	t.Cleanup(func() { fsx.Sync = real })

	var restarted bool
	err := Upgrade(render.New(io.Discard, false, false), UpgradeOptions{
		Base: rel.srv.URL, Exe: exe, Restart: func() error { restarted = true; return nil },
	})
	if code(err) != pdr.CodeUpgradeRefused {
		t.Fatalf("a replacement that cannot be flushed: %v — want %s", err, pdr.CodeUpgradeRefused)
	}
	if restarted {
		t.Error("the service was restarted on a replacement that could not be made durable")
	}
	var pe *pdr.Error
	if errors.As(err, &pe) && strings.Contains(pe.Next, "nothing was replaced") {
		t.Errorf("the refusal claims nothing was replaced: %q", pe.Next)
	}
	if got, _ := os.ReadFile(exe); string(got) != "the new binary" {
		t.Errorf("the premise: the rename lands before the flush, and the binary on disk is the new one")
	}
}
