// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"errors"
	"strings"
	"sync"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The instance guard (checkpoints.go:287).
// Writes that happen outside the exclusive job slot — a synchronous
// checkpoint run's record, an attestation, a progress write, a reveal —
// and destroy's removal of the instance's state take one lock per
// instance, and every such write first confirms the instance still
// exists. A checkpoint that finished evaluating as destroy removed the
// instance finds nothing to record into: no evidence directory reappears,
// no result row outlives the instance, and a later instance of the same
// name inherits nothing.

// instanceLock returns the per-instance mutex, made on first use and kept
// (a mutex per instance name ever seen is small).
func (e *Engine) instanceLock(name string) *sync.Mutex {
	e.instMu.Lock()
	defer e.instMu.Unlock()
	if e.instLocks == nil {
		e.instLocks = map[string]*sync.Mutex{}
	}
	l, ok := e.instLocks[name]
	if !ok {
		l = &sync.Mutex{}
		e.instLocks[name] = l
	}
	return l
}

// withInstance runs fn under the instance's lock once the very instance
// the operation began on is confirmed still there — the same name and the
// same creation instant. A name that is gone is PDR-E202; a name that now
// belongs to a later instance (destroyed and created again while the
// operation ran) is PDR-E202 too, saying so: nothing of the old instance
// is written into the new one. A store
// fault stays a store fault, never absence.
func (e *Engine) withInstance(inst *state.Instance, fn func() error) error {
	l := e.instanceLock(inst.Name)
	l.Lock()
	defer l.Unlock()
	cur, err := e.opts.Store.GetInstance(inst.Name)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			return e.notFound(inst.Name)
		}
		return storeErr("look up instance "+inst.Name, err)
	}
	if !cur.Created.Equal(inst.Created) {
		pe := pdr.New(pdr.CodeInstanceNotFound, "instance %q was replaced while this operation ran", inst.Name)
		pe.Cause = "the instance this operation began on was destroyed, and a new one of the same name created, meanwhile"
		pe.Next = "repeat the operation against the new instance"
		return pe
	}
	return fn()
}

// forgetEvaluations drops an instance's evaluation-start records and its
// reset mark (destroy: a later instance of the name starts afresh).
func (e *Engine) forgetEvaluations(name string) {
	e.evalMu.Lock()
	defer e.evalMu.Unlock()
	for k := range e.lastEval {
		if strings.HasPrefix(k, name+"\x00") {
			delete(e.lastEval, k)
		}
	}
	delete(e.resetMark, name)
}

// evalTicket issues the next freshness ticket. Every evaluation and
// attestation takes one where it used to take a wall-clock instant, and
// a reset takes one when it clears; the order of those tickets is the
// order the events began in, which no clock correction can reverse.
func (e *Engine) evalTicket() uint64 { return e.evalSeq.Add(1) }

// markReset records the ticket at which a reset cleared an instance's
// results: the generation turns there.
func (e *Engine) markReset(name string, at uint64) {
	e.evalMu.Lock()
	defer e.evalMu.Unlock()
	if e.resetMark == nil {
		e.resetMark = map[string]uint64{}
	}
	if at > e.resetMark[name] { // a generation never turns back
		e.resetMark[name] = at
	}
}

// preReset reports whether an evaluation that took ticket seq belongs to
// a generation a reset has since cleared.
func (e *Engine) preReset(name string, seq uint64) bool {
	e.evalMu.Lock()
	defer e.evalMu.Unlock()
	mark, ok := e.resetMark[name]
	return ok && seq < mark
}

// forgetJournal drops an instance's cached evidence journal on destroy:
// a later instance of the same name starts its own.
func (e *Engine) forgetJournal(name string) {
	e.journalMu.Lock()
	defer e.journalMu.Unlock()
	delete(e.journals, name)
}

// refuseWhileRebuilding refuses a result-producing operation from outside
// the job slot while a destroy or reset job is active on the instance
// (PDR-E201): the lab is on its way out or being rebuilt, so an observation
// taken now is of containers that will not be there when it lands.
// A create or verify runs alongside, as
// API §4 says.
func (e *Engine) refuseWhileRebuilding(name string) error {
	active, err := e.activeJob(name)
	if err != nil {
		return err
	}
	if active != nil && (active.Kind == "destroy" || active.Kind == "reset") {
		return e.busy(name, active)
	}
	return nil
}
