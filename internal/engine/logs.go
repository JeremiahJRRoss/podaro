// SPDX-License-Identifier: AGPL-3.0-only

package engine

// Service logs (API §7, plan S9; Manual §15 `podaro logs`).
//
// A product prints what it was configured with, and it was configured
// with this lab's secrets: a product that refuses a password may echo
// the password, and one that starts may print its own bootstrap.
// So no byte of a container's output leaves this engine before the
// instance's redaction filter has seen it — the same filter the journal,
// the evidence and the export use, built the same way, failing closed
// the same way (PDR-E412).
//
// The filtering is line-oriented, because a stream is read in whatever
// chunks the pipe delivers and a secret can straddle two of them. A
// partial line is held until its newline arrives. A line past the cap is
// emitted without one — and there the value that straddles the cut is
// trimmed from the end of what is emitted (TrimPartial) *and carried
// into the next chunk*, so the filter sees it whole. Trimming alone is
// not enough: it stops the prefix leaving, and then the rest of the
// value arrives as a chunk the filter does not recognise, which is a
// leak of everything after the cut.

import (
	"bufio"
	"context"
	"io"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// LogOptions is what a caller narrows a log read by (API §7).
type LogOptions struct {
	Since  time.Duration
	Tail   int
	Follow bool
}

// MaxLogLine bounds one line held for filtering. A product that writes
// megabytes without a newline must not make the engine hold them: the
// line is filtered and emitted at the cap, and the next chunk starts a
// new one.
const MaxLogLine = 64 << 10

// Logs opens one service's output, filtered. The reader is the caller's
// to close, and closing it stops the read behind it.
func (e *Engine) Logs(ctx context.Context, instance, service string, opts LogOptions, by Actor) (ret io.ReadCloser, err error) {
	lv, err := e.instanceViewFor(instance, by.Gen)
	if err != nil {
		return nil, err
	}
	defer func() { err = e.confirmed(lv, err) }()
	// The filter first: an instance whose secrets cannot be read gets no
	// logs at all, rather than logs no filter has seen.
	red, perr := e.redactor(instance)
	if perr != nil {
		return nil, perr
	}
	svcs, err := e.opts.Store.ListServices(instance)
	if err != nil {
		return nil, storeErr("list services of "+instance, err)
	}
	var svc *state.Service
	for i := range svcs {
		if svcs[i].Name == service {
			svc = &svcs[i]
			break
		}
	}
	if svc == nil {
		known := make([]string, 0, len(lv.plan.Services))
		for _, ps := range lv.plan.Services {
			known = append(known, ps.Name)
		}
		pe := pdr.New(pdr.CodeServiceNotFound, "instance %s has no service %q", instance, service)
		pe.Cause = "the template declares: " + joinIDs(known)
		pe.Next = "podaro status " + instance
		return nil, pe
	}
	if svc.Container == "" {
		pe := pdr.New(pdr.CodeServiceNotFound, "service %s of %s has no container yet", service, instance)
		pe.Cause = "the instance has not reached the stage where its containers exist"
		pe.Next = "podaro status " + instance + " · podaro up " + instance
		return nil, pe
	}
	stream, err := e.opts.Runtime.Logs(ctx, svc.Container, runtime.LogOptions{
		Since: opts.Since, Tail: opts.Tail, Follow: opts.Follow,
	})
	if err != nil {
		return nil, runtimeErr("read the logs of "+svc.Container, err)
	}
	return &filteredLog{src: stream, red: red}, nil
}

// ServiceNames lists an instance's services, for a caller that must name
// one (the CLI's argument check, the console's picker).
func (e *Engine) ServiceNames(instance string) ([]string, error) {
	svcs, err := e.opts.Store.ListServices(instance)
	if err != nil {
		return nil, storeErr("list services of "+instance, err)
	}
	names := make([]string, 0, len(svcs))
	for _, s := range svcs {
		names = append(names, s.Name)
	}
	return names, nil
}

// filteredLog is the reader the caller gets: whole lines, filtered.
type filteredLog struct {
	src io.ReadCloser
	red interface {
		RedactBytes([]byte) []byte
		TrimPartial([]byte) []byte
	}
	br      *bufio.Reader
	pending []byte
	// carry is the tail TrimPartial took off the last emitted chunk: the
	// beginning of a value the cut interrupted. It is prepended to the
	// next chunk so the filter meets the value whole. It is bounded by
	// the longest secret, since that is the most a prefix can be.
	carry   []byte
	err     error
	drained bool
}

func (f *filteredLog) Read(b []byte) (int, error) {
	for len(f.pending) == 0 {
		if f.err != nil {
			if !f.drained && len(f.carry) > 0 {
				// The stream ended mid-value: what was carried is a
				// prefix of a secret and nothing else. It is dropped, not
				// printed — the last thing a cut log should end with is
				// the first characters of a credential.
				f.drained = true
				f.carry = nil
			}
			return 0, f.err
		}
		if f.br == nil {
			f.br = bufio.NewReaderSize(f.src, MaxLogLine)
		}
		line, err := f.br.ReadSlice('\n')
		chunk := line
		if len(f.carry) > 0 {
			chunk = append(append([]byte(nil), f.carry...), line...)
			f.carry = nil
		}
		switch {
		case err == nil:
			f.pending = f.red.RedactBytes(chunk)
		case err == bufio.ErrBufferFull:
			// A line past the cap: filter and emit what there is, holding
			// back a value the cut interrupted for the next chunk.
			filtered := f.red.RedactBytes(chunk)
			kept := f.red.TrimPartial(filtered)
			f.carry = append([]byte(nil), filtered[len(kept):]...)
			f.pending = kept
		default:
			f.err = err
			if len(chunk) > 0 {
				// The tail has no newline: it may end in a value's prefix,
				// which is trimmed and never carried anywhere.
				f.pending = f.red.TrimPartial(f.red.RedactBytes(chunk))
				f.drained = true
				continue
			}
			f.drained = true
			return 0, err
		}
	}
	n := copy(b, f.pending)
	f.pending = f.pending[n:]
	return n, nil
}

func (f *filteredLog) Close() error { return f.src.Close() }
