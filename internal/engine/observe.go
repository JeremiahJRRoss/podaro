// SPDX-License-Identifier: AGPL-3.0-only

package engine

// The engine's side of the observability export (Manual §4, roadmap §9,
// threat model B10): the redaction filter the export path runs every
// record through, and the engine's own signals — its journal lines, one
// span per job, and the counts a job changes.
//
// Nothing here reaches a network unless the operator configured a
// destination: with no `observability` block the exporter is nil and
// every call below is a nil-receiver no-op. Vendor telemetry remains
// zero, ever.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jeremiahjrross/podaro/internal/observe"
	"github.com/jeremiahjrross/podaro/internal/secrets"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// ExportFilter is the filter the observability export runs every record
// through before it is queued: every instance's filter, applied in turn,
// built fresh — so a secret generated a moment ago filters the line that
// mentions it, and an instance created since the last record is covered
// by the next one.
//
// It fails closed. A store that cannot be read, or an instance missing a
// value its containers were configured with, is the same refusal the
// local paths raise (PDR-E412, redactor): the export withholds the
// record rather than send text the filter never saw. Withheld records
// are counted and reported by `podaro observe status`.
func (e *Engine) ExportFilter() (func(string) string, error) {
	list, err := e.opts.Store.ListInstances()
	if err != nil {
		return nil, fmt.Errorf("the redaction filter needs the instance list: %w", err)
	}
	reds := make([]*secrets.Redactor, 0, len(list))
	for _, inst := range list {
		red, perr := e.redactor(inst.Name)
		if perr != nil {
			return nil, perr
		}
		if !red.Empty() {
			reds = append(reds, red)
		}
	}
	return func(s string) string {
		for _, r := range reds {
			s = r.Redact(s)
		}
		return s
	}, nil
}

// observeJob exports a finished job as one span and one count. The span
// carries what the job was, on what, for how long, and whether it
// worked — never its error text beyond the envelope's message, which
// has already passed the instance's own filter (redactErrFor), and
// never anything a lab held.
func (e *Engine) observeJob(job state.Job) {
	if e.opts.Observe == nil {
		return
	}
	end := time.Now().UTC()
	if job.Finished != nil {
		end = job.Finished.UTC()
	}
	status := "ok"
	attrs := map[string]string{"job.kind": job.Kind, "instance": job.Instance, "job.state": string(job.State)}
	if job.Target != "" {
		attrs["job.target"] = job.Target
	}
	if job.State == state.JobFailed {
		status = "error"
		if job.Error != nil {
			attrs["error.code"] = job.Error.Code
			attrs["error.message"] = job.Error.Message
		}
	}
	e.opts.Observe.Trace(observe.Span{
		TraceID: traceID(job.ID), SpanID: spanID(),
		Name: "podaro." + job.Kind, Start: job.Started.UTC(), End: end,
		Status: status, Attrs: attrs,
	})
	e.opts.Observe.Metric("podaro.job.duration_seconds", end.Sub(job.Started).Seconds(),
		map[string]string{"job.kind": job.Kind, "instance": job.Instance, "job.state": string(job.State)})
	e.opts.Observe.Metric("podaro.jobs.finished", 1,
		map[string]string{"job.kind": job.Kind, "job.state": string(job.State)})
}

// traceID derives a span's trace id from the job id, so every span of
// one job shares a trace and the id is the one the journal already
// names. A job id shorter than a trace id is padded rather than hashed:
// the correlation an operator wants is with the job, not privacy from
// their own collector.
func traceID(jobID string) string {
	const width = 32
	id := hex.EncodeToString([]byte(jobID))
	if len(id) >= width {
		return id[:width]
	}
	for len(id) < width {
		id += "0"
	}
	return id
}

func spanID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0000000000000001"
	}
	return hex.EncodeToString(b[:])
}
