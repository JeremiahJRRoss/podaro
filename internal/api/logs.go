// SPDX-License-Identifier: AGPL-3.0-only

package api

// `GET /instances/{name}/services/{svc}/logs` (API §7): a service's own
// output, redaction-filtered by the engine before it reaches this
// handler's writer.
//
// The scope is `read`, and that is the whole of D4's exclusion: an
// instance-access session carries the `instance` scope, which does not
// satisfy `read`, so an attendee is refused here by the routing table
// rather than by a check written beside it. Logs are the one lab read an
// attendee does not get — a product's own output is where a lab's
// plumbing, and the operator's mistakes, are visible.

import (
	"io"
	"net/http"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// MaxLogRead bounds a non-following read, so one request cannot be asked
// for a lab's entire history at once.
const MaxLogRead = 4 << 20

// HeaderTruncated marks an answer the cap cut short. A silent 200 that
// ends mid-line — and possibly before the failure being investigated —
// is a truncated log an operator cannot tell from a complete one, so the
// answer says which it is.
const HeaderTruncated = "X-Podaro-Truncated"

// logRoutes registers §7's log endpoint.
func (s *Server) logRoutes() {
	s.handle("GET /instances/{name}/services/{svc}/logs", auth.ScopeRead, s.logs)
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.o.Engine.View(name, actorOf(r)); err != nil {
		s.writeError(w, r, err)
		return
	}
	q := r.URL.Query()
	opts := engine.LogOptions{Follow: q.Get("follow") == "true"}
	if v := q.Get("since"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			pe := pdr.New(pdr.CodeCreateRequest, "since %q is not a duration", v)
			pe.Next = "since=10m (API §7)"
			s.writeError(w, r, pe)
			return
		}
		opts.Since = d
	}
	if v := q.Get("tail"); v != "" {
		n, err := atoiPositive(v)
		if err != nil {
			pe := pdr.New(pdr.CodeCreateRequest, "tail %q is not a whole number of lines", v)
			pe.Next = "tail=200 (API §7)"
			s.writeError(w, r, pe)
			return
		}
		opts.Tail = n
	}
	stream, err := s.o.Engine.Logs(r.Context(), name, r.PathValue("svc"), opts, actorOf(r))
	if err != nil {
		// Every refusal happens before a byte of the body is written, so
		// a client always gets an error envelope rather than an empty
		// stream that reads as a silent service.
		s.writeError(w, r, err)
		return
	}
	defer stream.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// Logs are a product's own words; nothing here is markup, and a
	// browser must not treat them as any.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if opts.Follow {
		w.WriteHeader(http.StatusOK)
		s.followLogs(w, r, stream)
		return
	}
	// One byte past the cap is read to learn whether there was more, and
	// the answer is buffered so the header can say so before the body
	// starts — a header cannot be set after the first write. The cap is
	// what bounds the memory this holds, which is the same bound the
	// endpoint already had.
	body, err := io.ReadAll(io.LimitReader(stream, MaxLogRead+1))
	truncated := len(body) > MaxLogRead
	if truncated {
		body = body[:MaxLogRead]
	}
	// A read that failed part way also produces an answer that is not
	// the whole log, and the operator is owed the same warning — with
	// what was read, which is the half of it that is useful.
	if err != nil {
		truncated = true
	}
	if truncated {
		w.Header().Set(HeaderTruncated, "true")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// followLogs forwards a follow as the lines arrive — a stream a client
// watches is worth nothing delivered in one buffer at the end — and
// stops when the credential that opened it stops being valid.
//
// A credential is admitted once, when the request is (Server.handle
// reads the principal the door put on the context), and a follow is a
// request that does not return. Signing out, revoking the token or
// reaching the session's idle expiry therefore left the copy running:
// `podman logs --follow` went on delivering a product's own output —
// where a lab's plumbing and the operator's mistakes are visible — to a
// credential every new request was refusing. The event feed re-checks on
// its own tick; this is the other long-lived response, and it did not.
//
// The read runs in its own goroutine so the check has a cadence at all:
// `src.Read` blocks until the product says something, and a lab that has
// gone quiet is exactly when a revocation most needs to land. Only this
// function writes to `w`. When it returns, `done` releases a goroutine
// waiting to hand over a chunk, and the caller's `stream.Close()` —
// deferred before this is reached, so it runs after — releases one
// blocked in the read.
//
// The stream ends rather than saying why: a plain-text log has no
// grammar of its own to say it in, and a line the API invents would be
// read as the product's. The client's next request gets the refusal.
func (s *Server) followLogs(w http.ResponseWriter, r *http.Request, src io.Reader) {
	flusher, _ := w.(http.Flusher)
	type chunk struct {
		b   []byte
		err error
	}
	chunks := make(chan chunk)
	done := make(chan struct{})
	defer close(done)
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			c := chunk{err: err}
			if n > 0 {
				c.b = append([]byte(nil), buf[:n]...)
			}
			select {
			case chunks <- c:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	// The feed's cadence, deliberately the same number: both are the
	// same promise about how long a dead credential can still be served.
	tick := time.NewTicker(eventTick)
	defer tick.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if !s.credentialLive(r) {
				return
			}
		case c := <-chunks:
			if len(c.b) > 0 {
				if _, werr := w.Write(c.b); werr != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if c.err != nil {
				return
			}
		}
	}
}

// atoiPositive parses a positive whole number written in digits alone —
// `+1` and `1e3` are not counts (D174).
func atoiPositive(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, errNotANumber
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errNotANumber
		}
		n = n*10 + int(c-'0')
		if n > 1<<20 {
			return 0, errNotANumber
		}
	}
	if n == 0 {
		return 0, errNotANumber
	}
	return n, nil
}

// errNotANumber is the one refusal atoiPositive gives; the caller turns
// it into the envelope naming the parameter.
var errNotANumber = errNotANumberType{}

type errNotANumberType struct{}

func (errNotANumberType) Error() string { return "not a whole number" }
