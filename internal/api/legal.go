// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/console"
	"github.com/jeremiahjrross/podaro/internal/legal"
	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// GET /system/legal (API §5; the reconciliation §7.2; the reconciliation
// plan's R5): the licence, the notices and the offer of the running
// binary's exact source, as JSON — and, to `Accept: text/html`, as the
// fragment the gateway's /legal page frames, rendered from the same value.
//
// It is one of the two public routes, and the only /api route that needs
// no credential at all: an attendee, and a visitor at the sign-in page,
// must reach the source offer (the reconciliation §7.2), so it is
// registered open and the gateway serves it before any session is looked
// at — the hostname binding included, since it reads no session to bind.
// It is static — the value is built once from the binary and the
// operator's legal.source_url, and rebuilt only by a reload — it reads
// and writes no state, and it is rate-limited per source like the login
// form (threat model B1).
func (s *Server) getLegal(w http.ResponseWriter, r *http.Request) {
	if err := s.AdmitPublic(r); err != nil {
		s.writeError(w, r, err)
		return
	}
	info := s.o.Legal()
	s.respond(w, r, http.StatusOK, map[string]any{"legal": info}, console.FragmentLegal, info)
}

// Legal is GET /system/legal's value, for the gateway's /legal page — the
// same value the route answers with, so the page renders what the JSON
// holds and nothing else.
func (s *Server) Legal() legal.Info { return s.o.Legal() }

// The public routes' allowance, per source: a burst, then a steady rate.
// A person reading the page, reloading it, following its link from the
// footer, never meets it; a loop asking for it thousands of times does.
const (
	publicBurst  = 30
	publicRefill = 2 * time.Second
	// publicSources bounds the memory the allowance holds. A source whose
	// allowance has refilled carries nothing worth remembering and is
	// forgotten first; past the bound, a source not yet seen waits its
	// turn rather than growing the table.
	publicSources = 4096
)

type publicBucket struct {
	tokens float64
	last   time.Time
}

// publicLimiter is the per-source allowance of the public routes: memory
// only, never the state store — the routes are stateless by design, and
// an engine restart forgets every source, which costs nothing.
type publicLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets map[string]*publicBucket
}

func newPublicLimiter() *publicLimiter {
	return &publicLimiter{now: time.Now, buckets: map[string]*publicBucket{}}
}

// allow spends one request of source's allowance, or says how long until
// the next one.
func (l *publicLimiter) allow(source string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.buckets[source]
	if b == nil {
		if len(l.buckets) >= publicSources {
			for k, old := range l.buckets {
				if now.Sub(old.last) >= publicBurst*publicRefill {
					delete(l.buckets, k)
				}
			}
		}
		if len(l.buckets) >= publicSources {
			return publicRefill, false
		}
		b = &publicBucket{tokens: publicBurst, last: now}
		l.buckets[source] = b
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += float64(elapsed) / float64(publicRefill)
		if b.tokens > publicBurst {
			b.tokens = publicBurst
		}
	}
	b.last = now
	if b.tokens < 1 {
		return time.Duration((1 - b.tokens) * float64(publicRefill)), false
	}
	b.tokens--
	return 0, true
}

// AdmitPublic admits one request to a public route — GET /system/legal,
// or the gateway's /legal page — or returns the refusal to answer with:
// PDR-E315, 429, carrying its Retry-After. The source is the peer address,
// never a forwarded header, as for the login throttle (API §2.1); the
// local socket is the operator's own door and is not limited.
func (s *Server) AdmitPublic(r *http.Request) error {
	if p := PrincipalFrom(r.Context()); p != nil && p.Mechanism == auth.MechanismSocket {
		return nil
	}
	source := clientSource(r)
	wait, ok := s.public.allow(source)
	if ok {
		return nil
	}
	e := pdr.New(pdr.CodePublicThrottled, "too many requests for the licence and source page from %s", source)
	e.Cause = fmt.Sprintf("a source may ask for it %d times at once, then once every %s", publicBurst, publicRefill)
	e.Next = "wait and load the page again · or run podaro legal on the host"
	return &auth.Throttled{Env: e, RetryAfter: wait}
}
