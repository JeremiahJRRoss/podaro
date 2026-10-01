// SPDX-License-Identifier: AGPL-3.0-only

package api

// Instance access (API §2.4, plan S9): the operator issues an attendee a
// `pdi_` link, lists what is outstanding, and revokes one; the attendee
// exchanges the link for a session scoped to that instance.
//
// The grant that session carries is the one the routes already declare:
// every endpoint an attendee may reach is registered with
// `auth.ScopeInstance`, and every other one outranks it, so the fixed
// grant is a property of the routing table rather than a list kept
// somewhere else. Destroy, reset, logs, other instances, the auth
// surfaces and instance creation are outside it by construction.

import (
	"net/http"
	"strings"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// accessRoutes registers §2.4's endpoints.
func (s *Server) accessRoutes() {
	s.handle("POST /instances/{name}/access", auth.ScopeAdmin, s.issueAccess)
	s.handle("GET /instances/{name}/access", auth.ScopeAdmin, s.listAccess)
	s.handle("DELETE /instances/{name}/access/{id}", auth.ScopeAdmin, s.revokeAccess)
	// The join is open by necessity: whoever holds the link has not
	// authenticated yet, and the link is the credential. It is refused in
	// one shape whatever is wrong with it (auth.Join).
	s.open("GET /join/{token}", s.join)
}

// accessView is what a listing carries: never the secret, and never its
// hash — a name, the prefix that tells one link from another, and the
// times an operator revokes by.
type accessView struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Prefix   string     `json:"prefix"`
	Created  time.Time  `json:"created"`
	Expires  time.Time  `json:"expires"`
	LastUsed *time.Time `json:"last_used"`
}

func accessViews(list []state.Access) []accessView {
	out := make([]accessView, 0, len(list))
	for _, a := range list {
		out = append(out, accessView{ID: a.ID, Name: a.Name, Prefix: a.Prefix, Created: a.Created, Expires: a.Expires, LastUsed: a.LastUsed})
	}
	return out
}

func (s *Server) issueAccess(w http.ResponseWriter, r *http.Request) {
	if s.o.Auth == nil {
		s.writeError(w, r, pdr.New(pdr.CodeNoOperator, "authentication is not configured on this door"))
		return
	}
	name := r.PathValue("name")
	// Resolved once, here, and carried to the write. Throwing this away
	// and letting issuance look the instance up again left a window in
	// which the name could become a different lab between the two reads.
	target, err := s.o.Engine.View(name, actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var body struct {
		Name    string `json:"name"`
		Expires string `json:"expires"`
	}
	// The body is a JSON object or nothing: a name is required, and the
	// same reader every other write uses refuses a null, a scalar or a
	// member the shape does not have (D196, D197, D202).
	if err := readObject(w, r, 4<<10, false, &body); err != nil {
		e := pdr.New(pdr.CodeCreateRequest, "access request: %v", err)
		e.Next = `POST {"name":"alice","expires":"8h"} (API §2.4)`
		s.writeError(w, r, e)
		return
	}
	ttl := time.Duration(0)
	if body.Expires != "" {
		d, err := time.ParseDuration(body.Expires)
		if err != nil || d <= 0 {
			e := pdr.New(pdr.CodeCreateRequest, "expires %q is not a duration", body.Expires)
			e.Next = `{"name":"alice","expires":"8h"}`
			s.writeError(w, r, e)
			return
		}
		ttl = d
	}
	p := PrincipalFrom(r.Context())
	secret, acc, err := s.o.Auth.IssueAccess(name, target.Generation(), body.Name, ttl, p.Subject, p.Mechanism)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	// The secret is returned once, here, and never again: the store holds
	// its hash. The join link is built from the instance's own hostname,
	// which is the only one the gateway will accept it on.
	out := map[string]any{
		"access": accessView{ID: acc.ID, Name: acc.Name, Prefix: acc.Prefix, Created: acc.Created, Expires: acc.Expires},
		"token":  secret,
		"join":   s.joinURL(name, secret),
	}
	s.respond(w, r, http.StatusCreated, out, "", nil)
}

func (s *Server) listAccess(w http.ResponseWriter, r *http.Request) {
	if s.o.Auth == nil {
		s.writeError(w, r, pdr.New(pdr.CodeNoOperator, "authentication is not configured on this door"))
		return
	}
	name := r.PathValue("name")
	if _, err := s.o.Engine.View(name, actorOf(r)); err != nil {
		s.writeError(w, r, err)
		return
	}
	list, err := s.o.Auth.ListAccess(name)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.respond(w, r, http.StatusOK, map[string]any{"access": accessViews(list)}, "", nil)
}

func (s *Server) revokeAccess(w http.ResponseWriter, r *http.Request) {
	if s.o.Auth == nil {
		s.writeError(w, r, pdr.New(pdr.CodeNoOperator, "authentication is not configured on this door"))
		return
	}
	name := r.PathValue("name")
	if _, err := s.o.Engine.View(name, actorOf(r)); err != nil {
		s.writeError(w, r, err)
		return
	}
	p := PrincipalFrom(r.Context())
	if err := s.o.Auth.RevokeAccess(name, r.PathValue("id"), p.Subject, p.Mechanism); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// join exchanges a `pdi_` secret for a session scoped to its instance.
func (s *Server) join(w http.ResponseWriter, r *http.Request) {
	if s.o.Auth == nil {
		s.writeError(w, r, pdr.New(pdr.CodeNoOperator, "authentication is not configured on this door"))
		return
	}
	sess, acc, err := s.o.Auth.Join(r.PathValue("token"), clientSource(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	value, err := s.o.Auth.CookieValue(sess)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	http.SetCookie(w, s.sessionCookie(value, int(auth.SessionIdle/time.Second)))
	if wantsHTML(r) {
		// A browser followed the link: land on the instance's own console,
		// which is the only place this session can go.
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.respond(w, r, http.StatusOK, map[string]any{
		"session": map[string]any{"subject": sess.Subject, "instance": acc.Instance, "expires": sess.Expires, "csrf": sess.CSRF},
	}, "", nil)
}

// joinURL is the link an operator hands out: the instance's own console
// hostname, which is the only one the gateway accepts this credential
// on. Before `podaro setup` there is no domain, and the link is the path
// alone — honest about what is not configured yet rather than inventing
// a host.
func (s *Server) joinURL(instance, secret string) string {
	home := s.homeURL()
	if home == "" {
		return Prefix + "/join/" + secret
	}
	scheme, host, ok := splitHome(home)
	if !ok {
		return Prefix + "/join/" + secret
	}
	return scheme + "://" + instance + "." + host + Prefix + "/join/" + secret
}

// splitHome breaks `https://labs.example:8443` into its scheme and host.
func splitHome(home string) (scheme, host string, ok bool) {
	for _, p := range []string{"https", "http"} {
		if rest, found := strings.CutPrefix(home, p+"://"); found {
			return p, rest, rest != ""
		}
	}
	return "", "", false
}
