// SPDX-License-Identifier: AGPL-3.0-only

// Package console renders the console: full pages (the shell) and the
// content-negotiated fragments the API serves beside JSON (ADR-0003).
// The binding rule holds by construction — every fragment template
// receives the same value its JSON twin marshals, so it can render only
// what the JSON contains. Fragment goldens live in testdata/ and run in
// CI beside the JSON shape tests.
package console

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/brand"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

//go:embed templates/*.html
var templateFS embed.FS

// Renderer holds the parsed template set.
type Renderer struct {
	tmpl *template.Template
	// assets is the embedded bundle's content revision, supplied to
	// every page this renderer frames unless the caller set one (the
	// tests do, so the goldens are stable): a page that reached the
	// browser with an empty cache key would be cached for a day under
	// it, and the failed plain-form sign-in did.
	assets string
}

// New parses the embedded templates.
func New() (*Renderer, error) {
	t, err := template.New("console").Funcs(template.FuncMap{
		"glyph":    glyph,
		"rowGlyph": rowGlyph,
		"rfc3339":  func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
		"lower":    strings.ToLower,
		"deref":    func(b *bool) bool { return b != nil && *b },
		// S7 surfaces (rail, scoreboard, credentials, reset):
		"resultLine":  resultLine,
		"chips":       chips,
		"status":      statusToken,
		"word":        statusWord,
		"expectation": expectation,
		"join":        join,
		"summary":     evSummary,
		"markdown":    renderMarkdown,
		"seconds":     seconds,
		// The product's display name (internal/brand): set when the
		// binary is built, never from a request, so a page may print it
		// as it prints its own static text.
		"brand": func() string { return brand.Name },
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Renderer{tmpl: t, assets: podaro.ConsoleRevision()}, nil
}

// Must is New for package-level wiring.
func Must() *Renderer {
	r, err := New()
	if err != nil {
		panic(err)
	}
	return r
}

// Fragment names (the API's Accept: text/html twins and page parts).
const (
	FragmentInstances = "instances" // []engine.InstanceView — GET /instances
	FragmentInstance  = "instance"  // engine.InstanceView   — GET /instances/{name}
	// FragmentInstanceLive is the same read as seen by the console's live
	// region: the ladder, plus the parts of the page one event also
	// changes, as out-of-band swaps. Every part is a projection of a twin
	// the same caller may fetch (ADR-0003 amendment, plan S7).
	FragmentInstanceLive = "instancelive" // InstanceLive — GET /instances/{name} (text/html)
	FragmentSystem       = "system"       // sysinfo.Info          — GET /system
	FragmentLegal        = "legal"        // legal.Info            — GET /system/legal, and the /legal page
	FragmentSession      = "session"      // auth.Whoami           — GET /auth/session
	FragmentError        = "error"        // *pdr.Error            — any §3 envelope
	FragmentLogin        = "login"        // LoginData             — the login form (page chrome)
	// Plan S7 — the lab surface. Each names the twin it renders; the
	// wrapper types in rail.go carry those twins plus render manners.
	FragmentRail      = "rail"       // RailData    — GET …/playbooks/{id} (+ progress, checkpoints)
	FragmentPlaybooks = "playbooks"  // []engine.PlaybookSummary — GET …/playbooks
	FragmentEvidence  = "evidence"   // EvidenceData — GET …/checkpoints
	FragmentJournal   = "journal"    // JournalData  — GET …/evidence
	FragmentSecrets   = "secrets"    // SecretsData  — GET …/secrets
	FragmentReveal    = "reveal"     // RevealData   — POST …/secrets/{s}/reveal
	FragmentResetPlan = "resetplan"  // ResetData    — GET …/reset-plan
	FragmentResult    = "result"     // ResultLine   — POST …/checkpoints/{id}/run
	FragmentStartHere = "starthere"  // StartHere    — projected from the instance twin
	FragmentTabs      = "tabs"       // []Tab        — projected from the instance twin
	FragmentKeymap    = "keymap"     // nil          — UX §9's keyboard map
	FragmentLab       = "labsurface" // LabData     — the instance page, assembled
)

// Fragment renders one named fragment.
func (r *Renderer) Fragment(name string, data any) (template.HTML, error) {
	var buf bytes.Buffer
	if err := r.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		return "", fmt.Errorf("fragment %s: %w", name, err)
	}
	return template.HTML(buf.String()), nil //nolint:gosec // html/template output
}

// ShellData is the page frame around a fragment.
type ShellData struct {
	Title   string
	Version string
	// Assets is the console bundle's content revision
	// (podaro.ConsoleRevision), the asset URLs' cache key: the gateway
	// serves assets for a day, so the key must change whenever a bundle
	// does, and the release number does not on an in-place upgrade of
	// a dev build. Page supplies it when empty; the tests set it.
	Assets string
	// HomeURL is the operator console's origin (https://<domain>:<port>).
	HomeURL string
	// Instance is set on instance-hostname pages.
	Instance *engine.InstanceView
	// Session is nil on the login page.
	Session *SessionView
	// Poll is the API path the main region refreshes from; empty for
	// static pages.
	Poll string
	// Feed is the instance's SSE endpoint (API §4). When set, the main
	// region refreshes from Poll on a feed event instead of on a timer —
	// the live-region contract of UX §11, and what ADR-0003 assigns to
	// the htmx SSE extension. A page without a feed (the instance list,
	// which spans instances and so has no single stream) keeps the timer.
	Feed string
	Body template.HTML
}

// Bound reports whether this page is being rendered for an
// instance-bound session (API §2.4): an attendee's.
//
// The shell must not advertise what that grant structurally excludes —
// reset, other instances, the auth and authoring surfaces — because the
// engine refuses those and the console would be offering a 403 with the
// look of a control (UX §12: no disabled controls without a stated
// reason, and an advertised control that answers 403 is worse than
// either). The scope already exists and ranks below read; the shell
// simply had no way to see it.
func (d ShellData) Bound() bool { return d.Session != nil && d.Session.Instance != "" }

// SessionView is what the shell shows about the signed-in caller.
type SessionView struct {
	Subject string
	CSRF    string
	// Instance is the one instance this session is bound to (API §2.4),
	// empty for the operator's. It is the caller's capability as far as
	// the shell is concerned: an instance-bound session carries the
	// `instance` scope, which ranks *below* read.
	Instance string
}

// LoginData feeds the login form.
type LoginData struct {
	Username string
	// Next is the in-domain URL to return to after login, if any.
	Next  string
	Error *pdr.Error
}

// PageTitle is a page's <title>: what the page is, then the product's
// display name (internal/brand) — "Sign in · Podaro", or the name alone.
func PageTitle(what ...string) string {
	return strings.Join(append(what, brand.Name), " · ")
}

// Page renders the full shell.
func (r *Renderer) Page(w io.Writer, data ShellData) error {
	if data.Title == "" {
		data.Title = PageTitle()
	}
	if data.Assets == "" {
		data.Assets = r.assets
	}
	return r.tmpl.ExecuteTemplate(w, "layout", data)
}

// Glyph pairs a UX §4 glyph with its status class.
type Glyph struct {
	Char  string
	Class string
	Word  string
}

func glyph(status string) Glyph {
	switch status {
	case "pass", "ready", "complete":
		return Glyph{"●", "ready", status}
	case "progress":
		return Glyph{"◐", "progress", status}
	case "fail":
		return Glyph{"✗", "fail", status}
	case "warn":
		return Glyph{"!", "warn", status}
	case "attest":
		return Glyph{"◇", "attest", status}
	case "skip":
		return Glyph{"–", "pending", status}
	default:
		return Glyph{"○", "pending", "pending"}
	}
}

// rowGlyph mirrors the CLI's ladder row logic (internal/cli): failed ✗,
// in-progress ◐, reached ●, else ○.
func rowGlyph(s engine.ServiceView, inProgress bool) Glyph {
	switch {
	case s.Error != "":
		return glyph("fail")
	case s.Stage == string(state.StageAlive) && inProgress:
		return glyph("progress")
	case s.Stage != "":
		return glyph("complete")
	default:
		return glyph("pending")
	}
}
