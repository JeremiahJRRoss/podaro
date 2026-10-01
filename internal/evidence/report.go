// SPDX-License-Identifier: AGPL-3.0-only

package evidence

// The human evidence report (API §10, plan S9): the artifact a presenter
// forwards after a demo and a trainee keeps after a lab.
//
// The §10 content contract is what this file implements, and it is a
// contract about what is *not* there as much as what is. It contains the
// instance, its template and versions and image digests; the checkpoint
// results split by class with observed against expected; the seed runs
// and their durations; the attendee identity when an access link was
// used; and reveal *events* by secret name. It excludes secret values
// (structurally — evidence records hashes and counts, never values),
// host addresses, and full internal hostnames: services appear by name.
//
// The page is one file. It carries its own stylesheet and makes no
// external request, because a report is forwarded to people who will
// open it from a mail attachment on a laptop that has never heard of
// this lab — and because a report that phones home is a report that
// tells someone else it was opened.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jeremiahjrross/podaro/internal/brand"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// ReportData is everything the report renders. The engine assembles it;
// this package decides what reaches the page.
type ReportData struct {
	Instance  string
	Template  string
	Title     string
	Version   string
	Profile   string
	Mode      string
	Created   time.Time
	Generated time.Time
	Engine    string
	// Authoring marks a report from an authoring instance: its evidence
	// is excluded from completion claims (roadmap §3.1), and a reader
	// must be told which kind of report they are holding.
	Authoring bool

	Services   []ReportService
	Results    []state.CheckpointResult
	Seeds      []ReportSeed
	Attendees  []ReportAttendee
	Reveals    []ReportReveal
	Milestones []ReportMilestone

	// Scrub removes what the contract excludes from free text. Nil means
	// no scrubbing, which is only right in a test.
	Scrub func(string) string
}

// ReportService is one service as the report names it: the name, and the
// image it actually ran, by digest.
type ReportService struct {
	Name   string
	Module string
	Image  string
	Digest string
}

// ReportSeed is one seed run.
type ReportSeed struct {
	Name      string
	Generator string
	Count     int
	Duration  string
	At        time.Time
	Seed      string
	Failed    bool
	Message   string
}

// ReportAttendee is one person who joined by an access link. Identity is
// the name the operator issued the link under — the report's answer to
// "who did this work" (D4).
type ReportAttendee struct {
	Name  string
	First time.Time
	Last  time.Time
	Joins int
}

// ReportReveal is one reveal *event*: the secret's name, who revealed
// it, and when. Never the value — there is none in evidence to print.
type ReportReveal struct {
	Secret string
	Actor  string
	At     time.Time
}

// ReportMilestone is one lifecycle line: the stage reached, or a warning
// like PDR-W101.
type ReportMilestone struct {
	At     time.Time
	Event  string
	Stage  string
	Code   string
	Detail string
}

// classSummary is one class's tally, never summed with the other's
// (spec 0001 §1).
type classSummary struct {
	Class    string
	Pass     int
	Fail     int
	Attested int
	Error    int
	Pending  int
	Total    int
	Results  []reportResult
}

type reportResult struct {
	state.CheckpointResult
	ObservedText string
	ExpectedText string
	MessageText  string
	HintText     string
	ErrorText    string
}

type reportView struct {
	ReportData
	Baseline  classSummary
	Objective classSummary
}

// Report renders the page. It never fails on content: a field the
// engine could not gather is absent from the page rather than a reason
// not to produce one — an operator asking for the report after a lab
// went wrong is exactly who needs it.
func Report(d ReportData) ([]byte, error) {
	scrub := d.Scrub
	if scrub == nil {
		scrub = func(s string) string { return s }
	}
	v := reportView{ReportData: d}
	// The heading is the template's own title: free text up to 80
	// characters, so it can carry an address as readily as any message
	// can, and it was the one free-text field on the page that did not
	// pass the scrubber. Its neighbours cannot: `metadata.name` is a DNS
	// label and `version` is three numbers, by schema.
	v.Title = scrub(d.Title)
	v.Baseline = summarise("baseline", d.Results, scrub)
	v.Objective = summarise("objective", d.Results, scrub)
	// An image reference carries a registry, and a registry is a host: an
	// address or a hostname, which §10 says this report excludes. The
	// scrubber alone was not enough — it removes addresses and this
	// deployment's own domain, and an internal registry is usually
	// neither (`registry.corp/team/product`), so the host is taken off
	// the reference first. Which registries are internal is not knowable
	// here, so none is kept: the repository, tag and digest say what ran,
	// and the digest is the identity.
	for i := range v.Services {
		v.Services[i].Image = scrub(withoutRegistry(v.Services[i].Image))
	}
	// An attendee's name and a reveal's actor are the access name an
	// operator chose, and `CheckUsername` allows digits and dots — so
	// `10.0.0.5` is a name a link can be issued to, and it reached the
	// page as authored. Round 5 looked at this and left it, reasoning
	// that scrubbing a name could mangle a legitimate one; that weighed
	// a hypothetical against a stated contract, and the contract wins.
	// A name without an address in it is untouched.
	for i := range v.Attendees {
		v.Attendees[i].Name = scrub(v.Attendees[i].Name)
	}
	for i := range v.Reveals {
		v.Reveals[i].Actor = scrub(v.Reveals[i].Actor)
		v.Reveals[i].Secret = scrub(v.Reveals[i].Secret)
	}
	for i := range v.Seeds {
		v.Seeds[i].Message = scrub(v.Seeds[i].Message)
	}
	for i := range v.Milestones {
		v.Milestones[i].Detail = scrub(v.Milestones[i].Detail)
	}
	var buf bytes.Buffer
	if err := reportTemplate.Execute(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// withoutRegistry removes an image reference's registry host, leaving
// the repository path. The OCI rule is the one used here: the part
// before the first `/` is a registry when it holds a `.` or a `:`, or is
// exactly `localhost` — otherwise it is the first path element of a
// Docker Hub short name and no host at all.
func withoutRegistry(ref string) string {
	head, rest, ok := strings.Cut(ref, "/")
	if !ok {
		return ref
	}
	if head != "localhost" && !strings.ContainsAny(head, ".:") {
		return ref
	}
	return "[registry withheld]/" + rest
}

func summarise(class string, all []state.CheckpointResult, scrub func(string) string) classSummary {
	s := classSummary{Class: class}
	for _, r := range all {
		if r.Class != class {
			continue
		}
		s.Total++
		switch r.Status {
		case "pass":
			s.Pass++
		case "fail":
			s.Fail++
		case "attested":
			s.Attested++
		case "error":
			s.Error++
		default:
			s.Pending++
		}
		s.Results = append(s.Results, reportResult{
			CheckpointResult: r,
			ObservedText:     scrub(compact(r.Observed)),
			ExpectedText:     scrub(compact(r.Expected)),
			MessageText:      scrub(r.Message),
			HintText:         scrub(r.Hint),
			ErrorText:        scrub(errorText(r)),
		})
	}
	sort.Slice(s.Results, func(i, j int) bool { return s.Results[i].ID < s.Results[j].ID })
	return s
}

func errorText(r state.CheckpointResult) string {
	if r.Error == nil {
		return ""
	}
	parts := []string{r.Error.Code, r.Error.Message}
	if r.Error.Cause != "" {
		parts = append(parts, r.Error.Cause)
	}
	return strings.Join(parts, " · ")
}

// compact renders recorded JSON on one line. A value the engine wrote is
// already redaction-filtered; this only makes it readable.
func compact(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}

// ipLiteral matches a host address. The contract excludes them: a report
// is forwarded outside the organisation that ran the lab, and an address
// is infrastructure.
//
// The IPv6 halves are drawn where they cannot take ordinary text with
// them. A compressed address is recognised by its `::`, which prose does
// not produce; an uncompressed one needs at least five groups, which no
// clock time reaches — `10:30:00` is three, and a report that redacted
// the time in a message would be worse than one that printed an address.
var ipLiteral = regexp.MustCompile(
	`\b(?:\d{1,3}\.){3}\d{1,3}\b` +
		`|\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b` +
		`|\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?` +
		`|::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*\b`)

// hostInURL and hostPort catch a hostname where it is unambiguously a
// host: the authority of a URL, or a name with a port after it. Both
// require a dot in the name, which is what keeps them off a service
// label the domain cut has already reduced — `https://prometheus/`
// stays as it is, and `https://db.internal/health` does not.
//
// A *bare* dotted word is deliberately left alone. A pattern loose
// enough to catch every possible FQDN also catches
// `lab.podaro.dev/v1alpha2`, `podaro.jobs.finished` and
// `report.junit.xml`, and a report that mangles the words it prints is a
// report nobody trusts. What the report claims is therefore exactly
// this, in its own footer and in API §10: addresses, hostnames under
// this deployment's domain, and any host named as a host.

// authority is where a URL's host begins: a scheme and `//`, or `//` on
// its own. A scheme-relative reference is a URL too, and requiring the
// scheme let `//svc:…@db.internal/health` past both rules below at once
// — the host by one, the credential by the other.
// Without a scheme it must begin the text or follow a byte that cannot
// continue a path, which is what keeps it off the second slash of
// `…/a.b//report.junit.xml`. Both rules are built from this one string,
// because a host rule and a credential rule that disagree about where an
// authority starts is exactly how that hole was opened.
const authority = `([a-zA-Z][a-zA-Z0-9+.\-]*://|(?:^|[^/A-Za-z0-9.\-])//)`

var (
	// The final label is a DNS label, not two-or-more letters. That was
	// a guess about top-level domains, and an internal name — `db.corp1`,
	// a punycode label — was matched only as far as its letters, so the
	// report went out reading `[hostname withheld]1`: the label that
	// identifies the host, left behind by the rule that removes hosts.
	// `hostPort` carried the same guess and
	// matched nothing at all in that case, so both move together.
	// Every group inside a label is non-capturing, and the labels before
	// the last are one non-capturing repeat: the only numbered groups
	// left are the authority in one rule and the port in the other, so
	// each replacement names the one thing it puts back.
	label     = `[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?`
	hostInURL = regexp.MustCompile(authority + `(?:` + label + `\.)+` + label)
	hostPort  = regexp.MustCompile(`\b(?:` + label + `\.)+` + label + `(:\d{1,5})\b`)

	// A URL's userinfo is a credential by construction, and invariant 6
	// says a secret never appears in evidence — of everything the
	// report holds, this is the page built to leave the building. It is
	// removed as its own rule rather than as part of the host, because
	// by the time these run the host may be a bare service label the
	// domain cut left behind: `https://svc:…@es.lab.example.com/` reads
	// `https://es/`, and the rule that withholds hosts would not have
	// looked at it twice. The authority ends at
	// the first `/`, `?`, `#` or space, so an address written in prose
	// after a URL is not swept up as one.
	urlUserinfo = regexp.MustCompile(authority + `[^/?#\s]*@`)
)

// Scrubber builds the filter the contract's exclusions need: host
// addresses become a placeholder, a hostname under this deployment's
// domain is cut back to the label a service is known by — so
// `prometheus.intro.lab.example.com` reads `prometheus`, the
// name the rest of the report uses — and a host named as a host, in a
// URL or with a port, is withheld whatever domain it is under. A URL's
// userinfo never survives, whichever of those its host turns out to be.
func Scrubber(domain string) func(string) string {
	var suffixes []string
	if d := strings.Trim(strings.TrimSpace(domain), "."); d != "" {
		suffixes = append(suffixes, "."+d)
	}
	return func(s string) string {
		for _, suffix := range suffixes {
			s = cutSuffixes(s, suffix)
		}
		// Credentials before anything looks at the host, then
		// addresses, so an address in a URL is named as one.
		s = urlUserinfo.ReplaceAllString(s, "${1}")
		s = ipLiteral.ReplaceAllString(s, "[address withheld]")
		s = hostInURL.ReplaceAllString(s, "${1}[hostname withheld]")
		return hostPort.ReplaceAllString(s, "[hostname withheld]${1}")
	}
}

// cutSuffixes removes a domain suffix wherever it appears, leaving the
// label before it. The scan is over the whole string because hostnames
// arrive inside URLs, messages and error causes, not on their own.
//
// It is case-insensitive because DNS is: `DB.LAB.EXAMPLE.COM` is this
// deployment's own name written in an author's own shout, and comparing
// bytes let it past the cut and then — having no port and no scheme —
// past the other two rules as well. The scan runs
// over an ASCII-lowered mirror of the same byte length, so every index
// it finds is an index into the original and the text around the name
// goes out exactly as it was written.
func cutSuffixes(s, suffix string) string {
	lower, lowerSuffix := asciiLower(s), asciiLower(suffix)
	var b strings.Builder
	for {
		i := strings.Index(lower, lowerSuffix)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		end := i + len(lowerSuffix)
		// Only a whole label boundary: `.lab.example` inside
		// `.lab.example.org` is not this domain.
		if end < len(s) && (isHostByte(s[end])) {
			b.WriteString(s[:end])
			s, lower = s[end:], lower[end:]
			continue
		}
		// Keep everything up to the suffix — which ends with the last
		// label of the hostname, the service or instance name.
		b.WriteString(s[:i])
		s, lower = s[end:], lower[end:]
	}
}

// asciiLower lowers A–Z and nothing else. strings.ToLower would be
// wrong here for the one reason that matters: it can change a string's
// length (`İ` becomes two bytes), and these indexes are used against
// the original. A hostname is ASCII, so nothing a domain suffix can
// contain is missed.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func isHostByte(c byte) bool {
	return c == '-' || c == '.' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

var reportFuncs = template.FuncMap{
	// The build's display name and title (internal/brand), set when the
	// binary is built and never from a request.
	"brand":      func() string { return brand.Name },
	"brandTitle": func() string { return brand.Title },
	"stamp": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.UTC().Format("2006-01-02 15:04:05 UTC")
	},
	"day": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.UTC().Format("2006-01-02")
	},
	"glyph": func(status string) string {
		switch status {
		case "pass":
			return "✓"
		case "fail":
			return "✗"
		case "attested":
			return "◇"
		case "error":
			return "!"
		default:
			return "○"
		}
	},
	"word": func(status string) string {
		if status == "" {
			return "not evaluated"
		}
		return status
	},
	"short": func(digest string) string {
		if len(digest) > 19 {
			return digest[:19] + "…"
		}
		return digest
	},
	// tally is one class's counts on one line, the same sentence for
	// each — a reader compares two lines, not two paragraphs.
	"tally": func(c classSummary) string {
		return fmt.Sprintf("%d passed, %d failed, %d attested, %d errored, %d not evaluated (of %d).",
			c.Pass, c.Fail, c.Attested, c.Error, c.Pending, c.Total)
	},
	// list lets the template walk the two classes without repeating the
	// whole table for each — and without letting a third class in: the
	// caller passes exactly the two the spec has.
	"list": func(items ...classSummary) []classSummary { return items },
}
