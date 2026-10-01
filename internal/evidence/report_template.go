// SPDX-License-Identifier: AGPL-3.0-only

package evidence

// The report's one page. It is a Go template with its stylesheet inline
// and nothing fetched: `html/template` escapes every value, and the
// only markup is this file's.

import "html/template"

var reportTemplate = template.Must(template.New("report").Funcs(reportFuncs).Parse(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{brand}} evidence · {{.Instance}}</title>
<style>
:root {
  --ink: #14171a; --muted: #5a6270; --line: #dfe3e8; --bg: #ffffff; --panel: #f7f8fa;
  --pass: #1a7f37; --fail: #b42318; --warn: #9a6700; --attest: #6941c6;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root { --ink: #e8eaed; --muted: #9aa4b2; --line: #2c313a; --bg: #14171a; --panel: #1b1f24;
          --pass: #4ac26b; --fail: #ff7b72; --warn: #d9a441; --attest: #b692f6; }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 2.5rem 1.5rem 4rem; background: var(--bg); color: var(--ink);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
main { max-width: 60rem; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
h2 { font-size: 1.05rem; margin: 2.25rem 0 .5rem; padding-bottom: .35rem; border-bottom: 1px solid var(--line); }
.sub { color: var(--muted); margin: 0 0 1.75rem; }
.facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); gap: .35rem 1.5rem;
  background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 1rem 1.15rem; }
.facts div { display: flex; gap: .6rem; }
.facts dt { color: var(--muted); min-width: 7.5rem; }
.facts dd { margin: 0; }
dl { margin: 0; }
table { width: 100%; border-collapse: collapse; margin-top: .35rem; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: .85rem; }
code, .mono { font-family: var(--mono); font-size: .87em; }
.pass { color: var(--pass); } .fail { color: var(--fail); } .error { color: var(--warn); }
.attested { color: var(--attest); } .pending { color: var(--muted); }
.tally { margin: .35rem 0 0; color: var(--muted); }
.tally strong { color: var(--ink); }
.detail { color: var(--muted); font-size: .88rem; }
.detail div { margin-top: .2rem; }
.wrap { overflow-x: auto; }
.note { color: var(--muted); font-size: .88rem; margin-top: .6rem; }
.badge { display: inline-block; border: 1px solid var(--warn); color: var(--warn);
  border-radius: 4px; padding: .05rem .4rem; font-size: .8rem; }
footer { margin-top: 3rem; padding-top: .75rem; border-top: 1px solid var(--line);
  color: var(--muted); font-size: .85rem; }
@media print { body { padding: 0; } .wrap { overflow: visible; } }
</style>
</head><body><main>

<h1>{{if .Title}}{{.Title}}{{else}}{{.Template}}{{end}}</h1>
<p class="sub">Evidence for instance <strong>{{.Instance}}</strong>
{{- if .Authoring}} <span class="badge">authoring instance — excluded from completion claims</span>{{end}}</p>

<dl class="facts">
  <div><dt>Instance</dt><dd>{{.Instance}}</dd></div>
  <div><dt>Template</dt><dd>{{.Template}}{{if .Version}} <span class="mono">@{{.Version}}</span>{{end}}</dd></div>
  <div><dt>Mode</dt><dd>{{.Mode}}</dd></div>
  {{if .Profile}}<div><dt>Profile</dt><dd>{{.Profile}}</dd></div>{{end}}
  <div><dt>Created</dt><dd>{{stamp .Created}}</dd></div>
  <div><dt>Report made</dt><dd>{{stamp .Generated}}</dd></div>
  {{if .Engine}}<div><dt>Engine</dt><dd class="mono">{{.Engine}}</dd></div>{{end}}
</dl>

<h2>Checkpoints</h2>
<p class="tally">
  <strong>Baseline</strong> — the infrastructure truths that gate <em>ready</em>:<br>
  {{tally .Baseline}}<br>
  <strong>Objective</strong> — the learner's work, expected red at the start:<br>
  {{tally .Objective}}
</p>
<p class="note">The two classes are never summed: a baseline proves the lab works, an objective proves
the work was done (spec 0001 §1). An attested result is a human's claim, recorded as one — never a
machine pass.</p>

{{range $class := (list .Baseline .Objective)}}
{{if $class.Total}}
<h2 style="text-transform: capitalize">{{$class.Class}} checkpoints</h2>
<div class="wrap"><table>
<thead><tr><th>Checkpoint</th><th>Adapter</th><th>Result</th><th>Observed</th><th>Expected</th><th>Took</th><th>When</th></tr></thead>
<tbody>
{{range $class.Results}}
<tr>
  <td class="mono">{{.ID}}</td>
  <td class="mono">{{.Adapter}}</td>
  <td class="{{if .Status}}{{.Status}}{{else}}pending{{end}}">{{glyph .Status}} {{word .Status}}</td>
  <td class="mono">{{if .ObservedText}}{{.ObservedText}}{{else}}—{{end}}</td>
  <td class="mono">{{if .ExpectedText}}{{.ExpectedText}}{{else}}—{{end}}</td>
  <td>{{if .Duration}}{{.Duration}}{{else}}—{{end}}</td>
  <td>{{stamp .At}}</td>
</tr>
{{if or .MessageText .HintText .ErrorText}}
<tr><td colspan="7" class="detail">
  {{if .MessageText}}<div>{{.MessageText}}</div>{{end}}
  {{if .ErrorText}}<div class="error">{{.ErrorText}}</div>{{end}}
  {{if .HintText}}<div>Hint: {{.HintText}}</div>{{end}}
</td></tr>
{{end}}
{{end}}
</tbody></table></div>
{{end}}
{{end}}

{{if .Services}}
<h2>What ran</h2>
<div class="wrap"><table>
<thead><tr><th>Service</th><th>Module</th><th>Image</th><th>Digest</th></tr></thead>
<tbody>
{{range .Services}}
<tr><td>{{.Name}}</td><td class="mono">{{if .Module}}{{.Module}}{{else}}—{{end}}</td>
    <td class="mono">{{.Image}}</td><td class="mono">{{short .Digest}}</td></tr>
{{end}}
</tbody></table></div>
<p class="note">Services appear by name. Excluded by contract (API §10): host addresses, hostnames
under this deployment's own domain, any host named as one — in a URL, with whatever userinfo it
carries, or with a port — and the registry an image was pulled from, since which registries are
internal is not knowable from here.
A dotted word in an author's own free text is left as written; the digest is what actually ran.</p>
{{end}}

{{if .Seeds}}
<h2>Data injected</h2>
<div class="wrap"><table>
<thead><tr><th>Seed</th><th>Generator</th><th>Count</th><th>Took</th><th>Seed value</th><th>When</th></tr></thead>
<tbody>
{{range .Seeds}}
<tr class="{{if .Failed}}fail{{end}}">
  <td class="mono">{{.Name}}</td><td class="mono">{{.Generator}}</td>
  <td>{{if .Count}}{{.Count}}{{else}}—{{end}}</td><td>{{.Duration}}</td>
  <td class="mono">{{if .Seed}}{{.Seed}}{{else}}—{{end}}</td><td>{{stamp .At}}</td>
</tr>
{{if .Message}}<tr><td colspan="6" class="detail">{{.Message}}</td></tr>{{end}}
{{end}}
</tbody></table></div>
<p class="note">Generators are deterministic: the seed value reproduces the same data (spec 0002 §5).</p>
{{end}}

{{if .Attendees}}
<h2>Who worked in this lab</h2>
<div class="wrap"><table>
<thead><tr><th>Attendee</th><th>Joins</th><th>First</th><th>Last</th></tr></thead>
<tbody>
{{range .Attendees}}
<tr><td>{{.Name}}</td><td>{{.Joins}}</td><td>{{stamp .First}}</td><td>{{stamp .Last}}</td></tr>
{{end}}
</tbody></table></div>
<p class="note">Identity comes from the access link the operator issued (API §2.4). An instance with no
access link has no attendee: the operator did the work.</p>
{{end}}

{{if .Reveals}}
<h2>Credentials revealed</h2>
<div class="wrap"><table>
<thead><tr><th>Secret</th><th>Revealed by</th><th>When</th></tr></thead>
<tbody>
{{range .Reveals}}
<tr><td class="mono">{{.Secret}}</td><td>{{if .Actor}}{{.Actor}}{{else}}—{{end}}</td><td>{{stamp .At}}</td></tr>
{{end}}
</tbody></table></div>
<p class="note">Reveal <em>events</em>, by secret name. Values are structurally absent: evidence records
that a secret was revealed, never what it was.</p>
{{end}}

{{if .Milestones}}
<h2>Lifecycle</h2>
<div class="wrap"><table>
<thead><tr><th>When</th><th>Event</th><th>Stage</th><th>Detail</th></tr></thead>
<tbody>
{{range .Milestones}}
<tr><td>{{stamp .At}}</td><td>{{.Event}}{{if .Code}} <span class="mono error">{{.Code}}</span>{{end}}</td>
    <td>{{if .Stage}}{{.Stage}}{{else}}—{{end}}</td><td class="detail">{{.Detail}}</td></tr>
{{end}}
</tbody></table></div>
{{end}}

<footer>
{{brandTitle}} · evidence is append-only and immutable; it vanishes only with <code>destroy</code>.
This report holds no secret value, no host address, no hostname under this deployment's own domain
and no host named as one — in a URL, with whatever userinfo it carries, or with a port. A dotted word
in an author's own free text is left as written (API §10 content contract).
Generated {{stamp .Generated}}.
</footer>
</main></body></html>
`))
