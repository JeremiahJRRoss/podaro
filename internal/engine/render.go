// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/secrets"
	"github.com/jeremiahjrross/podaro/internal/wire"
)

// Create-time rendering (plan S6; spec 0003 §5, §6, §9.1): per-instance
// secret values replace `${secret:<name>}` in a service's env, command,
// args, and files, and in its init requests — engine-side, so the values
// exist in the container's configuration and the secret store, and
// nowhere else.

// renderedConfig is an EffectiveConfig with its references resolved.
type renderedConfig struct {
	Env        map[string]string
	Entrypoint []string
	Args       []string
	Files      []runtime.FileSpec
}

// renderConfig resolves a service's effective configuration.
func renderConfig(cfg *lab.EffectiveConfig, values map[string]string) (*renderedConfig, error) {
	out := &renderedConfig{Env: map[string]string{}}
	if cfg == nil {
		return out, nil
	}
	for k, v := range cfg.Env {
		r, err := secrets.Render(v, values)
		if err != nil {
			return nil, fmt.Errorf("env %s: %w", k, err)
		}
		out.Env[k] = r
	}
	for _, a := range cfg.Entrypoint {
		r, err := secrets.Render(a, values)
		if err != nil {
			return nil, fmt.Errorf("command: %w", err)
		}
		out.Entrypoint = append(out.Entrypoint, r)
	}
	for _, a := range cfg.Args {
		r, err := secrets.Render(a, values)
		if err != nil {
			return nil, fmt.Errorf("args: %w", err)
		}
		out.Args = append(out.Args, r)
	}
	for _, f := range cfg.Files {
		// A file's path names the file and is never rendered: validation
		// refuses a reference there, and so does create, should one reach
		// it.
		if strings.Contains(f.Path, "${secret:") {
			return nil, fmt.Errorf("file %s: a secret reference in a file's path is never rendered — it belongs in the content", f.Path)
		}
		content, err := secrets.Render(f.Content, values)
		if err != nil {
			return nil, fmt.Errorf("file %s: %w", f.Path, err)
		}
		mode := fs.FileMode(0o644)
		if f.Mode != "" {
			m, err := strconv.ParseUint(f.Mode, 8, 32)
			if err != nil {
				return nil, fmt.Errorf("file %s: mode %q", f.Path, f.Mode)
			}
			mode = fs.FileMode(m)
		}
		out.Files = append(out.Files, runtime.FileSpec{Path: f.Path, Mode: mode, Content: []byte(content)})
	}
	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].Path < out.Files[j].Path })
	return out, nil
}

// envFile renders the environment in Podman's --env-file form.
func (r *renderedConfig) envFile() (string, error) {
	keys := make([]string, 0, len(r.Env))
	for k := range r.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v := r.Env[k]
		if strings.ContainsAny(v, "\n\r") {
			return "", fmt.Errorf("env %s: multi-line values cannot be passed through an env file", k)
		}
		if strings.ContainsAny(k, "=\n\r ") || k == "" {
			return "", fmt.Errorf("env %q: not a valid variable name", k)
		}
		fmt.Fprintf(&b, "%s=%s\n", k, v)
	}
	return b.String(), nil
}

// Init request defaults (module schema: retries {10, 5s}).
const (
	defaultInitAttempts = 10
	defaultInitBackoff  = 5 * time.Second
	// initRequestBudget bounds one attempt of one request.
	initRequestBudget = 60 * time.Second
)

// renderInitProgram turns a service's init requests into the program its
// helper executes: targets resolved to in-lab URLs through declared
// endpoints (the request's port, else the target's api endpoint, else its
// first), bodies and headers rendered, auth resolved to the secret's
// value, poll semantics with the schema defaults.
func renderInitProgram(lv *labView, service string, init *lab.Init, values map[string]string) (*runtime.InitProgram, error) {
	p := &runtime.InitProgram{}
	for i, req := range init.Requests {
		target := req.Service
		if target == "" {
			target = service
		}
		port, scheme := req.Port, req.Scheme
		if port == 0 {
			ep, ok := lab.EndpointOf(lv.res, target, "api")
			if !ok {
				ep, ok = lab.EndpointOf(lv.res, target, "")
			}
			if !ok {
				return nil, fmt.Errorf("init request %d targets %s, which declares no endpoint to reach", i+1, target)
			}
			port = ep.Port
			if scheme == "" && ep.Scheme != "tcp" {
				scheme = ep.Scheme
			}
		}
		if scheme == "" {
			scheme = "http"
		}
		// The path is rendered like the headers and the body: every free
		// string of a request the validator lets a reference into is one
		// create renders, so no placeholder reaches the helper as text.
		reqPath, err := secrets.Render(req.Path, values)
		if err != nil {
			return nil, fmt.Errorf("init request %d path: %w", i+1, err)
		}
		if !strings.HasPrefix(reqPath, "/") {
			reqPath = "/" + reqPath
		}
		r := runtime.InitRequest{Method: req.Method, URL: fmt.Sprintf("%s://%s:%d%s", scheme, target, port, reqPath), Insecure: scheme == "https", Attempts: defaultInitAttempts, BackoffMillis: int(defaultInitBackoff / time.Millisecond)}
		if r.Method == "" {
			r.Method = "GET"
		}
		if len(req.Headers) > 0 {
			r.Headers = map[string]string{}
			for k, v := range req.Headers {
				rv, err := secrets.Render(v, values)
				if err != nil {
					return nil, fmt.Errorf("init request %d header %s: %w", i+1, k, err)
				}
				r.Headers[k] = rv
			}
		}
		if req.Body != nil {
			r.HasBody = true
			switch b := req.Body.(type) {
			case string:
				rb, err := secrets.Render(b, values)
				if err != nil {
					return nil, fmt.Errorf("init request %d body: %w", i+1, err)
				}
				r.Body = rb
			default:
				raw, err := json.Marshal(b)
				if err != nil {
					return nil, fmt.Errorf("init request %d body: %w", i+1, err)
				}
				// Generated values are alphanumeric, hex, or a UUID, so a
				// value substituted inside a JSON string stays valid JSON.
				rb, err := secrets.Render(string(raw), values)
				if err != nil {
					return nil, fmt.Errorf("init request %d body: %w", i+1, err)
				}
				r.Body = rb
			}
		}
		if req.Auth != nil && req.Auth.Secret != "" {
			v, ok := values[req.Auth.Secret]
			if !ok {
				return nil, fmt.Errorf("init request %d authenticates with secret %s, which has no value", i+1, req.Auth.Secret)
			}
			r.Username, r.Password = req.Auth.Username, v
			if r.Username == "" {
				r.Username = req.Auth.Secret
			}
		}
		if req.Until != nil {
			r.Until = req.Until.Status
		}
		if req.Retries != nil {
			if req.Retries.Attempts > 0 {
				r.Attempts = req.Retries.Attempts
			}
			if d, err := time.ParseDuration(req.Retries.Backoff); err == nil && d >= 0 {
				r.BackoffMillis = int(d / time.Millisecond)
			}
		}
		if r.Until == 0 {
			// A single attempt, retried only on transient failures.
			if req.Retries == nil {
				r.Attempts = 3
			}
		}
		p.Requests = append(p.Requests, r)
	}
	return p, nil
}

// maxInitTimeout caps the helper's run budget at a day. The attempts and
// backoff a module declares (spec 0003 §9.1) are the budget it asked for,
// up to what a lab could ever wait for: a schema-valid `backoff:
// 1000000h` multiplied by its attempts wrapped the sum into a negative
// that neither runtime applied as a timeout, and the helper would have
// slept its declared backoff under the job's unbounded context.
const maxInitTimeout = 24 * time.Hour

// initTimeout bounds the whole helper run honestly: every request may
// spend its full per-attempt budget (connect + transfer) on each of its
// attempts, with a backoff between attempts, plus thirty seconds of
// slack for the helper itself. The sum saturates at maxInitTimeout —
// every term is capped before it is added, so no declared value, however
// large, wraps it.
func initTimeout(p *runtime.InitProgram) time.Duration {
	per := initConnectTimeout + initRequestBudget
	total := 30 * time.Second
	for _, r := range p.Requests {
		attempts := time.Duration(r.Attempts)
		if attempts < 1 {
			attempts = 1
		}
		if attempts > maxInitTimeout/per {
			return maxInitTimeout
		}
		total += attempts * per
		var backoff time.Duration
		switch {
		case r.BackoffMillis >= int(maxInitTimeout/time.Millisecond):
			backoff = maxInitTimeout
		case r.BackoffMillis > 0:
			backoff = time.Duration(r.BackoffMillis) * time.Millisecond
		}
		if backoff > 0 && attempts-1 > maxInitTimeout/backoff {
			return maxInitTimeout
		}
		total += (attempts - 1) * backoff
		if total >= maxInitTimeout {
			return maxInitTimeout
		}
	}
	return total
}

// hasHeader reports whether a request's headers name a field, whatever
// its case: HTTP field names are case-insensitive (RFC 9110 §5.1), so a
// module's `content-type` is the one Content-Type field, and the default
// yields to it rather than sending a second value.
func hasHeader(headers map[string]string, name string) bool {
	for k := range headers {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

// duplicateField reports two names in a request's header list that spell
// the same case-insensitive field: mapping keys are case-sensitive, so a
// schema-valid map can carry `Content-Type` beside `content-type`, and
// the helper would send two values of a single-valued field. The
// validator refuses it first (`init-header-duplicate`, spec 0003 §9.1);
// this is the render's own refusal.
func duplicateField(names []string) (first, second string, dup bool) {
	seen := map[string]string{}
	for _, n := range names {
		lower := strings.ToLower(n)
		if f, ok := seen[lower]; ok {
			return f, n, true
		}
		seen[lower] = n
	}
	return "", "", false
}

// controlCharacter names the first part of a request — its URL, its
// method, its credentials, a header's name or value — that carries a CR,
// LF or NUL, or "" when none does: the option file curl reads is
// line-based, so a raw newline would end a quoted parameter early and
// make the rest another option (`user` first of all),
// and an HTTP field may hold none of the three (RFC 9110
// §5.5). Two characters `\n` are not one (the backslash arrives as declared).
// The credentials are named, never shown.
func controlCharacter(r runtime.InitRequest) string {
	has := func(s string) bool { return strings.ContainsAny(s, "\r\n\x00") }
	switch {
	case has(r.URL):
		return "the URL"
	case has(r.Method):
		return "the method"
	case has(r.Username) || has(r.Password):
		return "the credentials"
	}
	keys := make([]string, 0, len(r.Headers))
	for k := range r.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if has(k) || has(r.Headers[k]) {
			return fmt.Sprintf("header %q", k)
		}
	}
	return ""
}

// initDir is where the helper's rendered files live inside the container.
const initDir = "/run/podaro/init"

// initRunnerPath is the POSIX shell runner the helper executes.
const initRunnerPath = initDir + "/run.sh"

// initConnectTimeout bounds the TCP connect of one attempt.
const initConnectTimeout = 10 * time.Second

// renderInitFiles produces what the helper container carries: the
// program (for runtimes that execute it themselves), one curl option
// file per request (`N.curl`: the URL, method, credentials, headers and
// body — never on a command line), and a POSIX shell runner that drives
// the sequence with the program's semantics: a request that declares
// `until` is polled until the response status *equals* it, up to its
// attempts with its backoff (curl alone cannot assert an exact status —
// `--fail` only distinguishes HTTP errors); a request without `until`
// succeeds on any status below 400, fails at once on a 4xx, and retries
// a 5xx or a connection failure. The first failed request ends the run:
// exit 22 with the last status, or 7 when the last attempt did not
// connect — the same codes the fake runtime produces.
func renderInitFiles(p *runtime.InitProgram) ([]runtime.FileSpec, error) {
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	files := []runtime.FileSpec{{Path: runtime.InitProgramPath, Mode: 0o600, Content: raw}}
	var script strings.Builder
	script.WriteString(initRunnerHead)
	for i, r := range p.Requests {
		if part := controlCharacter(r); part != "" {
			return nil, fmt.Errorf("init request %d: a control character (CR, LF or NUL) in %s: the option file curl reads is line-based, and an HTTP field may hold none", i+1, part)
		}
		// curl's --user and HTTP Basic (RFC 7617 §2) split the credentials
		// at the first colon, so a username carrying one cannot be sent
		// as written; the validator refuses it first (init-auth-username)
		// and the render refuses the same, naming no value.
		if strings.Contains(r.Username, ":") {
			return nil, fmt.Errorf("init request %d: the username carries a colon, at which curl's --user would split the credentials (RFC 9110 §11, RFC 7617 §2)", i+1)
		}
		var b strings.Builder
		fmt.Fprintf(&b, "# rendered by podaro — init request %d (spec 0003 §9.1)\n", i+1)
		b.WriteString("silent\nshow-error\n")
		fmt.Fprintf(&b, "url = %s\n", curlQuote(r.URL))
		fmt.Fprintf(&b, "request = %s\n", curlQuote(r.Method))
		if r.Username != "" || r.Password != "" {
			fmt.Fprintf(&b, "user = %s\n", curlQuote(r.Username+":"+r.Password))
		}
		keys := make([]string, 0, len(r.Headers))
		for k := range r.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if first, second, dup := duplicateField(keys); dup {
			return nil, fmt.Errorf("init request %d declares header %q twice (%q and %q): HTTP field names are case-insensitive, one value per field", i+1, strings.ToLower(first), first, second)
		}
		for _, k := range keys {
			// A field name is RFC 9110 §5.1's token: curl reads the first
			// colon of a header line as the field's end, so `Bad:Name`
			// would send a field `Bad` with `Name: value` — the validator
			// refuses it first (init-header-name), the render refuses the
			// same.
			if !wire.ValidFieldName(k) {
				return nil, fmt.Errorf("init request %d: header %q is not a legal HTTP field name (RFC 9110 §5.1): curl reads the first colon as the field's end", i+1, k)
			}
			// An authored Host names the virtual host the request is for;
			// curl sends it as written, so it is judged by the wire's
			// grammar first — the seed and the checkpoint paths' rule.
			// The validator refuses it
			// earlier (init-host); the render refuses the same, naming no
			// value.
			if strings.EqualFold(k, "Host") && !wire.ValidHost(r.Headers[k]) {
				return nil, fmt.Errorf("init request %d: the Host header is not a legal HTTP host — a name or an IP address, a numeric port at most (RFC 9110 §7.2)", i+1)
			}
			fmt.Fprintf(&b, "header = %s\n", curlQuote(k+": "+r.Headers[k]))
		}
		if r.BodyDeclared() {
			bodyPath := path.Join(initDir, strconv.Itoa(i+1)+".body")
			files = append(files, runtime.FileSpec{Path: bodyPath, Mode: 0o600, Content: []byte(r.Body)})
			fmt.Fprintf(&b, "data-binary = %s\n", curlQuote("@"+bodyPath))
			if !hasHeader(r.Headers, "Content-Type") {
				b.WriteString("header = \"Content-Type: application/json\"\n")
			}
		}
		fmt.Fprintf(&b, "connect-timeout = %d\nmax-time = %d\n", int(initConnectTimeout/time.Second), int(initRequestBudget/time.Second))
		if r.Insecure {
			b.WriteString("insecure\n")
		}
		b.WriteString("output = \"/dev/null\"\n")
		b.WriteString("write-out = \"%{http_code}\"\n")
		files = append(files, runtime.FileSpec{Path: path.Join(initDir, strconv.Itoa(i+1)+".curl"), Mode: 0o600, Content: []byte(b.String())})

		attempts := r.Attempts
		if attempts < 1 {
			attempts = 1
		}
		until := ""
		if r.Until != 0 {
			until = strconv.Itoa(r.Until)
		}
		fmt.Fprintf(&script, "req %d %s %s %d %s %s || exit $?\n", i+1, shellQuote(r.Method), shellQuote(r.URL), attempts, sleepSeconds(r.BackoffMillis), shellQuote(until))
	}
	script.WriteString("exit 0\n")
	files = append(files, runtime.FileSpec{Path: initRunnerPath, Mode: 0o700, Content: []byte(script.String())})
	return files, nil
}

// initRunnerHead is the runner's fixed part: req runs one request's
// attempts against its option file and judges the status as the program
// says. POSIX sh (busybox): no arrays, no bashisms.
const initRunnerHead = `#!/bin/sh
# rendered by podaro — the init request sequence (spec 0003 §9.1)
set -u
dir=` + initDir + `
# The helper's root filesystem is read-only (Spec 0002 §3); only /tmp is
# writable, so curl's diagnostics go there.
errdir="${TMPDIR:-/tmp}"
# req INDEX METHOD URL ATTEMPTS BACKOFF_SECONDS UNTIL_STATUS_OR_EMPTY
req() {
  n=$1; method=$2; url=$3; attempts=$4; backoff=$5; until=$6
  i=1
  while :; do
    code=$(curl --config "$dir/$n.curl" 2>"$errdir/init.$n.err") || code=000
    [ -n "$code" ] || code=000
    if [ -n "$until" ]; then
      if [ "$code" = "$until" ]; then echo "$code $method $url"; return 0; fi
    else
      case "$code" in
        [123]??) echo "$code $method $url"; return 0 ;;
        4??) break ;;
      esac
    fi
    if [ "$i" -ge "$attempts" ]; then break; fi
    i=$((i+1))
    if [ "$backoff" != "0" ]; then sleep "$backoff"; fi
  done
  echo "$code $method $url"
  if [ "$code" = "000" ]; then
    echo "curl: (7) request $n $method $url: $(tr -d '\r' <"$errdir/init.$n.err" | tail -n 1)" >&2
    return 7
  fi
  if [ -n "$until" ]; then
    echo "curl: (22) request $n $method $url returned $code (wanted $until)" >&2
  else
    echo "curl: (22) request $n $method $url returned $code" >&2
  fi
  return 22
}
`

// sleepSeconds renders a backoff in milliseconds as the seconds `sleep`
// takes — "0" for none (the runner skips the call), "0.25" for 250 ms,
// "5" for 5 s: the declared value, never rounded up to a whole second
// (busybox and GNU sleep accept fractions).
func sleepSeconds(millis int) string {
	if millis <= 0 {
		return "0"
	}
	return strconv.FormatFloat(float64(millis)/1000, 'f', -1, 64)
}

// shellQuote renders a value as one POSIX shell word: single-quoted,
// with embedded single quotes closed, escaped, and reopened.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// curlQuote renders a value for curl's config grammar: double-quoted,
// with backslash and double quote escaped (curl also reads \n, \t, \r, \v
// inside quotes; a literal backslash is doubled so it stays literal).
func curlQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	// Nothing is undone: curl reads `\n`, `\t`, `\r` and `\v` inside a
	// quoted parameter as control characters, so a backslash a value
	// carries stays doubled and arrives as declared. The reversal that
	// once stood here served write-out, which never passes through.
	return `"` + s + `"`
}

// initEntrypoint and initCommand are what the helper image runs: the
// POSIX shell of the pinned curl image, on the rendered runner. The
// image's own entrypoint (curl) is replaced — the runner calls curl.
func initEntrypoint() []string { return []string{"/bin/sh"} }

func initCommand() []string { return []string{initRunnerPath} }
