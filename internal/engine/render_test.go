// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/runtime"
)

// The init helper's rendering (spec 0003 §9.1): one curl option file per
// request carrying the URL, method, credentials, headers and body — never
// on a command line — and a POSIX shell runner that drives the sequence
// with the program's status semantics (render.go:281):
// a request with `until` is polled until the status
// *equals* it; one without succeeds below 400, fails at once on a 4xx,
// and retries a 5xx or a connection failure.
func TestInitRunnerRendersExactStatusSemantics(t *testing.T) {
	p := &runtime.InitProgram{Requests: []runtime.InitRequest{
		{Method: "GET", URL: "http://web:80/", Until: 200, Attempts: 3, BackoffMillis: 1000},
		{Method: "POST", URL: "http://web:80/api/setup", Headers: map[string]string{"X-Setup": "yes"}, Body: `{"a":1}`, Username: "admin", Password: "s3cr3tpw", Attempts: 2, BackoffMillis: 1000},
	}}
	files, err := renderInitFiles(p)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]runtime.FileSpec{}
	for _, f := range files {
		byPath[f.Path] = f
	}
	for _, want := range []string{runtime.InitProgramPath, "/run/podaro/init/1.curl", "/run/podaro/init/2.curl", "/run/podaro/init/2.body", initRunnerPath} {
		if _, ok := byPath[want]; !ok {
			t.Fatalf("missing %s in %v", want, keysOf(byPath))
		}
	}
	one := string(byPath["/run/podaro/init/1.curl"].Content)
	for _, want := range []string{`url = "http://web:80/"`, `request = "GET"`, `write-out = "%{http_code}"`, `output = "/dev/null"`, "connect-timeout = 10", "max-time = 60"} {
		if !strings.Contains(one, want) {
			t.Fatalf("1.curl lacks %q:\n%s", want, one)
		}
	}
	if strings.Contains(one, "retry") || strings.Contains(one, "fail") {
		t.Fatalf("the runner, not curl, judges attempts and statuses:\n%s", one)
	}
	two := string(byPath["/run/podaro/init/2.curl"].Content)
	for _, want := range []string{`user = "admin:s3cr3tpw"`, `header = "X-Setup: yes"`, `header = "Content-Type: application/json"`, `data-binary = "@/run/podaro/init/2.body"`} {
		if !strings.Contains(two, want) {
			t.Fatalf("2.curl lacks %q:\n%s", want, two)
		}
	}
	runner := string(byPath[initRunnerPath].Content)
	if byPath[initRunnerPath].Mode != 0o700 || !strings.HasPrefix(runner, "#!/bin/sh\n") {
		t.Fatalf("the runner is an executable POSIX script: mode %o, %q", byPath[initRunnerPath].Mode, runner[:20])
	}
	for _, want := range []string{"req 1 'GET' 'http://web:80/' 3 1 '200' || exit $?", "req 2 'POST' 'http://web:80/api/setup' 2 1 '' || exit $?", `if [ "$code" = "$until" ]`, "[123]??)", "4??) break", `errdir="${TMPDIR:-/tmp}"`, `2>"$errdir/init.$n.err"`, `if [ "$backoff" != "0" ]; then sleep "$backoff"; fi`} {
		if !strings.Contains(runner, want) {
			t.Fatalf("runner lacks %q:\n%s", want, runner)
		}
	}
	if strings.Contains(runner, "s3cr3tpw") {
		t.Fatal("credentials stay in the option files, never in the runner")
	}
	if ep, cmd := initEntrypoint(), initCommand(); ep[0] != "/bin/sh" || cmd[0] != initRunnerPath {
		t.Fatalf("entrypoint %v command %v", ep, cmd)
	}
	if q := shellQuote("it's"); q != `'it'\''s'` {
		t.Fatalf("shellQuote: %s", q)
	}
	// A backoff is rendered as the declared value: fractions and zero
	// preserved, never rounded up to a whole second.
	for millis, want := range map[int]string{0: "0", 1: "0.001", 250: "0.25", 1000: "1", 5000: "5", 1500: "1.5"} {
		if got := sleepSeconds(millis); got != want {
			t.Fatalf("sleepSeconds(%d) = %q, want %q", millis, got, want)
		}
	}
	sub, _ := renderInitFiles(&runtime.InitProgram{Requests: []runtime.InitRequest{{Method: "GET", URL: "http://web:80/", Attempts: 4, BackoffMillis: 250}, {Method: "GET", URL: "http://web:80/x", Attempts: 2}}})
	for _, f := range sub {
		if f.Path == initRunnerPath {
			if body := string(f.Content); !strings.Contains(body, "req 1 'GET' 'http://web:80/' 4 0.25 ''") || !strings.Contains(body, "req 2 'GET' 'http://web:80/x' 2 0 ''") {
				t.Fatalf("subsecond and zero backoffs rendered as declared:\n%s", body)
			}
		}
	}
}

func keysOf(m map[string]runtime.FileSpec) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The runner, executed by a real POSIX shell against a stub curl that
// answers a scripted sequence of statuses per request: `until` is an
// exact match polled across attempts; a mismatch after the attempts is
// exit 22 naming the wanted status; without `until` a 5xx is retried, a
// 4xx is final, and a connection failure after the attempts is exit 7 —
// the fake runtime's table, produced for real.
func TestInitRunnerExecutesTheProgramSemantics(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on this host")
	}
	// The stub curl: reads --config <n>.curl, answers the next status of
	// CODES_<n> (space separated; the last one repeats), prints it like
	// write-out would; 000 is a connection failure (exit 7). Its attempt
	// counters live under TMPDIR — the rendered directory is read-only,
	// as the helper's root filesystem is under the walls.
	bin := t.TempDir()
	stub := `#!/bin/sh
cfg=""
while [ $# -gt 0 ]; do [ "$1" = "--config" ] && cfg=$2; shift; done
n=$(basename "$cfg" .curl)
codes=$(eval "echo \"\$CODES_$n\"")
cnt=$(cat "$TMPDIR/count.$n" 2>/dev/null || echo 0); cnt=$((cnt+1)); echo "$cnt" >"$TMPDIR/count.$n"
code=$(echo "$codes" | cut -d' ' -f"$cnt"); [ -n "$code" ] || code=$(echo "$codes" | awk '{print $NF}')
if [ "$code" = "000" ]; then echo "curl: (7) Could not resolve host: web" >&2; exit 7; fi
printf '%s' "$code"
`
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, p *runtime.InitProgram, env ...string) (code int, stdout, stderr string, attempts map[string]string) {
		t.Helper()
		dir := t.TempDir()
		files, err := renderInitFiles(p)
		if err != nil {
			t.Fatal(err)
		}
		var runner string
		rendered := map[string]bool{}
		for _, f := range files {
			name := filepath.Base(f.Path)
			rendered[name] = true
			content := f.Content
			if f.Path == initRunnerPath {
				// The one seam: the runner's fixed directory becomes the test's.
				content = []byte(strings.Replace(string(f.Content), "dir="+initDir+"\n", "dir="+dir+"\n", 1))
				runner = filepath.Join(dir, name)
			}
			if err := os.WriteFile(filepath.Join(dir, name), content, os.FileMode(f.Mode)); err != nil {
				t.Fatal(err)
			}
		}
		// The walls: the rendered files' directory is read-only (Spec 0002
		// §3, --read-only); only the tmpfs at TMPDIR is writable. The mode
		// bits bind a non-root test user; root ignores them, so what the
		// runner leaves in its directory is asserted below regardless.
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		tmp := t.TempDir()
		cmd := exec.Command(sh, runner)
		cmd.Env = append([]string{"PATH=" + bin + ":" + os.Getenv("PATH"), "TMPDIR=" + tmp}, env...)
		var out, errb strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &errb
		start := time.Now()
		err = cmd.Run()
		// Each scenario makes at most three stub requests with millisecond
		// backoffs: sleeping whole seconds between them (a backoff rounded
		// up) would show here.
		if time.Since(start) > 1500*time.Millisecond {
			t.Fatalf("runner took %s for millisecond backoffs", time.Since(start))
		}
		code = 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		attempts = map[string]string{}
		for _, n := range []string{"1", "2"} {
			if raw, err := os.ReadFile(filepath.Join(tmp, "count."+n)); err == nil {
				attempts[n] = strings.TrimSpace(string(raw))
			}
		}
		// The runner's own directory stays as rendered — under --read-only
		// a write there fails the request — and its diagnostics land on
		// the writable tmpfs.
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !rendered[e.Name()] {
				t.Fatalf("the runner wrote %s into its own read-only directory: diagnostics belong under TMPDIR", e.Name())
			}
		}
		if _, err := os.Stat(filepath.Join(tmp, "init.1.err")); err != nil {
			t.Fatalf("the runner's curl diagnostics must land on the writable tmpfs: %v", err)
		}
		return code, out.String(), errb.String(), attempts
	}
	until := &runtime.InitProgram{Requests: []runtime.InitRequest{
		{Method: "GET", URL: "http://web:80/", Until: 200, Attempts: 3, BackoffMillis: 1},
		{Method: "POST", URL: "http://web:80/api/setup", Attempts: 1},
	}}
	// A: polled until the exact status; 204 (a success to curl) is not it.
	code, out, errOut, att := run(t, until, "CODES_1=204 204 200", "CODES_2=201")
	if code != 0 || out != "200 GET http://web:80/\n201 POST http://web:80/api/setup\n" || att["1"] != "3" || att["2"] != "1" {
		t.Fatalf("A: code %d out %q err %q attempts %v", code, out, errOut, att)
	}
	// B: never the wanted status → exit 22 after the attempts, the second
	// request never runs.
	code, out, errOut, att = run(t, until, "CODES_1=204", "CODES_2=201")
	if code != 22 || !strings.Contains(errOut, "curl: (22) request 1 GET http://web:80/ returned 204 (wanted 200)") || strings.Contains(out, "POST") || att["1"] != "3" || att["2"] != "" {
		t.Fatalf("B: code %d out %q err %q attempts %v", code, out, errOut, att)
	}
	plain := &runtime.InitProgram{Requests: []runtime.InitRequest{{Method: "POST", URL: "http://web:80/api/setup", Attempts: 3, BackoffMillis: 1}}}
	// C: without until a 5xx is retried and a later 2xx succeeds.
	code, out, _, att = run(t, plain, "CODES_1=500 503 201")
	if code != 0 || out != "201 POST http://web:80/api/setup\n" || att["1"] != "3" {
		t.Fatalf("C: code %d out %q attempts %v", code, out, att)
	}
	// D: a 4xx is final at once.
	code, _, errOut, att = run(t, plain, "CODES_1=404 200")
	if code != 22 || !strings.Contains(errOut, "returned 404") || att["1"] != "1" {
		t.Fatalf("D: code %d err %q attempts %v", code, errOut, att)
	}
	// E: a connection failure is retried and, still failing, is exit 7.
	code, _, errOut, att = run(t, plain, "CODES_1=000")
	if code != 7 || !strings.Contains(errOut, "curl: (7) request 1 POST http://web:80/api/setup: curl: (7) Could not resolve host: web") || att["1"] != "3" {
		t.Fatalf("E: code %d err %q attempts %v", code, errOut, att)
	}
}

// The helper's run budget covers every attempt of every request — each
// may spend its connect and transfer budget — plus the backoffs between
// them (render.go:215).
func TestInitTimeoutCoversEveryAttempt(t *testing.T) {
	p := &runtime.InitProgram{Requests: []runtime.InitRequest{{Method: "GET", URL: "http://web:80/", Until: 200, Attempts: 10, BackoffMillis: 5000}}}
	want := 30*time.Second + 10*(initConnectTimeout+initRequestBudget) + 9*5*time.Second
	if got := initTimeout(p); got != want {
		t.Fatalf("initTimeout = %s, want %s (ten attempts of %s each plus nine backoffs)", got, want, initConnectTimeout+initRequestBudget)
	}
	two := &runtime.InitProgram{Requests: []runtime.InitRequest{{Attempts: 1}, {Attempts: 2, BackoffMillis: 1000}}}
	if got := initTimeout(two); got != 30*time.Second+3*(initConnectTimeout+initRequestBudget)+time.Second {
		t.Fatalf("initTimeout(two) = %s", got)
	}
}

// An init request's path is rendered like its headers and body: every free
// string the validator lets a reference into is one create renders, so no
// placeholder reaches the helper as text (validate.go:413).
func TestInitPathIsRendered(t *testing.T) {
	init := &lab.Init{Requests: []lab.InitRequest{{Method: "POST", Port: 80, Path: "/setup/${secret:token}/keys", Headers: map[string]string{"X-Token": "${secret:token}"}}}}
	p, err := renderInitProgram(&labView{}, "web", init, map[string]string{"token": "rendered-token-value"})
	if err != nil {
		t.Fatal(err)
	}
	url := p.Requests[0].URL
	if strings.Contains(url, "${secret:") || url != "http://web:80/setup/rendered-token-value/keys" {
		t.Fatalf("the path is rendered — placeholder left %v, value present %v", strings.Contains(url, "${secret:"), strings.Contains(url, "rendered-token-value"))
	}
	if p.Requests[0].Headers["X-Token"] != "rendered-token-value" {
		t.Fatal("headers are rendered as before")
	}
	if _, err := renderInitProgram(&labView{}, "web", &lab.Init{Requests: []lab.InitRequest{{Method: "GET", Port: 80, Path: "/${secret:missing}"}}}, map[string]string{}); err == nil || !strings.Contains(err.Error(), "path") {
		t.Fatalf("an unresolvable reference in the path is the request's error: %v", err)
	}
}

// A config file's path names the file and is never rendered: a secret
// reference there is refused by validation and, should one reach create,
// by the renderer too (render.go:74).
func TestConfigFilePathsAreNeverRendered(t *testing.T) {
	cfg := &lab.EffectiveConfig{Files: []lab.File{{Path: "/etc/${secret:token}.conf", Content: "x"}}}
	if _, err := renderConfig(cfg, map[string]string{"token": "rendered-token-value"}); err == nil || !strings.Contains(err.Error(), "path") {
		t.Fatalf("a placeholder in a file path must be refused, not passed through: %v", err)
	}
	out, err := renderConfig(&lab.EffectiveConfig{Files: []lab.File{{Path: "/etc/app.conf", Content: "token=${secret:token}"}}}, map[string]string{"token": "rendered-token-value"})
	if err != nil || len(out.Files) != 1 || string(out.Files[0].Content) != "token=rendered-token-value" {
		t.Fatalf("content is rendered as before: %v %+v", err, out)
	}
}

// A request that declares its own Content-Type — in whatever case, since
// HTTP field names carry none — sends that one value: the default
// `application/json` yields to `content-type: text/plain` instead of
// joining it as a second value of a single-valued field (render.go:292).
func TestInitDefaultContentTypeYieldsToADeclaredOne(t *testing.T) {
	p := &runtime.InitProgram{Requests: []runtime.InitRequest{
		{Method: "POST", URL: "http://web:80/api/setup", Headers: map[string]string{"content-type": "text/plain"}, Body: "hello", Attempts: 1},
		{Method: "POST", URL: "http://web:80/api/setup", Body: `{"a":1}`, Attempts: 1},
	}}
	files, err := renderInitFiles(p)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]string{}
	for _, f := range files {
		byPath[f.Path] = string(f.Content)
	}
	contentTypes := func(opts string) []string {
		var got []string
		for _, line := range strings.Split(opts, "\n") {
			if strings.HasPrefix(strings.ToLower(line), `header = "content-type:`) {
				got = append(got, line)
			}
		}
		return got
	}
	if got := contentTypes(byPath["/run/podaro/init/1.curl"]); len(got) != 1 || got[0] != `header = "content-type: text/plain"` {
		t.Fatalf("a declared content-type is the one Content-Type value: %q", got)
	}
	if got := contentTypes(byPath["/run/podaro/init/2.curl"]); len(got) != 1 || got[0] != `header = "Content-Type: application/json"` {
		t.Fatalf("a body without a declared type gets the default once: %q", got)
	}
}

// A schema-valid `backoff: 1000000h` at sixty attempts wrapped the budget
// into a negative that neither runtime applied as a timeout (render.go:236):
// the sum now saturates at a day
// (spec 0003 §9.1), and an ordinary budget is unchanged.
func TestInitTimeoutSaturatesAndIsCapped(t *testing.T) {
	const day = 24 * time.Hour
	huge := int((1000000 * time.Hour) / time.Millisecond)
	past := make([]runtime.InitRequest, 2000)
	for i := range past {
		past[i] = runtime.InitRequest{Attempts: 60, BackoffMillis: 60000}
	}
	for name, p := range map[string]*runtime.InitProgram{
		"sixty attempts of a million hours":  {Requests: []runtime.InitRequest{{Attempts: 60, BackoffMillis: huge}}},
		"two attempts of a million hours":    {Requests: []runtime.InitRequest{{Attempts: 2, BackoffMillis: huge}}},
		"two thousand requests past the cap": {Requests: past},
		"a backoff at the largest int":       {Requests: []runtime.InitRequest{{Attempts: 2, BackoffMillis: int(^uint(0) >> 1)}}},
	} {
		if got := initTimeout(p); got != day {
			t.Fatalf("%s: initTimeout = %s (%d), want the day cap", name, got, int64(got))
		}
	}
	ordinary := &runtime.InitProgram{Requests: []runtime.InitRequest{{Attempts: 10, BackoffMillis: 5000}}}
	if got := initTimeout(ordinary); got != 30*time.Second+10*(initConnectTimeout+initRequestBudget)+9*5*time.Second {
		t.Fatalf("an ordinary budget is unchanged: %s", got)
	}
}

// A schema-valid header map can carry `Content-Type` beside
// `content-type` — mapping keys are case-sensitive — and the helper would
// send two values of a single-valued field (render.go:326):
// the render refuses it, naming the field, and
// renders nothing; the validator refuses it first (init-header-duplicate).
func TestInitRenderRefusesCaseVariantDuplicateHeaders(t *testing.T) {
	p := &runtime.InitProgram{Requests: []runtime.InitRequest{
		{Method: "POST", URL: "http://web:80/api/setup", Headers: map[string]string{"Content-Type": "application/json", "content-type": "text/plain"}, Body: `{"a":1}`, Attempts: 1},
	}}
	files, err := renderInitFiles(p)
	if err == nil || !strings.Contains(err.Error(), `"content-type"`) || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("two spellings of one field must be refused: files=%d err=%v", len(files), err)
	}
	// One spelling, in any case, renders once.
	ok := &runtime.InitProgram{Requests: []runtime.InitRequest{{Method: "POST", URL: "http://web:80/api/setup", Headers: map[string]string{"CONTENT-TYPE": "text/plain", "X-Setup": "yes"}, Body: "hello", Attempts: 1}}}
	files, err = renderInitFiles(ok)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Path == "/run/podaro/init/1.curl" && strings.Count(strings.ToLower(string(f.Content)), `header = "content-type:`) != 1 {
			t.Fatalf("one Content-Type line expected:\n%s", f.Content)
		}
	}
}

// A backslash in a URL or header value arrives as declared: curl reads
// `\n` inside a quoted config parameter as a newline, so the doubled
// backslash the quoting writes must stay doubled — a reversal meant for
// write-out, which never passes through here, turned a literal `\n`
// back into curl's newline (render.go:427).
func TestCurlQuoteKeepsALiteralBackslash(t *testing.T) {
	for in, want := range map[string]string{
		`a\nb`:        `"a\\nb"`,
		`plain`:       `"plain"`,
		`say "hi"`:    `"say \"hi\""`,
		`c:\path\new`: `"c:\\path\\new"`,
	} {
		if got := curlQuote(in); got != want {
			t.Fatalf("curlQuote(%q) = %s, want %s", in, got, want)
		}
	}
	p := &runtime.InitProgram{Requests: []runtime.InitRequest{{Method: "GET", URL: `http://web:80/q?x=a\nb`, Headers: map[string]string{"X-Note": `line\nbreak`}, Attempts: 1}}}
	files, err := renderInitFiles(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Path == "/run/podaro/init/1.curl" {
			for _, want := range []string{`url = "http://web:80/q?x=a\\nb"`, `header = "X-Note: line\\nbreak"`} {
				if !strings.Contains(string(f.Content), want) {
					t.Fatalf("1.curl lacks %s:\n%s", want, f.Content)
				}
			}
		}
	}
}

// A raw CR, LF or NUL in a URL, a method or a header would end a quoted
// curl parameter early — the option file is line-based — and an HTTP
// field may hold none (RFC 9110 §5.5): the render refuses the request,
// naming the part, and renders nothing. Two characters `\n`, or a tab,
// are no control character (round 42 re-read).
func TestInitRenderRefusesControlCharacters(t *testing.T) {
	base := func() runtime.InitRequest {
		return runtime.InitRequest{Method: "POST", URL: "http://web:80/api/setup", Headers: map[string]string{"X-Setup": "yes"}, Body: "hello", Attempts: 1}
	}
	for name, mutate := range map[string]func(r *runtime.InitRequest){
		"URL":          func(r *runtime.InitRequest) { r.URL = "http://web:80/api\n/setup" },
		"method":       func(r *runtime.InitRequest) { r.Method = "PO\rST" },
		"header name":  func(r *runtime.InitRequest) { r.Headers["X-Bad\n"] = "v" },
		"header value": func(r *runtime.InitRequest) { r.Headers["X-Setup"] = "a\r\nInjected: yes" },
		"NUL":          func(r *runtime.InitRequest) { r.Headers["X-Setup"] = "a\x00b" },
		"username":     func(r *runtime.InitRequest) { r.Username, r.Password = "ad\nmin", "pw" },
		"password":     func(r *runtime.InitRequest) { r.Username, r.Password = "admin", "p\rw" },
	} {
		r := base()
		mutate(&r)
		files, err := renderInitFiles(&runtime.InitProgram{Requests: []runtime.InitRequest{r}})
		if err == nil || !strings.Contains(err.Error(), "control character") {
			t.Fatalf("%s: a control character must be refused: files=%d err=%v", name, len(files), err)
		}
	}
	r := base()
	r.Headers["X-Note"] = "two characters \\n and a tab\ttoo"
	if _, err := renderInitFiles(&runtime.InitProgram{Requests: []runtime.InitRequest{r}}); err != nil {
		t.Fatalf("a backslash-n as two characters, or a tab, is no control character: %v", err)
	}
}

// curl's --user and HTTP Basic (RFC 7617 §2) split the credentials at the
// first colon, so `admin:tenant` with password `pw` would authenticate as
// `admin` with password `tenant:pw`: the render refuses a username
// carrying one, naming no value; a plain username renders as before
// (render.go:370).
func TestInitRenderRefusesAColonInTheUsername(t *testing.T) {
	bad := &runtime.InitProgram{Requests: []runtime.InitRequest{{Method: "POST", URL: "http://web:80/login", Username: "admin:tenant", Password: "pw", Attempts: 1}}}
	if files, err := renderInitFiles(bad); err == nil || !strings.Contains(err.Error(), "colon") || strings.Contains(err.Error(), "tenant") {
		t.Fatalf("a colon in the username must be refused without naming it: files=%d err=%v", len(files), err)
	}
	ok := &runtime.InitProgram{Requests: []runtime.InitRequest{{Method: "POST", URL: "http://web:80/login", Username: "admin", Password: "pw:with:colons", Attempts: 1}}}
	files, err := renderInitFiles(ok)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Path == "/run/podaro/init/1.curl" && !strings.Contains(string(f.Content), `user = "admin:pw:with:colons"`) {
			t.Fatalf("a plain username and a password with colons render as one user line:\n%s", f.Content)
		}
	}
}

// A request that declares an empty body (`body: ""`, schema-valid) is a
// request with an empty body: its body file, `data-binary` and the
// default Content-Type are rendered as for any body, where before the
// empty string read as "no body" and a different request went out (render.go:391).
// A request that declares none
// still carries none.
func TestInitSendsAnEmptyBodyItWasGiven(t *testing.T) {
	init := &lab.Init{Requests: []lab.InitRequest{
		{Method: "POST", Port: 80, Path: "/api/flush", Body: ""},
		{Method: "POST", Port: 80, Path: "/api/touch"},
	}}
	p, err := renderInitProgram(&labView{}, "web", init, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	files, err := renderInitFiles(p)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]string{}
	for _, f := range files {
		byPath[f.Path] = string(f.Content)
	}
	body, ok := byPath["/run/podaro/init/1.body"]
	if !ok || body != "" {
		t.Fatalf("the declared empty body is rendered as an empty body file: present %v, %q", ok, body)
	}
	one := byPath["/run/podaro/init/1.curl"]
	for _, want := range []string{`data-binary = "@/run/podaro/init/1.body"`, `header = "Content-Type: application/json"`} {
		if !strings.Contains(one, want) {
			t.Fatalf("request 1 sends its empty body with its type — missing %s in:\n%s", want, one)
		}
	}
	if _, ok := byPath["/run/podaro/init/2.body"]; ok || strings.Contains(byPath["/run/podaro/init/2.curl"], "data-binary") || strings.Contains(byPath["/run/podaro/init/2.curl"], "Content-Type") {
		t.Fatalf("a request without a body still has none:\n%s", byPath["/run/podaro/init/2.curl"])
	}
	// The program the fake runtime executes carries the same presence.
	if !p.Requests[0].HasBody || p.Requests[1].HasBody {
		t.Fatalf("presence follows the declaration: %+v", p.Requests)
	}
}

// An init request's authored Host is judged by the wire's grammar before
// it is rendered — curl sends it as written — as the seed and checkpoint
// paths judge theirs (render.go:390). A
// legal one is rendered as the header curl sends as the wire Host.
func TestInitRenderRefusesAnIllegalHost(t *testing.T) {
	for _, bad := range []string{"tenant:abc", "[", "bad host", "tenant%20a", "grafana.local:0", "a..b", ""} {
		p := &runtime.InitProgram{Requests: []runtime.InitRequest{{Method: "GET", URL: "http://web:80/", Headers: map[string]string{"Host": bad}, Attempts: 1}}}
		_, err := renderInitFiles(p)
		if err == nil || !strings.Contains(err.Error(), "Host") || strings.Contains(err.Error(), bad+"\"") {
			t.Fatalf("Host %q: want a refusal naming the field and not the value, got %v", bad, err)
		}
	}
	p := &runtime.InitProgram{Requests: []runtime.InitRequest{{Method: "GET", URL: "http://web:80/", Headers: map[string]string{"host": "tenant-a.example:8080"}, Attempts: 1}}}
	files, err := renderInitFiles(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Path == "/run/podaro/init/1.curl" && !strings.Contains(string(f.Content), `header = "host: tenant-a.example:8080"`) {
			t.Fatalf("a legal Host is rendered as written:\n%s", f.Content)
		}
	}
}

// A header name is one token: curl reads the first colon of a header
// line as the field's end, so `Bad:Name` would send a field `Bad` with
// the value `Name: value` — the render refuses it before curl sees it,
// as the validator does (render.go:400).
func TestInitRenderRefusesAnIllegalHeaderName(t *testing.T) {
	for _, bad := range []string{"Bad:Name", "X Team", "", "X\tTeam", "X(Team)", "Ünïcode"} {
		p := &runtime.InitProgram{Requests: []runtime.InitRequest{{Method: "GET", URL: "http://web:80/", Headers: map[string]string{bad: "value"}, Attempts: 1}}}
		_, err := renderInitFiles(p)
		if err == nil || !strings.Contains(err.Error(), "field name") {
			t.Fatalf("header %q: want a refusal naming the rule, got %v", bad, err)
		}
	}
	p := &runtime.InitProgram{Requests: []runtime.InitRequest{{Method: "GET", URL: "http://web:80/", Headers: map[string]string{"X-Team": "blue"}, Attempts: 1}}}
	files, err := renderInitFiles(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Path == "/run/podaro/init/1.curl" && !strings.Contains(string(f.Content), `header = "X-Team: blue"`) {
			t.Fatalf("a legal name is rendered as written:\n%s", f.Content)
		}
	}
}
