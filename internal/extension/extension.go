// SPDX-License-Identifier: AGPL-3.0-only

// Package extension runs Spec 0002 extensions — checkpoint adapters and
// seed generators as digest-pinned OCI containers — through the runtime's
// one-shot Run, with the contract's input on stdin, its verdict from
// stdout, the five walls in the run spec, and §6's error mapping.
package extension

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/secrets"
	"slices"
)

// Contract is the version negotiated in both directions (Spec 0002 §8).
const Contract = "podaro.dev/exec/v1"

// Caps of the resource wall an engine never exceeds (Spec 0002 §2).
const (
	MaxCPUMillis   = 2000
	MaxMemoryBytes = 1 << 30
	// MinMemoryBytes is the floor a declared memory limit must reach to be
	// one: 0 is no limit at all under podman --memory, and below 6 MiB (the
	// minimum Docker documents; Podman shares the runtimes) no container
	// starts usefully. A declared value under it falls to the default, like
	// an unparseable one.
	MinMemoryBytes = 6 << 20
)

// Input is Spec 0002 §3's stdin document.
type Input struct {
	Contract   string          `json:"contract"`
	Kind       string          `json:"kind"`
	RunID      string          `json:"run_id"`
	Timeout    string          `json:"timeout"`
	Instance   Instance        `json:"instance"`
	Secrets    SecretsInfo     `json:"secrets"`
	Checkpoint *CheckpointSpec `json:"checkpoint,omitempty"`
	Seed       *SeedSpec       `json:"seed,omitempty"`
}

// Instance is the lab as an extension sees it: endpoints from module
// metadata, never guessed ports.
type Instance struct {
	Name      string     `json:"name"`
	Mode      string     `json:"mode"`
	Endpoints []Endpoint `json:"endpoints"`
}

// Endpoint is one service port on the instance network.
type Endpoint struct {
	Service string `json:"service"`
	Purpose string `json:"purpose"`
	Scheme  string `json:"scheme"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
}

// Grants is the set a `secrets:` list names: sorted, and each name once.
// A grant is a grant — naming one twice grants it once — and one
// implementation of that is what keeps the objects the run creates, the
// list the contract carries on stdin, and the record evidence keeps from
// disagreeing.
func Grants(secrets []string) []string {
	out := append([]string(nil), secrets...)
	sort.Strings(out)
	return slices.Compact(out)
}

// SecretsInfo names the granted secrets and where they are mounted.
type SecretsInfo struct {
	Granted []string `json:"granted"`
	Mount   string   `json:"mount"`
}

// CheckpointSpec is the checkpoint half of the input; Expect passes
// through verbatim — the container is the judge.
type CheckpointSpec struct {
	ID     string            `json:"id"`
	Args   []string          `json:"args"`
	Env    map[string]string `json:"env,omitempty"`
	Expect any               `json:"expect"`
}

// SeedSpec is the seed half of the input.
type SeedSpec struct {
	Name      string         `json:"name"`
	Args      []string       `json:"args"`
	Count     int            `json:"count"`
	Params    map[string]any `json:"params,omitempty"`
	SeedValue string         `json:"seed_value"`
}

// Verdict is Spec 0002 §4's stdout document for both kinds.
type Verdict struct {
	Contract string          `json:"contract"`
	Status   string          `json:"status"`
	Observed any             `json:"observed,omitempty"`
	Sent     any             `json:"sent,omitempty"`
	Message  string          `json:"message,omitempty"`
	Evidence VerdictEvidence `json:"evidence,omitempty"`
}

// VerdictEvidence is the capture block a verdict may carry.
type VerdictEvidence struct {
	Capture map[string]any `json:"capture,omitempty"`
}

// Spec is what a checkpoint's or seed's exec params declare (spec 0001
// §3, spec 0003 §4): the pinned image, args, env, secret grants, limits.
type Spec struct {
	Image   string
	Args    []string
	Env     map[string]string
	Secrets []string
	Limits  map[string]string
}

// SpecKeys are the fields an exec spec carries (spec 0001 §3, Spec 0002
// §2): image, args, env, secrets, limits.
var SpecKeys = []string{"args", "env", "image", "limits", "secrets"}

// SpecFromParams reads an exec checkpoint's params. A key the spec does
// not carry — `arg`, `environment` — is an error, never skipped: the
// checkpoint schema leaves the params object open (frozen), and an
// extension pulled and run without its authored configuration could
// answer a verdict nobody asked for. A
// present field of the wrong shape is refused the same way.
func SpecFromParams(params map[string]any) (Spec, error) {
	s := Spec{}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !slices.Contains(SpecKeys, k) {
			return Spec{}, fmt.Errorf("params.%s is not a parameter the exec adapter reads (image, args, env, secrets, limits)", k)
		}
	}
	image, ok := params["image"].(string)
	if !ok || image == "" {
		return Spec{}, errors.New("params.image must name the digest-pinned image")
	}
	s.Image = image
	if raw, has := params["args"]; has {
		args, ok := raw.([]any)
		if !ok {
			return Spec{}, errors.New("params.args must be a list of strings")
		}
		for _, a := range args {
			str, ok := a.(string)
			if !ok {
				return Spec{}, errors.New("params.args must be a list of strings")
			}
			s.Args = append(s.Args, str)
		}
	}
	if raw, has := params["env"]; has {
		env, ok := raw.(map[string]any)
		if !ok {
			return Spec{}, errors.New("params.env must be a map of names to strings")
		}
		s.Env = map[string]string{}
		for k, v := range env {
			str, ok := v.(string)
			if !ok {
				return Spec{}, fmt.Errorf("params.env.%s must be a string", k)
			}
			s.Env[k] = str
		}
	}
	if raw, has := params["secrets"]; has {
		grants, ok := raw.([]any)
		if !ok {
			return Spec{}, errors.New("params.secrets must be a list of declared secret names")
		}
		for _, g := range grants {
			str, ok := g.(string)
			if !ok {
				return Spec{}, errors.New("params.secrets must be a list of declared secret names")
			}
			s.Secrets = append(s.Secrets, str)
		}
	}
	if raw, has := params["limits"]; has {
		limits, ok := raw.(map[string]any)
		if !ok {
			return Spec{}, errors.New("params.limits must be a map of cpu and memory")
		}
		s.Limits = map[string]string{}
		for k, v := range limits {
			str, ok := v.(string)
			if !ok {
				return Spec{}, fmt.Errorf("params.limits.%s must be a string", k)
			}
			s.Limits[k] = str
		}
	}
	return s, nil
}

// Report is what a run produced beside the verdict: timing and the
// redaction-filtered stderr excerpt evidence attaches on error.
type Report struct {
	Started  time.Time
	Finished time.Time
	ExitCode int
	Stderr   string
	Image    string
	Secrets  []string
}

// Runner runs extensions for one instance.
type Runner struct {
	Runtime  runtime.Runtime
	Instance string
	// Network is the instance's internal network (the network wall).
	Network string
	Labels  map[string]string
	// Secrets is the instance's secret store (granted values come from
	// its files); Redactor filters stderr and messages.
	Secrets  *secrets.Store
	Redactor *secrets.Redactor
	// EnvDir holds the per-run 0600 env files.
	EnvDir string
	// Logf receives one line per run; nil discards.
	Logf func(format string, args ...any)
}

func (r *Runner) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

// ErrPull wraps a pull failure (PDR-E501); ErrRoot a refused image
// (PDR-E505). Both are judged before anything runs.

// Prepare pulls the image and judges its user (Spec 0002 §2, §6: pulls
// at create/plan time; root-UID images refused before anything runs).
// It returns the resolved user for the run's secret mounts.
func (r *Runner) Prepare(ctx context.Context, image string) (runtime.ImageUser, *pdr.Error) {
	if err := r.Runtime.Pull(ctx, image); err != nil {
		e := pdr.New(pdr.CodeExecPull, "exec image %s could not be pulled", image)
		e.Cause = err.Error()
		e.Next = "check the image reference and digest, registry access, and podaro doctor; then re-run"
		return runtime.ImageUser{}, e
	}
	user, err := r.Runtime.ImageUser(ctx, image)
	if err != nil {
		e := pdr.New(pdr.CodeExecRoot, "exec image %s refused: its user cannot be inspected", image)
		e.Cause = err.Error()
		e.Next = "podaro doctor · podman image inspect " + image
		return runtime.ImageUser{}, e
	}
	if user.Root() {
		e := pdr.New(pdr.CodeExecRoot, "exec image %s refused: it would run as root", image)
		e.Cause = "the image declares no USER, or USER 0/root (Spec 0002 §2: extensions run non-root)"
		e.Next = "add USER <non-root uid> to the adapter image's Containerfile and re-pin its digest"
		return user, e
	}
	if !user.Resolved {
		e := pdr.New(pdr.CodeExecRoot, "exec image %s refused: USER %q cannot be resolved to a uid", image, user.Raw)
		e.Cause = "the image's /etc/passwd does not name that user; the engine refuses rather than guess (Spec 0002 §2)"
		e.Next = "use a numeric USER in the adapter image's Containerfile and re-pin its digest"
		return user, e
	}
	return user, nil
}

// Run executes one extension: the input on stdin, the verdict from
// stdout; the returned *pdr.Error carries §6's code when the run did not
// produce a verdict. Report is always returned once the container was
// attempted.
func (r *Runner) Run(ctx context.Context, spec Spec, user runtime.ImageUser, input Input, timeout time.Duration) (*Verdict, *Report, *pdr.Error) {
	input.Contract = Contract
	input.Timeout = timeout.String()
	input.Secrets.Mount = runtime.SecretsMount
	// A grant is a grant: naming one twice grants it once. The runtime
	// derives a secret object's name from the secret and the run's id, so
	// a repeated grant would ask for the same object twice and the second
	// create is a name already in use — the run refused before the
	// extension ever starts. The list the
	// contract carries on stdin is the same set, for the same reason: a
	// grant listed twice is not two grants.
	granted := Grants(spec.Secrets)
	input.Secrets.Granted = granted
	if input.Secrets.Granted == nil {
		input.Secrets.Granted = []string{}
	}
	if input.Instance.Endpoints == nil {
		input.Instance.Endpoints = []Endpoint{}
	}
	stdin, err := json.Marshal(input)
	if err != nil {
		return nil, nil, wrapRuntime("encode the contract input", err)
	}
	var b [6]byte
	if _, err := randRead(b[:]); err != nil {
		return nil, nil, wrapRuntime("name the run", err)
	}
	name := fmt.Sprintf("pdr-%s-run-%s", r.Instance, hex.EncodeToString(b[:]))
	labels := map[string]string{}
	for k, v := range r.Labels {
		labels[k] = v
	}
	labels[runtime.LabelInstance] = r.Instance
	labels[runtime.LabelManaged] = "true"
	labels[runtime.LabelRun] = name
	rs := runtime.RunSpec{
		Name: name, Image: spec.Image, Network: r.Network, Labels: labels,
		Command: spec.Args, UID: user.UID, GID: user.GID, Stdin: stdin, Timeout: timeout,
		MaxStderr: runtime.DefaultMaxStderr,
	}
	report := &Report{Image: spec.Image, Secrets: granted}
	if len(spec.Env) > 0 {
		if r.EnvDir == "" {
			return nil, nil, wrapRuntime("render the extension env", errors.New("no env directory"))
		}
		if err := os.MkdirAll(r.EnvDir, 0o700); err != nil {
			return nil, nil, wrapRuntime("render the extension env", err)
		}
		keys := make([]string, 0, len(spec.Env))
		for k := range spec.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var buf bytes.Buffer
		for _, k := range keys {
			if strings.ContainsAny(k, "=\n\r ") || strings.ContainsAny(spec.Env[k], "\n\r") {
				return nil, nil, wrapRuntime("render the extension env", fmt.Errorf("env %s: not expressible in an env file", k))
			}
			fmt.Fprintf(&buf, "%s=%s\n", k, spec.Env[k])
		}
		rs.EnvFile = filepath.Join(r.EnvDir, name+".env")
		if err := os.WriteFile(rs.EnvFile, buf.Bytes(), 0o600); err != nil {
			return nil, nil, wrapRuntime("render the extension env", err)
		}
		defer os.Remove(rs.EnvFile)
	}
	for _, g := range granted {
		if r.Secrets == nil {
			return nil, nil, wrapRuntime("grant secrets", errors.New("no secret store"))
		}
		if _, err := r.Secrets.Value(g); err != nil {
			return nil, nil, wrapRuntime("grant secret "+g, err)
		}
		rs.Secrets = append(rs.Secrets, runtime.SecretFile{Name: g, Source: r.Secrets.Path(g)})
	}
	cpu, mem := Limits(spec.Limits)
	rs.CPU, rs.Memory = cpu, mem
	r.logf("run %s: %s %s (timeout %s, secrets %s)", name, spec.Image, strings.Join(spec.Args, " "), timeout, strings.Join(granted, ","))
	res, err := r.Runtime.Run(ctx, rs)
	if err != nil {
		return nil, report, wrapRuntime("run "+spec.Image, err)
	}
	report.Started, report.Finished, report.ExitCode = res.Started, res.Finished, res.ExitCode
	// Redaction runs before any cut — the excerpts, the message's display
	// limit — and a stream the cap cut first loses the trailing fragment
	// of a value it may hold: a secret cut in two leaves a fragment the
	// filter no longer recognises.
	stderr := res.Stderr
	if res.StderrTruncated {
		stderr = r.Redactor.TrimPartial(stderr)
	}
	report.Stderr = r.Redactor.Redact(string(bytes.TrimSpace(stderr)))
	if res.TimedOut {
		e := pdr.New(pdr.CodeExecTimeout, "exec container exceeded its timeout of %s", timeout)
		e.Cause = fmt.Sprintf("%s ran %s against a budget of %s", spec.Image, res.Finished.Sub(res.Started).Round(time.Millisecond), timeout)
		e.Next = "raise the timeout if the judgment legitimately takes longer; otherwise fix the adapter's wait loop"
		return nil, report, e
	}
	if res.ExitCode != 0 {
		e := pdr.New(pdr.CodeExecExit, "exec container exited %d", res.ExitCode)
		e.Cause = excerpt(report.Stderr, 500)
		if e.Cause == "" {
			e.Cause = "no stderr"
		}
		e.Next = "read the stderr excerpt in the evidence entry; fix the adapter image; re-run the checkpoint"
		return nil, report, e
	}
	if res.StdoutTruncated {
		// A cut stdout is no verdict: whatever followed the cap — chatter,
		// a second value — is unknown, and the contract is the verdict
		// JSON and nothing else (Spec 0002 §2).
		e := pdr.New(pdr.CodeExecOutput, "exec container stdout exceeded its %d-byte cap", runtime.DefaultMaxStdout)
		e.Cause = "the stream was cut at the cap, so the output cannot be read as one verdict and nothing else"
		e.Next = "print only the verdict JSON on stdout (status pass|fail for checkpoints, ok for seeds); move diagnostics to stderr"
		return nil, report, e
	}
	// The whole stdout is filtered before it is parsed, so the first bytes
	// an error quotes and the message the verdict carries are redacted
	// before either is cut (round 33).
	verdict, perr := ParseVerdict(r.Redactor.RedactBytes(res.Stdout), input.Kind)
	if perr != nil {
		return nil, report, perr
	}
	// The decoded message is filtered again before the cut: JSON escaping
	// (\uXXXX) keeps a secret off the wire as a literal, so the pre-parse
	// filter cannot see it, and the parsed string carries it whole.
	verdict.Message = cutMessage(r.Redactor.Redact(verdict.Message))
	return verdict, report, nil
}

// MaxMessage is the display length of a verdict message in bytes. The
// runner cuts a longer message after redaction, never before: a cut
// through a secret would leave a fragment the filter cannot see.
const MaxMessage = 500

// cutMessage keeps the first MaxMessage bytes of s without splitting a rune.
func cutMessage(s string) string {
	if len(s) <= MaxMessage {
		return s
	}
	cut := MaxMessage
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// ParseVerdict reads a contract verdict: one JSON value, the contract
// field, a status the kind allows. The message is kept whole; the runner
// cuts it to MaxMessage after redaction (round 33).
func ParseVerdict(stdout []byte, kind string) (*Verdict, *pdr.Error) {
	bad := func(cause string) *pdr.Error {
		e := pdr.New(pdr.CodeExecOutput, "exec container output is not contract JSON")
		e.Cause = cause
		e.Next = "print only the verdict JSON on stdout (status pass|fail for checkpoints, ok for seeds); move diagnostics to stderr"
		return e
	}
	trimmed := bytes.TrimSpace(stdout)
	if len(trimmed) == 0 {
		return nil, bad("stdout is empty")
	}
	var v Verdict
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	// Numbers stay exact: an integer beyond the 53 bits a double keeps —
	// in observed, sent or evidence.capture — is recorded as the adapter
	// wrote it, never rounded.
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, bad(decodeFault(err) + unquoted)
	}
	// Exactly one JSON value: a second value, or a stray delimiter after
	// the verdict, is not "the verdict JSON and nothing else" (Spec 0002
	// §4). More() only asks whether an enclosing array or object goes on,
	// so a second decode must reach EOF.
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, bad(fmt.Sprintf("more than one JSON value on stdout, or stray bytes after the verdict, after byte %d", dec.InputOffset()) + unquoted)
	}
	if v.Contract != Contract {
		return nil, bad(fmt.Sprintf("contract %q is not %s", v.Contract, Contract))
	}
	switch kind {
	case "seed":
		if v.Status != "ok" {
			return nil, bad(fmt.Sprintf("seed status %q is not ok", v.Status))
		}
	default:
		if v.Status != "pass" && v.Status != "fail" {
			return nil, bad(fmt.Sprintf("checkpoint status %q is not pass or fail", v.Status))
		}
	}
	return &v, nil
}

// unquoted closes an output error's cause: a stdout that is not the
// contract is never quoted in a result — not even its first bytes. An
// output that failed to parse may hold anything, a secret written as JSON
// \uXXXX escapes included, which the byte-level filter that ran before the
// parse cannot see and which no parse can decode for the filter.
// The redaction-filtered stderr excerpt in the
// evidence entry is the diagnostic channel (Spec 0002 §7).
const unquoted = " — stdout is never quoted in a result; the stderr excerpt in the evidence entry is the diagnostic channel"

// decodeFault names a decode error's kind and position without a byte of
// the input: the offset of a syntax fault, the field a value of the wrong
// type landed in (never the value), an input that ends inside the value.
func decodeFault(err error) string {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Sprintf("malformed JSON at byte %d", syn.Offset)
	case errors.As(err, &typ):
		field := typ.Field
		if field == "" {
			field = "the verdict"
		}
		return fmt.Sprintf("%s holds a JSON value of another type than the contract's %s", field, typ.Type)
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return "stdout ends inside the JSON value"
	}
	return "stdout is not one JSON value"
}

// Limits caps a declared limits block to the engine's ceiling (Spec 0002
// §2: never above 2 CPU / 1 GiB) and falls to the defaults when unset.
func Limits(limits map[string]string) (cpu, memory string) {
	cpu, memory = "500m", "256MiB"
	if v := limits["cpu"]; v != "" {
		if m, ok := cpuMillis(v); ok {
			if m > MaxCPUMillis {
				m = MaxCPUMillis
			}
			if m < 1 {
				m = 1
			}
			cpu = strconv.Itoa(m) + "m"
		}
	}
	if v := limits["memory"]; v != "" {
		// Below the floor — 0 first of all — a declared value is not a limit
		// Podman would enforce and falls to the default, as the CPU path
		// floors at 1m.
		if b, ok := memoryBytes(v); ok && b >= MinMemoryBytes {
			if b > MaxMemoryBytes {
				b = MaxMemoryBytes
			}
			memory = strconv.FormatInt((b+(1<<20)-1)>>20, 10) + "MiB"
		}
	}
	return cpu, memory
}

func cpuMillis(v string) (int, bool) {
	v = strings.TrimSpace(v)
	if strings.HasSuffix(v, "m") {
		n, err := strconv.Atoi(strings.TrimSuffix(v, "m"))
		return n, err == nil && n >= 0
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	// Clamped to the ceiling before the conversion: a float past the int
	// range converts to nothing usable.
	if f*1000 > float64(MaxCPUMillis) {
		return MaxCPUMillis, true
	}
	return int(f * 1000), true
}

func memoryBytes(v string) (int64, bool) {
	v = strings.TrimSpace(v)
	for suffix, mult := range map[string]int64{"GiB": 1 << 30, "MiB": 1 << 20, "KiB": 1 << 10, "g": 1 << 30, "m": 1 << 20, "k": 1 << 10} {
		if strings.HasSuffix(v, suffix) {
			n, err := strconv.ParseInt(strings.TrimSuffix(v, suffix), 10, 64)
			if err != nil || n < 0 {
				return 0, false
			}
			// Clamped to the ceiling before the unit multiplies: a value
			// large enough to overflow would otherwise read as 0, which
			// podman --memory takes as no limit at all.
			if n > MaxMemoryBytes/mult {
				return MaxMemoryBytes, true
			}
			return n * mult, true
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil && n >= 0
}

func excerpt(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func wrapRuntime(op string, err error) *pdr.Error {
	var pe *pdr.Error
	if errors.As(err, &pe) {
		return pe
	}
	e := pdr.New(pdr.CodeRuntimeFailed, "%s failed", op)
	e.Cause = err.Error()
	e.Next = "podaro doctor · then re-run"
	return e
}

var randRead = func(b []byte) (int, error) { return cryptoRandRead(b) }
