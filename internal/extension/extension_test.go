// SPDX-License-Identifier: AGPL-3.0-only

package extension

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/secrets"
)

const image = "docker.io/podaro/exec-conformance@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

func newRunner(t *testing.T) (*Runner, *runtime.Fake) {
	t.Helper()
	t.Setenv(runtime.EnvFakeReadyDelay, "0s")
	dir := t.TempDir()
	f, err := runtime.NewFake(filepath.Join(dir, "world.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	ctx := context.Background()
	labels := map[string]string{runtime.LabelInstance: "lab", runtime.LabelManaged: "true"}
	_ = f.EnsureNetwork(ctx, "pdr-lab", labels, false)
	_ = f.EnsureNetwork(ctx, "pdr-lab-int", labels, true)
	store := secrets.NewStore(filepath.Join(dir, "secrets"))
	if _, err := store.Ensure("tok", secrets.KindToken); err != nil {
		t.Fatal(err)
	}
	values, _ := store.Values()
	r := &Runner{Runtime: f, Instance: "lab", Network: "pdr-lab-int", Labels: labels, Secrets: store, Redactor: secrets.NewRedactor(values), EnvDir: filepath.Join(dir, "env")}
	return r, f
}

func checkpointInput(expect any) Input {
	return Input{Kind: "checkpoint", RunID: "run_1", Instance: Instance{Name: "lab", Mode: "delivery", Endpoints: []Endpoint{{Service: "web", Purpose: "ui", Scheme: "http", Host: "web", Port: 80}}}, Checkpoint: &CheckpointSpec{ID: "c", Expect: expect}}
}

// Spec 0002 §6, end to end on the fake: pass and fail are verdicts; a
// non-zero exit is E502 with the stderr excerpt; a timeout E503; garbage
// on stdout E504; a root image E505 before anything runs; a pull failure
// E501.
func TestConformanceMapping(t *testing.T) {
	r, _ := newRunner(t)
	ctx := context.Background()
	user, perr := r.Prepare(ctx, image)
	if perr != nil || user.UID != 1000 {
		t.Fatalf("prepare: %+v %v", user, perr)
	}
	spec := Spec{Image: image, Args: []string{"pass"}}
	v, rep, perr := r.Run(ctx, spec, user, checkpointInput(map[string]any{"lag": 0}), 2*time.Second)
	if perr != nil || v.Status != "pass" || rep == nil || rep.ExitCode != 0 {
		t.Fatalf("pass: %+v %+v %v", v, rep, perr)
	}
	if obs, _ := json.Marshal(v.Observed); string(obs) != `{"lag":0}` {
		t.Fatalf("observed passes through: %s", obs)
	}
	// The captured count is judged by its JSON form, not its Go type: the
	// verdict decoder keeps numbers exact (round 32), so it is a json.Number.
	if n, _ := json.Marshal(v.Evidence.Capture["endpoints"]); v.Evidence.Capture["run_id"] != "run_1" || string(n) != "1" {
		t.Fatalf("capture: %v", v.Evidence.Capture)
	}
	spec.Args = []string{"fail"}
	v, rep, perr = r.Run(ctx, spec, user, checkpointInput(map[string]any{"lag": 0}), 2*time.Second)
	if perr != nil || v.Status != "fail" || rep.Stderr != "diagnostic chatter on stderr" {
		t.Fatalf("fail: %+v %+v %v", v, rep, perr)
	}
	spec.Args = []string{"crash"}
	v, rep, perr = r.Run(ctx, spec, user, checkpointInput(nil), 2*time.Second)
	if v != nil || perr == nil || perr.Code != pdr.CodeExecExit || !strings.Contains(perr.Cause, "crashing on purpose") || rep.ExitCode != 2 {
		t.Fatalf("crash: %+v %+v %v", v, rep, perr)
	}
	spec.Args = []string{"garbage"}
	v, _, perr = r.Run(ctx, spec, user, checkpointInput(nil), 2*time.Second)
	// The cause names the fault, never the output (round 50): what the
	// fixture printed is read in the evidence entry's stderr, not here.
	if v != nil || perr == nil || perr.Code != pdr.CodeExecOutput || strings.Contains(perr.Cause, "this is not contract json") || !strings.Contains(perr.Cause, "malformed JSON at byte") {
		t.Fatalf("garbage: %+v %v", v, perr)
	}
	spec.Args = []string{"sleep"}
	v, rep, perr = r.Run(ctx, spec, user, checkpointInput(nil), 40*time.Millisecond)
	if v != nil || perr == nil || perr.Code != pdr.CodeExecTimeout || !strings.Contains(perr.Cause, "budget of 40ms") {
		t.Fatalf("sleep: %+v %+v %v", v, rep, perr)
	}
	// A granted secret reaches the run as a file; its value never leaves.
	spec.Args = []string{"secret"}
	spec.Secrets = []string{"tok"}
	v, rep, perr = r.Run(ctx, spec, user, checkpointInput(nil), 2*time.Second)
	if perr != nil || v.Status != "pass" {
		t.Fatalf("secret: %+v %v", v, perr)
	}
	if obs, _ := json.Marshal(v.Observed); string(obs) != `{"secret_bytes":64}` || strings.Join(rep.Secrets, ",") != "tok" {
		t.Fatalf("secret observed: %s %v", obs, rep.Secrets)
	}
	spec.Secrets = []string{"nope"}
	if _, _, perr = r.Run(ctx, spec, user, checkpointInput(nil), time.Second); perr == nil || !strings.Contains(perr.Message, "grant secret nope") {
		t.Fatalf("ungranted secret: %v", perr)
	}
	// A seed run reports what it sent.
	seedIn := Input{Kind: "seed", RunID: "run_2", Instance: Instance{Name: "lab"}, Seed: &SeedSpec{Name: "orders", Count: 42, SeedValue: "9f2c66d1a4e07b53"}}
	v, _, perr = r.Run(ctx, Spec{Image: image, Args: []string{"pass"}}, user, seedIn, time.Second)
	if perr != nil || v.Status != "ok" || !strings.Contains(v.Message, "9f2c66d1a4e07b53") {
		t.Fatalf("seed: %+v %v", v, perr)
	}
	if sent, _ := json.Marshal(v.Sent); string(sent) != `{"events":42}` {
		t.Fatalf("sent: %s", sent)
	}
	// Refusals before anything runs.
	root := "docker.io/podaro/exec-conformance-root@sha256:" + strings.Repeat("b", 64)
	if _, perr := r.Prepare(ctx, root); perr == nil || perr.Code != pdr.CodeExecRoot {
		t.Fatalf("root image: %v", perr)
	}
	unresolved := "docker.io/podaro/exec-conformance-unresolved@sha256:" + strings.Repeat("c", 64)
	if _, perr := r.Prepare(ctx, unresolved); perr == nil || perr.Code != pdr.CodeExecRoot || !strings.Contains(perr.Cause, "cannot") && !strings.Contains(perr.Message, "cannot be resolved") {
		t.Fatalf("unresolved user: %v", perr)
	}
	if _, perr := r.Prepare(ctx, "docker.io/podaro/tagged:latest"); perr == nil || perr.Code != pdr.CodeExecPull {
		t.Fatalf("pull refusal: %v", perr)
	}
}

// stubRuntime answers Run with a canned result (the fake cannot echo a
// secret; this proves the redaction of what a real adapter might print).
type stubRuntime struct {
	*runtime.Fake
	res  *runtime.RunResult
	spec runtime.RunSpec
}

func (s *stubRuntime) Run(ctx context.Context, spec runtime.RunSpec) (*runtime.RunResult, error) {
	s.spec = spec
	return s.res, nil
}

func TestRunRedactsAndShapesTheRun(t *testing.T) {
	r, f := newRunner(t)
	value, _ := r.Secrets.Value("tok")
	stub := &stubRuntime{Fake: f, res: &runtime.RunResult{ExitCode: 0, Stdout: []byte(`{"contract":"podaro.dev/exec/v1","status":"pass","message":"token ` + value + ` accepted"}`), Stderr: []byte("saw " + value)}}
	r.Runtime = stub
	ctx := context.Background()
	_ = f.Pull(ctx, image)
	user := runtime.ImageUser{Raw: "1000", UID: 1000, GID: 1000, Resolved: true}
	spec := Spec{Image: image, Args: []string{"--topic", "orders"}, Env: map[string]string{"TOPIC": "orders"}, Secrets: []string{"tok"}, Limits: map[string]string{"cpu": "4", "memory": "8GiB"}}
	v, rep, perr := r.Run(ctx, spec, user, checkpointInput(map[string]any{"lag": 0}), 3*time.Second)
	if perr != nil {
		t.Fatal(perr)
	}
	if v.Message != "token [redacted:tok] accepted" || rep.Stderr != "saw [redacted:tok]" {
		t.Fatalf("redaction: %q %q", v.Message, rep.Stderr)
	}
	got := stub.spec
	if got.Network != "pdr-lab-int" || got.Image != image || strings.Join(got.Command, " ") != "--topic orders" || got.UID != 1000 || got.GID != 1000 || got.Timeout != 3*time.Second {
		t.Fatalf("run spec: %+v", got)
	}
	if got.CPU != "2000m" || got.Memory != "1024MiB" {
		t.Fatalf("limits capped at 2 CPU / 1 GiB: %s %s", got.CPU, got.Memory)
	}
	if len(got.Secrets) != 1 || got.Secrets[0].Name != "tok" || got.Secrets[0].Source != r.Secrets.Path("tok") {
		t.Fatalf("secret mounts: %+v", got.Secrets)
	}
	if got.Labels[runtime.LabelInstance] != "lab" || got.Labels[runtime.LabelRun] != got.Name || !strings.HasPrefix(got.Name, "pdr-lab-run-") {
		t.Fatalf("labels/name: %+v", got)
	}
	if got.EnvFile == "" {
		t.Fatal("env must travel as a file")
	}
	if _, err := os.Stat(got.EnvFile); !os.IsNotExist(err) {
		t.Fatal("the run's env file must be removed after the run")
	}
	var in Input
	if err := json.Unmarshal(got.Stdin, &in); err != nil || in.Contract != Contract || in.Kind != "checkpoint" || in.Timeout != "3s" || in.Secrets.Mount != runtime.SecretsMount || strings.Join(in.Secrets.Granted, ",") != "tok" || in.Checkpoint.ID != "c" {
		t.Fatalf("stdin: %s %v", got.Stdin, err)
	}
	if strings.Contains(string(got.Stdin), value) {
		t.Fatal("a secret value on stdin (Spec 0002 §2)")
	}
	// A runtime that cannot run the container is a runtime error, not a verdict.
	stub.res = nil
	r.Runtime = &failingRuntime{Fake: f}
	if _, _, perr := r.Run(ctx, Spec{Image: image}, user, checkpointInput(nil), time.Second); perr == nil || perr.Code != pdr.CodeRuntimeFailed {
		t.Fatalf("runtime failure: %v", perr)
	}
}

type failingRuntime struct{ *runtime.Fake }

func (f *failingRuntime) Run(ctx context.Context, spec runtime.RunSpec) (*runtime.RunResult, error) {
	return nil, context.DeadlineExceeded
}

func TestParseVerdictAndLimits(t *testing.T) {
	for _, tc := range []struct {
		out  string
		kind string
		code string
	}{
		{``, "checkpoint", pdr.CodeExecOutput},
		{`not json`, "checkpoint", pdr.CodeExecOutput},
		{`{"contract":"podaro.dev/exec/v2","status":"pass"}`, "checkpoint", pdr.CodeExecOutput},
		{`{"contract":"podaro.dev/exec/v1","status":"maybe"}`, "checkpoint", pdr.CodeExecOutput},
		{`{"contract":"podaro.dev/exec/v1","status":"pass"} {"again":true}`, "checkpoint", pdr.CodeExecOutput},
		{`{"contract":"podaro.dev/exec/v1","status":"pass"}`, "seed", pdr.CodeExecOutput},
		{`{"contract":"podaro.dev/exec/v1","status":"ok","sent":{"events":5}}`, "seed", ""},
		{`{"contract":"podaro.dev/exec/v1","status":"fail","observed":{"lag":3},"unknown":1}`, "checkpoint", ""},
	} {
		v, perr := ParseVerdict([]byte(tc.out), tc.kind)
		if tc.code == "" {
			if perr != nil || v == nil {
				t.Errorf("%s: %v", tc.out, perr)
			}
			continue
		}
		if perr == nil || perr.Code != tc.code {
			t.Errorf("%s: %+v %v", tc.out, v, perr)
		}
	}
	long, _ := ParseVerdict([]byte(`{"contract":"podaro.dev/exec/v1","status":"pass","message":"`+strings.Repeat("m", 600)+`"}`), "checkpoint")
	if len(long.Message) != 600 {
		t.Fatalf("ParseVerdict keeps the whole message — the runner cuts it after redaction (round 33): %d", len(long.Message))
	}
	if cut := cutMessage(strings.Repeat("m", 600)); len(cut) != MaxMessage {
		t.Fatalf("message cut to %d: %d", MaxMessage, len(cut))
	}
	if cut := cutMessage(strings.Repeat("m", 499) + "é"); cut != strings.Repeat("m", 499) {
		t.Fatalf("the cut never splits a rune: %q", cut[490:])
	}
	for _, tc := range []struct {
		limits   map[string]string
		cpu, mem string
	}{
		{nil, "500m", "256MiB"},
		{map[string]string{"cpu": "1", "memory": "512MiB"}, "1000m", "512MiB"},
		{map[string]string{"cpu": "4", "memory": "8GiB"}, "2000m", "1024MiB"},
		{map[string]string{"cpu": "250m", "memory": "1g"}, "250m", "1024MiB"},
		{map[string]string{"cpu": "x", "memory": "y"}, "500m", "256MiB"},
	} {
		if cpu, mem := Limits(tc.limits); cpu != tc.cpu || mem != tc.mem {
			t.Errorf("limits %v = %s %s, want %s %s", tc.limits, cpu, mem, tc.cpu, tc.mem)
		}
	}
	spec, err := SpecFromParams(map[string]any{"image": image, "args": []any{"--topic", "orders"}, "env": map[string]any{"TOPIC": "orders"}, "secrets": []any{"tok"}, "limits": map[string]any{"cpu": "1"}})
	if err != nil || spec.Image != image || strings.Join(spec.Args, " ") != "--topic orders" || spec.Env["TOPIC"] != "orders" || strings.Join(spec.Secrets, ",") != "tok" || spec.Limits["cpu"] != "1" {
		t.Fatalf("spec: %+v %v", spec, err)
	}
}

// An exec spec read from a checkpoint's open params refuses what it would
// otherwise skip: a key the spec does not carry (`arg`, `environment`),
// or a field of the wrong shape, is an error before anything is pulled or
// run — the schema leaves the params object open, so the reader carries
// the rule.
func TestSpecFromParamsRefusesWhatItWouldSkip(t *testing.T) {
	for _, tc := range []struct {
		params map[string]any
		want   string
	}{
		{map[string]any{"image": image, "arg": []any{"pass"}}, "params.arg is not a parameter the exec adapter reads"},
		{map[string]any{"image": image, "environment": map[string]any{"A": "b"}}, "params.environment is not a parameter"},
		{map[string]any{"image": image, "args": "pass"}, "params.args must be a list of strings"},
		{map[string]any{"image": image, "args": []any{1}}, "params.args must be a list of strings"},
		{map[string]any{"image": image, "env": []any{"A=b"}}, "params.env must be a map"},
		{map[string]any{"image": image, "env": map[string]any{"A": 1}}, "params.env.A must be a string"},
		{map[string]any{"image": image, "secrets": "tok"}, "params.secrets must be a list"},
		{map[string]any{"image": image, "limits": map[string]any{"cpu": 1}}, "params.limits.cpu must be a string"},
		{map[string]any{"args": []any{"pass"}}, "params.image must name the digest-pinned image"},
		{map[string]any{"image": 7}, "params.image must name the digest-pinned image"},
	} {
		_, err := SpecFromParams(tc.params)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: err %v, want %q", tc.params, err, tc.want)
		}
	}
	// The order of refusal is the sorted key order, so a report names the
	// same key on every engine.
	_, err := SpecFromParams(map[string]any{"image": image, "zeta": 1, "alpha": 2})
	if err == nil || !strings.Contains(err.Error(), "params.alpha ") {
		t.Fatalf("keys are judged in name order: %v", err)
	}
}

// A declared limit is clamped to the ceiling before its unit multiplies or
// its float converts: a value large enough to overflow int64 would
// otherwise render as 0MiB, which podman --memory takes as no limit at
// all.
func TestLimitsClampBeforeTheUnitMultiplies(t *testing.T) {
	for _, tc := range []struct {
		limits   map[string]string
		cpu, mem string
	}{
		{map[string]string{"cpu": "1e300", "memory": "17179869184GiB"}, "2000m", "1024MiB"},
		{map[string]string{"cpu": "3", "memory": "9223372036854775807k"}, "2000m", "1024MiB"},
		{map[string]string{"cpu": "Inf", "memory": "9223372036854775807"}, "500m", "1024MiB"},
		{map[string]string{"cpu": "NaN", "memory": "-1"}, "500m", "256MiB"},
		{map[string]string{"cpu": "99999999999999999999m", "memory": "8796093022208MiB"}, "500m", "1024MiB"},
	} {
		if cpu, mem := Limits(tc.limits); cpu != tc.cpu || mem != tc.mem {
			t.Errorf("limits %v = %s %s, want %s %s", tc.limits, cpu, mem, tc.cpu, tc.mem)
		}
	}
}

// A declared memory limit below the floor — 0 first of all — is not a
// limit Podman would enforce (--memory 0m means no limit) and falls to
// the default, as the CPU path floors at 1m.
func TestLimitsNeverRenderNoLimit(t *testing.T) {
	for _, tc := range []struct {
		limits   map[string]string
		cpu, mem string
	}{
		{map[string]string{"memory": "0MiB"}, "500m", "256MiB"},
		{map[string]string{"memory": "0"}, "500m", "256MiB"},
		{map[string]string{"memory": "5MiB"}, "500m", "256MiB"},
		{map[string]string{"memory": "1k"}, "500m", "256MiB"},
		{map[string]string{"memory": "6MiB"}, "500m", "6MiB"},
		{map[string]string{"cpu": "0", "memory": "0g"}, "1m", "256MiB"},
	} {
		if cpu, mem := Limits(tc.limits); cpu != tc.cpu || mem != tc.mem {
			t.Errorf("limits %v = %s %s, want %s %s", tc.limits, cpu, mem, tc.cpu, tc.mem)
		}
	}
}

// A stdout the cap cut is no verdict: what followed the cap is unknown, so
// the valid prefix never passes for the whole (podman.go:116).
func TestTruncatedVerdictStreamIsRejected(t *testing.T) {
	r, f := newRunner(t)
	verdict := []byte(`{"contract":"podaro.dev/exec/v1","status":"pass"}`)
	stub := &stubRuntime{Fake: f, res: &runtime.RunResult{ExitCode: 0, Stdout: verdict, StdoutTruncated: true}}
	r.Runtime = stub
	ctx := context.Background()
	_ = f.Pull(ctx, image)
	user := runtime.ImageUser{Raw: "1000", UID: 1000, GID: 1000, Resolved: true}
	_, _, perr := r.Run(ctx, Spec{Image: image}, user, checkpointInput(nil), time.Second)
	if perr == nil || perr.Code != pdr.CodeExecOutput || !strings.Contains(perr.Message, "cap") {
		t.Fatalf("a cut stdout must be PDR-E504, got %v", perr)
	}
	// The same bytes uncut are the verdict they read as.
	stub.res = &runtime.RunResult{ExitCode: 0, Stdout: verdict}
	if v, _, perr := r.Run(ctx, Spec{Image: image}, user, checkpointInput(nil), time.Second); perr != nil || v.Status != "pass" {
		t.Fatalf("uncut verdict: %v %v", v, perr)
	}
}

// The verdict is exactly one JSON value — a stray delimiter after it is no
// verdict — and its numbers are recorded exactly (extension.go:350 and :354).
func TestParseVerdictIsOneExactJSONValue(t *testing.T) {
	for _, out := range []string{
		`{"contract":"podaro.dev/exec/v1","status":"pass"}]`,
		`{"contract":"podaro.dev/exec/v1","status":"pass"}}`,
		`{"contract":"podaro.dev/exec/v1","status":"pass"} x`,
		`{"contract":"podaro.dev/exec/v1","status":"pass"} {"contract":"podaro.dev/exec/v1","status":"fail"}`,
	} {
		if v, perr := ParseVerdict([]byte(out), "checkpoint"); perr == nil || perr.Code != pdr.CodeExecOutput {
			t.Errorf("%q must be PDR-E504, got %v %v", out, v, perr)
		}
	}
	v, perr := ParseVerdict([]byte(`{"contract":"podaro.dev/exec/v1","status":"pass","observed":{"n":9007199254740993},"sent":123456789012345678901234567890,"evidence":{"capture":{"big":[9007199254740993]}}}`+"\n\n"), "checkpoint")
	if perr != nil {
		t.Fatal(perr)
	}
	raw, _ := json.Marshal(map[string]any{"observed": v.Observed, "sent": v.Sent, "capture": v.Evidence.Capture})
	for _, want := range []string{`"n":9007199254740993`, `"sent":123456789012345678901234567890`, `"big":[9007199254740993]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("numbers must survive exactly: want %s in %s", want, raw)
		}
	}
}

// Redaction runs before any cut — the message's display limit, an error's
// quoted first bytes, and the tail of a stderr the cap cut: a secret cut
// in two would leave a fragment the filter cannot see (extension.go:381).
func TestRunRedactsBeforeAnyCut(t *testing.T) {
	r, f := newRunner(t)
	value, _ := r.Secrets.Value("tok")
	ctx := context.Background()
	_ = f.Pull(ctx, image)
	user := runtime.ImageUser{Raw: "1000", UID: 1000, GID: 1000, Resolved: true}
	spec := Spec{Image: image, Secrets: []string{"tok"}}
	leak := value[:len(value)-3] // what a cut three bytes short of the value's end leaves behind
	// 1. A message whose secret straddles the display limit.
	stub := &stubRuntime{Fake: f, res: &runtime.RunResult{ExitCode: 0, Stdout: []byte(`{"contract":"podaro.dev/exec/v1","status":"pass","message":"` + strings.Repeat("m", MaxMessage-len(value)+3) + value + `"}`)}}
	r.Runtime = stub
	v, _, perr := r.Run(ctx, spec, user, checkpointInput(nil), time.Second)
	if perr != nil {
		t.Fatal(perr)
	}
	if !strings.Contains(v.Message, "[redacted:tok]") || strings.Contains(v.Message, leak) || len(v.Message) > MaxMessage {
		t.Fatalf("message: redact, then cut — marker %v, fragment leaked %v, length %d", strings.Contains(v.Message, "[redacted:tok]"), strings.Contains(v.Message, leak), len(v.Message))
	}
	// 2. An output error whose quoted first bytes would cut the secret.
	stub.res = &runtime.RunResult{ExitCode: 0, Stdout: []byte(strings.Repeat("x", 200-len(value)+3) + value + " is not json")}
	if _, _, perr = r.Run(ctx, spec, user, checkpointInput(nil), time.Second); perr == nil || perr.Code != pdr.CodeExecOutput || strings.Contains(perr.Cause, leak) || strings.Contains(perr.Cause, value[:8]) {
		leaked := perr != nil && (strings.Contains(perr.Cause, leak) || strings.Contains(perr.Cause, value[:8]))
		t.Fatalf("excerpt: redact, then cut — error %v, fragment leaked %v", perr != nil, leaked)
	}
	// 3. A stderr the cap cut, ending in the first bytes of the secret.
	stub.res = &runtime.RunResult{ExitCode: 0, Stdout: []byte(`{"contract":"podaro.dev/exec/v1","status":"pass"}`), Stderr: []byte("diag " + leak), StderrTruncated: true}
	if _, rep, perr := r.Run(ctx, spec, user, checkpointInput(nil), time.Second); perr != nil || strings.Contains(rep.Stderr, value[:8]) || !strings.HasPrefix(rep.Stderr, "diag") {
		t.Fatalf("a cut stderr loses the fragment — error %v, fragment leaked %v, kept prefix %v", perr, rep != nil && strings.Contains(rep.Stderr, value[:8]), rep != nil && strings.HasPrefix(rep.Stderr, "diag"))
	}
}

// JSON escaping bypasses the pre-parse filter — a secret written as \uXXXX
// sequences is no literal on the wire — so the decoded message is filtered
// again before the cut (extension.go:344).
func TestRunRedactsTheDecodedMessageBeforeTheCut(t *testing.T) {
	r, f := newRunner(t)
	value, _ := r.Secrets.Value("tok")
	var escaped strings.Builder
	for _, b := range []byte(value) {
		fmt.Fprintf(&escaped, `\u%04x`, b)
	}
	ctx := context.Background()
	_ = f.Pull(ctx, image)
	user := runtime.ImageUser{Raw: "1000", UID: 1000, GID: 1000, Resolved: true}
	stub := &stubRuntime{Fake: f, res: &runtime.RunResult{ExitCode: 0, Stdout: []byte(`{"contract":"podaro.dev/exec/v1","status":"pass","message":"` + strings.Repeat("m", MaxMessage-len(value)+3) + escaped.String() + `"}`)}}
	r.Runtime = stub
	v, _, perr := r.Run(ctx, Spec{Image: image, Secrets: []string{"tok"}}, user, checkpointInput(nil), time.Second)
	if perr != nil {
		t.Fatal(perr)
	}
	leak := value[:len(value)-3]
	if !strings.Contains(v.Message, "[redacted:tok]") || strings.Contains(v.Message, leak) || len(v.Message) > MaxMessage {
		t.Fatalf("decoded message: redact, then cut — marker %v, fragment leaked %v, length %d", strings.Contains(v.Message, "[redacted:tok]"), strings.Contains(v.Message, leak), len(v.Message))
	}
}

// An output error quotes no byte of stdout: an output that failed to parse
// may hold anything — a secret written as \uXXXX escapes, which the
// byte-level filter before the parse cannot see and which no parse can
// decode for it — so the E504 cause names the fault's kind and byte offset
// only, for the syntax fault and for the trailing data alike (extension.go:391).
func TestOutputErrorsQuoteNoStdout(t *testing.T) {
	r, f := newRunner(t)
	value, _ := r.Secrets.Value("tok")
	var escaped strings.Builder
	for _, b := range []byte(value) {
		fmt.Fprintf(&escaped, `\u%04x`, b)
	}
	ctx := context.Background()
	_ = f.Pull(ctx, image)
	user := runtime.ImageUser{Raw: "1000", UID: 1000, GID: 1000, Resolved: true}
	spec := Spec{Image: image, Secrets: []string{"tok"}}
	stub := &stubRuntime{Fake: f}
	r.Runtime = stub
	carries := func(cause string) bool {
		return strings.Contains(cause, value) || strings.Contains(cause, value[:4]) || strings.Contains(cause, `\u`) || strings.Contains(cause, escaped.String()[:12])
	}
	// 1. Malformed JSON (a stray comma): the escaped secret sits inside the
	// first 200 bytes.
	stub.res = &runtime.RunResult{ExitCode: 0, Stdout: []byte(`{"contract":"podaro.dev/exec/v1","status":"pass","message":"` + escaped.String() + `",}`)}
	_, _, perr := r.Run(ctx, spec, user, checkpointInput(nil), time.Second)
	if perr == nil || perr.Code != pdr.CodeExecOutput || carries(perr.Cause) || !strings.Contains(perr.Cause, "malformed JSON at byte") {
		t.Fatalf("malformed stdout: error %v, cause carries stdout bytes %v, names the fault's position %v", perr != nil, perr != nil && carries(perr.Cause), perr != nil && strings.Contains(perr.Cause, "malformed JSON at byte"))
	}
	// 1b. An output that ends inside the value, the escaped secret last.
	stub.res = &runtime.RunResult{ExitCode: 0, Stdout: []byte(`{"contract":"podaro.dev/exec/v1","status":"pass","message":"` + escaped.String())}
	_, _, perr = r.Run(ctx, spec, user, checkpointInput(nil), time.Second)
	if perr == nil || perr.Code != pdr.CodeExecOutput || carries(perr.Cause) || !strings.Contains(perr.Cause, "ends inside") {
		t.Fatalf("cut-short stdout: error %v, cause carries stdout bytes %v", perr != nil, perr != nil && carries(perr.Cause))
	}
	// 2. Trailing data after a valid verdict, carrying the escaped secret.
	stub.res = &runtime.RunResult{ExitCode: 0, Stdout: []byte(`{"contract":"podaro.dev/exec/v1","status":"pass"} {"message":"` + escaped.String() + `"}`)}
	_, _, perr = r.Run(ctx, spec, user, checkpointInput(nil), time.Second)
	if perr == nil || perr.Code != pdr.CodeExecOutput || carries(perr.Cause) || !strings.Contains(perr.Cause, "more than one JSON value") {
		t.Fatalf("trailing data: error %v, cause carries stdout bytes %v", perr != nil, perr != nil && carries(perr.Cause))
	}
}

// The decode fault is named by kind and position, never by content: a
// syntax fault by its byte offset, a value of the wrong type by the field
// it landed in, an input that ends early by that fact (round 50).
func TestParseVerdictNamesTheFaultWithoutTheInput(t *testing.T) {
	for _, tc := range []struct {
		out  string
		want string
	}{
		{`{"contract":"podaro.dev/exec/v1","status":"pass",}`, "malformed JSON at byte 50"},
		{`{"contract":5,"status":"pass"}`, "contract holds a JSON value of another type than the contract's string"},
		{`{"contract":"podaro.dev/exec/v1","status":"pa`, "stdout ends inside the JSON value"},
		{`{"contract":"podaro.dev/exec/v1","status":"pass"} tail-marker-0xdeadbeef`, "after byte 49"},
	} {
		_, perr := ParseVerdict([]byte(tc.out), "checkpoint")
		if perr == nil || perr.Code != pdr.CodeExecOutput {
			t.Fatalf("%d bytes of output: want PDR-E504, got %v", len(tc.out), perr)
		}
		if !strings.Contains(perr.Cause, tc.want) || strings.Contains(perr.Cause, "podaro.dev") || strings.Contains(perr.Cause, "tail-marker") || strings.Contains(perr.Cause, "pass") {
			t.Errorf("cause names the fault (%q) without the input: got %q", tc.want, perr.Cause)
		}
	}
}
