// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/seed"
	"github.com/jeremiahjrross/podaro/internal/state"
	"github.com/jeremiahjrross/podaro/internal/verify"
)

// failCreate is a runtime whose Create of one container fails the way
// podman does — with the command's arguments (the rendered command among
// them) and a stderr that echoes them — so what the engine persists about
// the failure can be inspected.
type failCreate struct {
	runtime.Runtime
	container string
	mu        sync.Mutex
	seen      []string
}

func (f *failCreate) Create(ctx context.Context, spec runtime.ContainerSpec) (string, error) {
	if spec.Name != f.container {
		return f.Runtime.Create(ctx, spec)
	}
	args := runtime.CreateArgs(spec)
	f.mu.Lock()
	f.seen = append([]string(nil), spec.Command...)
	f.mu.Unlock()
	return "", &runtime.CommandError{Args: args, Stderr: "Error: cannot create: invalid argument " + strings.Join(spec.Command, " ")}
}

// A runtime error's text can carry a rendered command — and with it a
// secret (engine.go:1829). Everything the job
// persists or logs about the failure passes the instance's redaction
// filter: the journal, the job record's envelope, the service row, the
// engine log; and podman's own error names the verb, never the values.
func TestRuntimeErrorsArePersistedRedacted(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var logMu sync.Mutex
	var logged strings.Builder
	h.eng.opts.Logf = func(format string, args ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		logged.WriteString(strings.TrimSpace(strings.ReplaceAll(format, "%", "%%")) + " ")
		for _, a := range args {
			logged.WriteString(strings.TrimSpace(strings.ReplaceAll(toString(a), "%", "%%")) + " ")
		}
		logged.WriteString("\n")
	}
	fc := &failCreate{Runtime: h.fake, container: "pdr-leaky-web"}
	h.eng.opts.Runtime = fc
	dir := t.TempDir()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: leaky, version: 1.0.0 }
secrets:
  tok: { kind: token }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    command: [ "serve", "--token", "${secret:tok}" ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
`
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "leaky"})
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(job.ID)
	if j.State != state.JobFailed || j.Error == nil || j.Error.Code != pdr.CodeRuntimeFailed {
		t.Fatalf("the create must fail on the runtime: %+v", j)
	}
	raw, err := os.ReadFile(filepath.Join(h.dir, "instances", "leaky", "secrets", "tok"))
	if err != nil || len(raw) != 64 {
		t.Fatalf("the token was generated before the container was created: %q %v", raw, err)
	}
	tok := string(raw)
	fc.mu.Lock()
	rendered := strings.Join(fc.seen, " ")
	fc.mu.Unlock()
	if !strings.Contains(rendered, tok) {
		t.Fatalf("the runtime received the rendered command (the leak's precondition): %q", rendered)
	}
	// The journal.
	if journal := journalOf(h, job.ID); strings.Contains(journal, tok) {
		t.Errorf("the token reached the job journal:\n%s", journal)
	} else if !strings.Contains(journal, "create web failed podman create: Error: cannot create: invalid argument serve --token [redacted:tok]") {
		t.Errorf("the journal names the verb and the filtered stderr:\n%s", journal)
	}
	// The job record and its envelope (what the API and CLI show).
	if enc, _ := json.Marshal(j); strings.Contains(string(enc), tok) {
		t.Errorf("the token reached the job record: %s", enc)
	}
	if !strings.Contains(j.Error.Cause, "[redacted:tok]") {
		t.Errorf("the envelope's cause is filtered, not dropped: %+v", j.Error)
	}
	// The service row.
	svcs, _ := h.store.ListServices("leaky")
	for _, s := range svcs {
		if strings.Contains(s.Error, tok) {
			t.Errorf("the token reached the service row: %q", s.Error)
		}
	}
	// The engine log.
	logMu.Lock()
	logText := logged.String()
	logMu.Unlock()
	if strings.Contains(logText, tok) {
		t.Errorf("the token reached the engine log:\n%s", logText)
	}
	// The instance object rendered for the API carries the same texts.
	v, err := h.eng.View("leaky", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if enc, _ := json.Marshal(v); strings.Contains(string(enc), tok) {
		t.Errorf("the token reached the instance view: %s", enc)
	}
}

func toString(a any) string {
	switch t := a.(type) {
	case string:
		return t
	case error:
		return t.Error()
	}
	raw, _ := json.Marshal(a)
	return string(raw)
}

// An extension's output is arbitrary JSON: a granted secret echoed into
// a verdict's observed values, its capture, its message, or a seed's sent
// counts — nested in maps and arrays — never reaches evidence (seeds.go:110 and checkpoints.go:240).
// The fake's `leak`
// conformance behavior is the misbehaving adapter.
func TestExecOutputIsRedactedRecursively(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	image := "docker.io/podaro/exec-conformance@sha256:" + strings.Repeat("e", 64)
	lab := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: spill, version: 1.0.0 }
secrets:
  tok: { kind: token }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
seeds:
  spill: { generator: { exec: { image: IMAGE, args: [leak], secrets: [tok] } }, count: 1 }
checkpoints:
  - id: leaky
    adapter: exec
    params: { image: IMAGE, args: [leak], secrets: [tok] }
    expect: { echo: anything }
    severity: warn
    retries: { attempts: 1 }
`
	lab = strings.ReplaceAll(lab, "IMAGE", image)
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "spill"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	raw, err := os.ReadFile(filepath.Join(h.dir, "instances", "spill", "secrets", "tok"))
	if err != nil {
		t.Fatal(err)
	}
	tok := string(raw)
	// The adapter did echo the value (the precondition): the fake's stderr
	// carried it into the capture before redaction — so the redacted
	// marker must appear where the value was.
	cps, _ := h.eng.Checkpoints("spill", Socket)
	var leaky *state.CheckpointResult
	for _, cp := range cps {
		if cp.ID == "leaky" {
			leaky = cp.Result
		}
	}
	if leaky == nil || leaky.Status != "pass" {
		t.Fatalf("the leak run must have passed: %+v", leaky)
	}
	if strings.Contains(string(leaky.Observed), tok) || strings.Contains(leaky.Message, tok) {
		t.Fatalf("the token reached the checkpoint result: %s · %s", leaky.Observed, leaky.Message)
	}
	if !strings.Contains(string(leaky.Observed), "[redacted:tok]") || !strings.Contains(leaky.Message, "leaked [redacted:tok]") {
		t.Fatalf("the value was redacted, not dropped: %s · %s", leaky.Observed, leaky.Message)
	}
	// Every evidence file — the checkpoint entry with its nested capture,
	// the seed entry with its nested sent counts.
	var files, redacted int
	_ = filepath.Walk(filepath.Join(h.dir, "instances", "spill", "evidence"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		files++
		raw, _ := os.ReadFile(p)
		if strings.Contains(string(raw), tok) {
			t.Errorf("the token reached evidence %s:\n%s", filepath.Base(p), raw)
		}
		if strings.Contains(string(raw), "[redacted:tok]") {
			redacted++
		}
		return nil
	})
	if files == 0 || redacted < 2 {
		t.Fatalf("expected the checkpoint and the seed entries to carry redacted markers: %d files, %d with markers", files, redacted)
	}
	entries, _ := h.eng.Evidence("spill", EvidenceFilter{Type: "checkpoint"}, Socket)
	var captureSeen bool
	for _, en := range entries {
		if en.Checkpoint != nil && en.Checkpoint.ID == "leaky" {
			// The journal indents its JSON: compare whitespace-free.
			obs := strings.Join(strings.Fields(string(en.Checkpoint.Observed)), "")
			if !strings.Contains(obs, `"deep":"[redacted:tok]"`) || !strings.Contains(obs, `"list":["[redacted:tok]"`) {
				t.Fatalf("the capture is redacted recursively: %s", obs)
			}
			captureSeen = true
		}
	}
	if !captureSeen {
		t.Fatal("no checkpoint entry for leaky")
	}
	seeds, _ := h.eng.Evidence("spill", EvidenceFilter{Type: "seed"}, Socket)
	if len(seeds) != 1 {
		t.Fatalf("one seed run: %d", len(seeds))
	}
	sent, _ := json.Marshal(seeds[0].Seed.Sent)
	if !strings.Contains(string(sent), `"echo":"[redacted:tok]"`) || !strings.Contains(string(sent), `"deep":"[redacted:tok]"`) || !strings.Contains(seeds[0].Seed.Message, "leaked [redacted:tok]") {
		t.Fatalf("the seed's sent counts and message are redacted recursively: %s · %s", sent, seeds[0].Seed.Message)
	}
	// The journal, too.
	if journal := journalOf(h, job.ID); strings.Contains(journal, tok) {
		t.Fatalf("the token reached the journal:\n%s", journal)
	}
}

// A service whose init targets another service comes up after it: the
// bring-up order honors init dependencies, ties by name (engine.go:1674).
// Alphabetically `alpha` would start
// first and run its init against a `zeta` that does not exist yet.
func TestInitTargetsComeUpFirst(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.opts.Library = lab.DirLibrary(filepath.Join("testdata", "modules"))
	dir := t.TempDir()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: crossinit, version: 1.0.0 }
services:
  alpha: { use: modules/init-cross@1.0 }
  zeta: { use: modules/init-web@1.0 }
`
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "crossinit"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	journal := journalOf(h, job.ID)
	zetaUp, alphaInit := strings.Index(journal, "alive zeta ok"), strings.Index(journal, "init alpha ok 2 requests")
	if zetaUp < 0 || alphaInit < 0 || zetaUp > alphaInit {
		t.Fatalf("zeta must be up before alpha's init runs against it:\n%s", journal)
	}
	if !strings.Contains(journal, "init zeta ok 2 requests") {
		t.Fatalf("zeta's own init runs too:\n%s", journal)
	}
}

// orderServices: name order with init targets first; a cycle is refused.
func TestOrderServicesHonorsInitTargets(t *testing.T) {
	order, err := orderServices([]string{"alpha", "mid", "zeta"}, map[string]map[string]int{"alpha": {"zeta": 0}, "mid": {"alpha": 1}})
	if err != nil || strings.Join(order, ",") != "zeta,alpha,mid" {
		t.Fatalf("order %v err %v", order, err)
	}
	order, err = orderServices([]string{"b", "a"}, nil)
	if err != nil || strings.Join(order, ",") != "a,b" {
		t.Fatalf("plain name order: %v %v", order, err)
	}
	if _, err := orderServices([]string{"a", "b", "c"}, map[string]map[string]int{"a": {"b": 0}, "b": {"a": 0}}); err == nil || !strings.Contains(err.Error(), "cycle among a, b") {
		t.Fatalf("a cycle must be refused: %v", err)
	}
	// Targets outside the plan (validation reports those) do not block.
	if order, err := orderServices([]string{"a"}, map[string]map[string]int{"a": {"ghost": 0}}); err != nil || len(order) != 1 {
		t.Fatalf("unknown target: %v %v", order, err)
	}
}

// A synchronous checkpoint run that finishes evaluating as destroy removes
// the instance records nothing: no evidence directory reappears, no result
// row outlives the instance, and the run reports the instance gone (checkpoints.go:287).
// The run is held between its
// evaluation and its record by the beforeRecord seam.
func TestCheckpointRunCannotOutliveDestroy(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Template: "grafana-prometheus-intro", Name: "intro"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	evaluated, destroyed := make(chan struct{}), make(chan struct{})
	beforeRecord = func(string) { close(evaluated); <-destroyed }
	t.Cleanup(func() { beforeRecord = nil })
	type outcome struct {
		row *state.CheckpointResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		row, err := h.eng.RunCheckpoint(ctx, "intro", "prometheus-ready", Socket)
		done <- outcome{row, err}
	}()
	<-evaluated
	dj, err := h.eng.Destroy(ctx, "intro", "intro")
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(dj.ID); j.State != state.JobSucceeded {
		t.Fatalf("destroy: %+v\n%s", j, journalOf(h, dj.ID))
	}
	if _, err := h.eng.RunCheckpoint(ctx, "intro", "prometheus-ready", Socket); code(err) != pdr.CodeInstanceNotFound {
		t.Fatalf("a run asked for after the destroy: %v", err)
	}
	close(destroyed)
	out := <-done
	if out.err == nil || code(out.err) != pdr.CodeInstanceNotFound {
		t.Fatalf("the late record must find the instance gone: err=%v row=%+v", out.err, out.row)
	}
	if _, err := os.Stat(h.eng.instanceDir("intro")); !os.IsNotExist(err) {
		t.Fatalf("the instance directory came back: %v", err)
	}
	if rows, _ := h.store.ListCheckpointResults("intro"); len(rows) != 0 {
		t.Fatalf("orphan result rows: %+v", rows)
	}
}

// A declaration whose secret kind changed after the value was generated is
// refused at the next walk of the create path — here a reset — naming both
// kinds; the listing shows the mismatch meanwhile (secrets.go:113).
func TestSecretKindChangeIsRefused(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.opts.Library = lab.DirLibrary(filepath.Join("testdata", "modules"))
	dir := t.TempDir()
	write := func(kind string) {
		body := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: kinds, version: 1.0.0 }\nsecrets:\n  tok: { kind: " + kind + " }\nservices:\n  web: { use: modules/init-web@1.0 }\n"
		if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("token")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "kinds"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	view, err := h.eng.Secrets("kinds", Socket)
	if err != nil || len(view) != 1 || view[0].Kind != "token" || view[0].Generated != "token" {
		t.Fatalf("listing after create: %+v %v", view, err)
	}
	value, _ := h.eng.secretStore("kinds").Value("tok")
	write("uuid")
	if view, _ := h.eng.Secrets("kinds", Socket); view[0].Kind != "uuid" || view[0].Generated != "token" {
		t.Fatalf("the listing must show the declared and the generated kind: %+v", view)
	}
	rj, err := h.eng.ResetAs(ctx, "kinds", Socket)
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(rj.ID)
	if j.State != state.JobFailed || !strings.Contains(errText(j), "PDR-E204") || !strings.Contains(errText(j), "generated as a token") || !strings.Contains(errText(j), "now says uuid") {
		t.Fatalf("the kind change must be refused, naming both kinds: %+v\n%s", j, journalOf(h, rj.ID))
	}
	if after, _ := h.eng.secretStore("kinds").Value("tok"); after != value {
		t.Fatal("the refusal must not touch the value")
	}
}

// A guarded write binds to the instance it began on: a run held across a
// destroy and a new create of the same name must not land in the new
// instance (guard.go:45).
func TestGuardedWriteBindsToTheInstanceGeneration(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	up := func() {
		job, err := h.eng.Create(ctx, CreateRequest{Template: "grafana-prometheus-intro", Name: "intro"})
		if err != nil {
			t.Fatal(err)
		}
		if j := h.wait(job.ID); j.State != state.JobSucceeded {
			t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
		}
	}
	up()
	evaluated, released := make(chan struct{}), make(chan struct{})
	beforeRecord = func(string) { close(evaluated); <-released }
	t.Cleanup(func() { beforeRecord = nil })
	type outcome struct {
		row *state.CheckpointResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		row, err := h.eng.RunCheckpoint(ctx, "intro", "prometheus-ready", Socket)
		done <- outcome{row, err}
	}()
	<-evaluated
	beforeRecord = nil // the second instance's own runs are not held
	dj, err := h.eng.Destroy(ctx, "intro", "intro")
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(dj.ID); j.State != state.JobSucceeded {
		t.Fatalf("destroy: %+v", j)
	}
	up()
	before, _ := h.eng.Evidence("intro", EvidenceFilter{Type: "checkpoint"}, Socket)
	rows, _ := h.store.ListCheckpointResults("intro")
	var was state.CheckpointResult
	for _, r := range rows {
		if r.ID == "prometheus-ready" {
			was = r
		}
	}
	close(released)
	out := <-done
	if out.err == nil || code(out.err) != pdr.CodeInstanceNotFound || !strings.Contains(out.err.Error(), "replaced") {
		t.Fatalf("the late write must be refused as belonging to a replaced instance: err=%v row=%+v", out.err, out.row)
	}
	after, _ := h.eng.Evidence("intro", EvidenceFilter{Type: "checkpoint"}, Socket)
	if len(after) != len(before) {
		t.Fatalf("the old run's evidence landed in the new instance: %d → %d entries", len(before), len(after))
	}
	rows, _ = h.store.ListCheckpointResults("intro")
	for _, r := range rows {
		if r.ID == "prometheus-ready" && (!r.At.Equal(was.At) || r.Evidence != was.Evidence) {
			t.Fatalf("the new instance's row was overwritten by the old run: %+v → %+v", was, r)
		}
	}
}

// A checkpoint whose class or adapter changed under an authoring instance
// starts over as a pending row: no verdict carries across a changed
// definition (lab.go:263).
func TestChangedCheckpointDefinitionStartsOverAsPending(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	write := func(class string) {
		body := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: redef, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n" + class + "    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    hint: Is the web service answering on port 80?\n"
		if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "redef"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	rows, _ := h.store.ListCheckpointResults("redef")
	if len(rows) != 1 || rows[0].Class != "baseline" || rows[0].Status != "pass" {
		t.Fatalf("the baseline passed at create: %+v", rows)
	}
	write("    class: objective\n")
	lv, err := h.eng.instanceView("redef")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.eng.ensureResultRows(lv); err != nil {
		t.Fatal(err)
	}
	rows, _ = h.store.ListCheckpointResults("redef")
	if len(rows) != 1 || rows[0].Class != "objective" || rows[0].Status != "" || rows[0].Evidence != "" || rows[0].Message != "" || rows[0].Observed != nil {
		t.Fatalf("a changed definition must start over as pending: %+v", rows)
	}
	view, err := h.eng.View("redef", Socket)
	if err != nil || view.Checkpoints.Objective.Total != 1 || view.Checkpoints.Objective.Passed != 0 || view.Checkpoints.Baseline.Total != 0 {
		t.Fatalf("the tally must not count a stale verdict: %+v %v", view.Checkpoints, err)
	}
}

// A run whose observation is older than the latest result on record stays
// in evidence but never replaces it: a run held across a reset does not
// overwrite the reset's fresh verdict (checkpoints.go:295).
func TestStaleRunNeverReplacesAFresherResult(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Template: "grafana-prometheus-intro", Name: "intro"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	evaluated, released := make(chan struct{}), make(chan struct{})
	beforeRecord = func(string) { close(evaluated); <-released }
	t.Cleanup(func() { beforeRecord = nil })
	type outcome struct {
		row *state.CheckpointResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		row, err := h.eng.RunCheckpoint(ctx, "intro", "prometheus-ready", Socket)
		done <- outcome{row, err}
	}()
	<-evaluated
	beforeRecord = nil
	rj, err := h.eng.ResetAs(ctx, "intro", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(rj.ID); j.State != state.JobSucceeded {
		t.Fatalf("reset: %+v\n%s", j, journalOf(h, rj.ID))
	}
	rowOf := func() state.CheckpointResult {
		rows, _ := h.store.ListCheckpointResults("intro")
		for _, r := range rows {
			if r.ID == "prometheus-ready" {
				return r
			}
		}
		t.Fatal("no row")
		return state.CheckpointResult{}
	}
	fresh := rowOf()
	before, _ := h.eng.Evidence("intro", EvidenceFilter{Type: "checkpoint"}, Socket)
	close(released)
	out := <-done
	if out.err != nil || out.row == nil || out.row.Evidence == "" {
		t.Fatalf("the run itself is answered with its result and recorded in evidence: %v %+v", out.err, out.row)
	}
	if now := rowOf(); !now.At.Equal(fresh.At) || now.Evidence != fresh.Evidence || now.Job != rj.ID {
		t.Fatalf("the reset's fresher result must stand: %+v → %+v", fresh, now)
	}
	if after, _ := h.eng.Evidence("intro", EvidenceFilter{Type: "checkpoint"}, Socket); len(after) != len(before)+1 {
		t.Fatalf("the stale run stays in evidence: %d → %d", len(before), len(after))
	}
}

// A run or an attestation asked for while a reset job is active is refused
// as busy (PDR-E201), like during a destroy.
func TestRunsAreRefusedWhileAResetIsActive(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Template: "grafana-prometheus-intro", Name: "intro"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	rj, err := h.eng.ResetAs(ctx, "intro", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.eng.RunCheckpoint(ctx, "intro", "prometheus-ready", Socket); code(err) != pdr.CodeInstanceBusy {
		t.Fatalf("a run during a reset: %v", err)
	}
	if _, err := h.eng.Attest(ctx, "intro", "prometheus-ready", "", Socket); code(err) != pdr.CodeInstanceBusy {
		t.Fatalf("an attestation during a reset: %v", err)
	}
	if j := h.wait(rj.ID); j.State != state.JobSucceeded {
		t.Fatalf("reset: %+v", j)
	}
}

// Progress is validated against the results inside the locked section
// that writes it: a result recorded between a PUT's arrival and its write
// is seen, and a stale claim never lands (progress.go:210).
// The PUT is held by the beforeProgressWrite seam.
func TestProgressIsValidatedUnderTheInstanceLock(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "playbooks"), 0o755)
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: prog, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\n"
	pb := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Playbook\nmetadata: { name: walk, title: Walk }\nsteps:\n  - id: look\n    title: Look\n    context: web\n    body: Look at the page.\n    checkpoint:\n      id: page-up\n      adapter: http\n      params: { url: http://web:80/ }\n      expect: { status: 200 }\n      hint: The page is always up.\n"
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "playbooks", "walk.yaml"), []byte(pb), 0o644)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "prog"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	if res, err := h.eng.RunCheckpoint(ctx, "prog", "page-up", Socket); err != nil || res.Status != "pass" {
		t.Fatalf("page-up passes while the page is up: %+v %v", res, err)
	}
	held, release := make(chan struct{}), make(chan struct{})
	beforeProgressWrite = func(string) { close(held); <-release }
	t.Cleanup(func() { beforeProgressWrite = nil })
	type outcome struct {
		p   *state.Progress
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		p, err := h.eng.PutProgress("prog", "walk", state.Progress{CurrentStep: "look", Steps: map[string]state.StepProgress{"look": {Status: "pass"}}}, Socket)
		done <- outcome{p, err}
	}()
	<-held
	beforeProgressWrite = nil
	// The page goes down and its checkpoint is judged again before the
	// PUT writes.
	svc, err := h.eng.Service("prog", "web")
	if err != nil || svc == nil {
		t.Fatalf("service: %v", err)
	}
	if err := h.fake.Stop(ctx, svc.Container, time.Second); err != nil {
		t.Fatal(err)
	}
	if res, err := h.eng.RunCheckpoint(ctx, "prog", "page-up", Socket); err != nil || res.Status == "pass" {
		t.Fatalf("page-up must not pass with the page down: %+v %v", res, err)
	}
	close(release)
	out := <-done
	if out.err == nil || code(out.err) != pdr.CodeProgressRefused || !strings.Contains(out.err.Error(), "claims pass") {
		t.Fatalf("a claim the latest result no longer supports must be refused: %v %+v", out.err, out.p)
	}
}

// writeProgLab writes an authoring template with one web service and a
// playbook whose step look is judged by the http checkpoint page-up.
func writeProgLab(t *testing.T, dir string) {
	t.Helper()
	writeProgLabWith(t, dir, "{ status: 200 }")
}

// writeProgLabWith is writeProgLab with the step checkpoint's expectation
// as given.
func writeProgLabWith(t *testing.T, dir, expect string) {
	t.Helper()
	_ = os.MkdirAll(filepath.Join(dir, "playbooks"), 0o755)
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: prog, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\n"
	pb := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Playbook\nmetadata: { name: walk, title: Walk }\nsteps:\n  - id: look\n    title: Look\n    context: web\n    body: Look at the page.\n    checkpoint:\n      id: page-up\n      adapter: http\n      params: { url: http://web:80/ }\n      expect: " + expect + "\n      hint: The page is always up.\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "playbooks", "walk.yaml"), []byte(pb), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeGateLab writes an authoring template with one web service and one
// gate baseline, web-up, judged by http.
func writeGateLab(t *testing.T, dir string) {
	t.Helper()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: gate, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    hint: Is the web service answering on port 80?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Freshness is judged by evaluation start: an older run that records
// after a newer one began does not make the newer one's result
// evidence-only (checkpoints.go:230).
func TestFreshnessIsJudgedByEvaluationStart(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Template: "grafana-prometheus-intro", Name: "intro"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	var mu sync.Mutex
	calls := 0
	atSeam := make(chan int, 2)
	holdA, holdB := make(chan struct{}), make(chan struct{})
	beforeRecord = func(string) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		atSeam <- n
		if n == 1 {
			<-holdA
		} else {
			<-holdB
		}
	}
	t.Cleanup(func() { beforeRecord = nil })
	type outcome struct {
		row *state.CheckpointResult
		err error
	}
	run := func() chan outcome {
		c := make(chan outcome, 1)
		go func() {
			row, err := h.eng.RunCheckpoint(ctx, "intro", "prometheus-ready", Socket)
			c <- outcome{row, err}
		}()
		return c
	}
	doneA := run()
	if n := <-atSeam; n != 1 {
		t.Fatalf("seam order: %d", n)
	}
	doneB := run() // begins after A finished evaluating
	if n := <-atSeam; n != 2 {
		t.Fatalf("seam order: %d", n)
	}
	close(holdA)
	outA := <-doneA
	close(holdB)
	outB := <-doneB
	if outA.err != nil || outB.err != nil {
		t.Fatalf("runs: %v %v", outA.err, outB.err)
	}
	rows, _ := h.store.ListCheckpointResults("intro")
	for _, r := range rows {
		if r.ID == "prometheus-ready" && r.Evidence != outB.row.Evidence {
			t.Fatalf("the later evaluation must stand as the latest result: row %s · A %s · B %s", r.Evidence, outA.row.Evidence, outB.row.Evidence)
		}
	}
}

// A verify job decides on the result that stands: its own observation,
// overtaken by a later evaluation's failure, must not mark the instance
// ready (checkpoints.go:238). The job is
// held between its evaluations and their records by beforeJobRecord.
func TestVerifyJobGatesOnTheResultThatStood(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeGateLab(t, dir)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "gate"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	held, release := make(chan struct{}), make(chan struct{})
	beforeJobRecord = func(string) { close(held); <-release }
	t.Cleanup(func() { beforeJobRecord = nil })
	vj, err := h.eng.VerifyAs(ctx, "gate", "", Socket)
	if err != nil {
		t.Fatal(err)
	}
	<-held
	beforeJobRecord = nil
	svc, err := h.eng.Service("gate", "web")
	if err != nil || svc == nil {
		t.Fatalf("service: %v", err)
	}
	if err := h.fake.Stop(ctx, svc.Container, time.Second); err != nil {
		t.Fatal(err)
	}
	if res, err := h.eng.RunCheckpoint(ctx, "gate", "web-up", Socket); err != nil || res.Status == "pass" {
		t.Fatalf("web-up must not pass with the page down: %+v %v", res, err)
	}
	close(release)
	if j := h.wait(vj.ID); j.State != state.JobSucceeded {
		t.Fatalf("verify: %+v\n%s", j, journalOf(h, vj.ID))
	}
	v, err := h.eng.View("gate", Socket)
	if err != nil || v.Ladder.Stage == "ready" {
		t.Fatalf("the job must gate on the failure that stood, not on its own overtaken pass: %+v\n%s", v.Ladder, journalOf(h, vj.ID))
	}
	rows, _ := h.store.ListCheckpointResults("gate")
	if len(rows) != 1 || rows[0].Status == "pass" {
		t.Fatalf("the latest result is the failure: %+v", rows)
	}
	if journal := journalOf(h, vj.ID); !strings.Contains(journal, "superseded") {
		t.Fatalf("the journal says the job's observation was superseded:\n%s", journal)
	}
}

// A reset's clearing waits for a progress write that holds the instance
// lock, then clears it: a claim validated before the reset never survives
// it (reset.go:110). The write is held inside
// the locked section by duringProgressWrite.
func TestResetClearingWaitsForAProgressWrite(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeProgLab(t, dir)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "prog"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	if res, err := h.eng.RunCheckpoint(ctx, "prog", "page-up", Socket); err != nil || res.Status != "pass" {
		t.Fatalf("page-up: %+v %v", res, err)
	}
	held, release := make(chan struct{}), make(chan struct{})
	duringProgressWrite = func(string) { close(held); <-release }
	t.Cleanup(func() { duringProgressWrite = nil })
	done := make(chan error, 1)
	go func() {
		_, err := h.eng.PutProgress("prog", "walk", state.Progress{CurrentStep: "look", Steps: map[string]state.StepProgress{"look": {Status: "pass"}}}, Socket)
		done <- err
	}()
	<-held
	duringProgressWrite = nil
	rj, err := h.eng.ResetAs(ctx, "prog", Socket)
	if err != nil {
		t.Fatal(err)
	}
	// The reset either waits at its clearing for the held write (the
	// guard) or, unguarded, races through it: give it two seconds to show
	// which, then release the write.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		j, _ := h.eng.Job(rj.ID, Socket)
		if j != nil && !j.Active() {
			break
		}
		if j != nil && j.Stage != "queued" && !strings.HasPrefix(j.Stage, "removing") && !strings.HasPrefix(j.Stage, "clearing") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("the write that began before the reset lands: %v", err)
	}
	if j := h.wait(rj.ID); j.State != state.JobSucceeded {
		t.Fatalf("reset: %+v\n%s", j, journalOf(h, rj.ID))
	}
	p, err := h.eng.Progress("prog", "walk", Socket)
	if err != nil || len(p.Steps) != 0 {
		t.Fatalf("a reset clears the progress written before it: %+v %v", p, err)
	}
}

// A progress write asked for while a reset job is active is refused as
// busy (PDR-E201), like a run.
func TestProgressWritesAreRefusedWhileAResetIsActive(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeProgLab(t, dir)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "prog"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	if res, err := h.eng.RunCheckpoint(ctx, "prog", "page-up", Socket); err != nil || res.Status != "pass" {
		t.Fatalf("page-up: %+v %v", res, err)
	}
	rj, err := h.eng.ResetAs(ctx, "prog", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.eng.PutProgress("prog", "walk", state.Progress{CurrentStep: "look", Steps: map[string]state.StepProgress{"look": {Status: "pass"}}}, Socket); code(err) != pdr.CodeInstanceBusy {
		t.Fatalf("a progress write during a reset: %v", err)
	}
	if j := h.wait(rj.ID); j.State != state.JobSucceeded {
		t.Fatalf("reset: %+v", j)
	}
}

// A synchronous run whose record would land after a destroy or reset was
// admitted is refused under the lock: nothing of it is recorded (checkpoints.go:356).
// The run is held between
// its evaluation and its record by beforeRecord.
func TestRunRecordIsRefusedWhenAResetBeganMeanwhile(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Template: "grafana-prometheus-intro", Name: "intro"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	syncRuns := func() int {
		entries, _ := h.eng.Evidence("intro", EvidenceFilter{Type: "checkpoint"}, Socket)
		n := 0
		for _, e := range entries {
			if e.Job == "" {
				n++
			}
		}
		return n
	}
	before := syncRuns()
	evaluated, released := make(chan struct{}), make(chan struct{})
	beforeRecord = func(string) { close(evaluated); <-released }
	t.Cleanup(func() { beforeRecord = nil })
	type outcome struct {
		row *state.CheckpointResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		row, err := h.eng.RunCheckpoint(ctx, "intro", "prometheus-ready", Socket)
		done <- outcome{row, err}
	}()
	<-evaluated
	beforeRecord = nil
	rj, err := h.eng.ResetAs(ctx, "intro", Socket)
	if err != nil {
		t.Fatal(err)
	}
	close(released)
	out := <-done
	if out.err == nil || code(out.err) != pdr.CodeInstanceBusy {
		t.Fatalf("a record after a reset was admitted must be refused as busy: %v %+v", out.err, out.row)
	}
	if j := h.wait(rj.ID); j.State != state.JobSucceeded {
		t.Fatalf("reset: %+v\n%s", j, journalOf(h, rj.ID))
	}
	if after := syncRuns(); after != before {
		t.Fatalf("the refused run must leave no evidence: %d → %d synchronous entries", before, after)
	}
}

// A job's evaluations carry their own start instants: one that waited at
// the semaphore and ran after a synchronous run of the same checkpoint is
// the newer observation, and its result stands (checkpoints.go:117).
func TestJobEvaluationsCarryTheirOwnStart(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	// Four slow objectives fill the evaluation slots (a status that never
	// matches, three attempts, 400 ms apart); web-up, authored last, is
	// admitted only when a slot frees.
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: queue, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n"
	for i := 1; i <= evaluateConcurrency; i++ {
		lab += "  - id: slow-" + strconv.Itoa(i) + "\n    class: objective\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 599 }\n    retries: { attempts: 3, backoff: 400ms }\n    hint: Never satisfied on purpose.\n"
	}
	lab += "  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    hint: Is the web service answering on port 80?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "queue"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	vj, err := h.eng.VerifyAs(ctx, "queue", "", Socket)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond) // the slow objectives hold every slot; web-up is queued
	if res, err := h.eng.RunCheckpoint(ctx, "queue", "web-up", Socket); err != nil || res.Status != "pass" {
		t.Fatalf("the synchronous run: %+v %v", res, err)
	}
	if j := h.wait(vj.ID); j.State != state.JobSucceeded {
		t.Fatalf("verify: %+v\n%s", j, journalOf(h, vj.ID))
	}
	rows, _ := h.store.ListCheckpointResults("queue")
	for _, r := range rows {
		if r.ID == "web-up" && r.Job != vj.ID {
			t.Fatalf("the job's evaluation ran after the synchronous one and must stand: %+v\n%s", r, journalOf(h, vj.ID))
		}
	}
}

// flakyResults is a store whose result writes fail on demand.
type flakyResults struct {
	state.Store
	mu   sync.Mutex
	fail bool
}

func (f *flakyResults) failing(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = on
}

func (f *flakyResults) PutCheckpointResult(r state.CheckpointResult) error {
	f.mu.Lock()
	fail := f.fail
	f.mu.Unlock()
	if fail {
		return errors.New("disk full")
	}
	return f.Store.PutCheckpointResult(r)
}

// The freshness mark advances only with a persisted result: a newer
// evaluation whose row the store refused leaves an older one free to land,
// instead of pinning the stale row (checkpoints.go:267).
func TestFreshnessAdvancesOnlyWithAPersistedResult(t *testing.T) {
	h := newHarness(t)
	fr := &flakyResults{Store: h.store}
	h.store = fr
	h.open()
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Template: "grafana-prometheus-intro", Name: "intro"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	var mu sync.Mutex
	calls := 0
	atSeam := make(chan int, 2)
	holdOld := make(chan struct{})
	beforeRecord = func(string) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		atSeam <- n
		if n == 1 {
			<-holdOld
		}
	}
	t.Cleanup(func() { beforeRecord = nil })
	type outcome struct {
		row *state.CheckpointResult
		err error
	}
	run := func() chan outcome {
		c := make(chan outcome, 1)
		go func() {
			row, err := h.eng.RunCheckpoint(ctx, "intro", "prometheus-ready", Socket)
			c <- outcome{row, err}
		}()
		return c
	}
	older := run()
	if n := <-atSeam; n != 1 {
		t.Fatalf("seam order: %d", n)
	}
	// The newer evaluation records while its row write fails.
	fr.failing(true)
	newer := run()
	if n := <-atSeam; n != 2 {
		t.Fatalf("seam order: %d", n)
	}
	if out := <-newer; out.err == nil {
		t.Fatal("the newer run's refused write must be an error")
	}
	fr.failing(false)
	close(holdOld)
	out := <-older
	if out.err != nil {
		t.Fatalf("the older run: %v", out.err)
	}
	rows, _ := h.store.ListCheckpointResults("intro")
	for _, r := range rows {
		if r.ID == "prometheus-ready" && r.Evidence != out.row.Evidence {
			t.Fatalf("the older evaluation must land, the newer one having never been persisted: row %s · older %s", r.Evidence, out.row.Evidence)
		}
	}
}

// Saving the seed salt writes onto the instance row as it stands, never the
// stale view a job began with: a running lab's stage survives it (seeds.go:56).
func TestSeedSaltSaveKeepsTheCurrentStage(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Template: "grafana-prometheus-intro", Name: "intro"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	lv, err := h.eng.instanceView("intro")
	if err != nil {
		t.Fatal(err)
	}
	// The view a create job holds: read before the services advanced.
	lv.inst.Stage, lv.inst.SeedSalt = state.StageNone, ""
	salt, err := h.eng.seedSalt(lv)
	if err != nil || len(salt) != 32 {
		t.Fatalf("seed salt: %q %v", salt, err)
	}
	cur, err := h.store.GetInstance("intro")
	if err != nil {
		t.Fatal(err)
	}
	if cur.Stage != state.StageReady || cur.SeedSalt != salt || lv.inst.SeedSalt != salt {
		t.Fatalf("the row keeps its stage and gains the salt: stage %q salt %q (view %q)", cur.Stage, cur.SeedSalt, lv.inst.SeedSalt)
	}
}

// A checkpoint whose expectation changed under an authoring instance —
// same id, class and adapter — starts over as pending, while an unchanged
// definition keeps its verdict (lab.go:258).
func TestChangedCheckpointExpectationStartsOverAsPending(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	write := func(expect string) {
		lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: redef, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: " + expect + "\n    hint: Is the web service answering on port 80?\n"
		if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("{ status: 200 }")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "redef"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	rowOf := func() state.CheckpointResult {
		rows, _ := h.store.ListCheckpointResults("redef")
		if len(rows) != 1 {
			t.Fatalf("one row: %+v", rows)
		}
		return rows[0]
	}
	if r := rowOf(); r.Status != "pass" || r.Definition == "" {
		t.Fatalf("the create's verdict, stamped with its definition: %+v", r)
	}
	// The same definition again: the verdict stands.
	lv, err := h.eng.instanceView("redef")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.eng.ensureResultRows(lv); err != nil {
		t.Fatal(err)
	}
	if r := rowOf(); r.Status != "pass" {
		t.Fatalf("an unchanged definition keeps its verdict: %+v", r)
	}
	// The expectation changes under the same id, class and adapter.
	write("{ status: 204 }")
	lv, err = h.eng.instanceView("redef")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.eng.ensureResultRows(lv); err != nil {
		t.Fatal(err)
	}
	if r := rowOf(); r.Status != "" || r.Evidence != "" || r.Class != "baseline" || r.Adapter != "http" {
		t.Fatalf("a changed expectation must start over as pending: %+v", r)
	}
}

// A progress claim backed by a result from before the checkpoint's
// definition changed is refused until the checkpoint is judged again
// (progress.go:248).
func TestProgressRefusesAResultFromAnObsoleteDefinition(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeProgLabWith(t, dir, "{ status: 200 }")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "prog"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	if res, err := h.eng.RunCheckpoint(ctx, "prog", "page-up", Socket); err != nil || res.Status != "pass" {
		t.Fatalf("page-up: %+v %v", res, err)
	}
	claim := state.Progress{CurrentStep: "look", Steps: map[string]state.StepProgress{"look": {Status: "pass"}}}
	if _, err := h.eng.PutProgress("prog", "walk", claim, Socket); err != nil {
		t.Fatalf("a claim the current definition's result backs: %v", err)
	}
	// The author changes what the step checks; the old pass no longer
	// speaks for it.
	writeProgLabWith(t, dir, "{ status: 204 }")
	_, err = h.eng.PutProgress("prog", "walk", claim, Socket)
	if code(err) != pdr.CodeProgressRefused || !strings.Contains(err.Error(), "changed since that result was recorded") {
		t.Fatalf("a claim backed by a result of the old definition must be refused: %v", err)
	}
}

// A module alias runs exactly what its module declared: a checkpoint param
// named image under an alias is not an exec spec and selects nothing
// (checkpoints.go:64).
func TestAliasCheckpointRunsWhatItsModuleDeclared(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.opts.Library = lab.DirLibrary(filepath.Join("testdata", "modules"))
	dir := t.TempDir()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: aliased, version: 1.0.0 }
services:
  web: { use: modules/alias-judge@1.0 }
checkpoints:
  - id: lag
    adapter: lag-judge
    params: { image: "docker.io/podaro/other@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", args: [crash] }
    expect: { lag: 0 }
    retries: { attempts: 1 }
`
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "aliased"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create must judge lag by the module's image, not the param's: %+v\n%s", j, journalOf(h, job.ID))
	}
	cps, err := h.eng.Checkpoints("aliased", Socket)
	if err != nil {
		t.Fatal(err)
	}
	var lag *state.CheckpointResult
	for _, cp := range cps {
		if cp.ID == "lag" {
			lag = cp.Result
		}
	}
	if lag == nil || lag.Status != "pass" {
		t.Fatalf("lag runs the module's declared image (the conformance fixture, pass): %+v", lag)
	}
	entries, _ := h.eng.Evidence("aliased", EvidenceFilter{Type: "checkpoint"}, Socket)
	var seen string
	for _, en := range entries {
		if en.Checkpoint != nil {
			seen += string(en.Checkpoint.Observed)
		}
	}
	if !strings.Contains(seen, "docker.io/podaro/exec-conformance@") || strings.Contains(seen, "docker.io/podaro/other@") {
		t.Fatalf("evidence names the module's image and never the param's:\n%s", seen)
	}
}

// Every read pairs a result with the definition it was judged by: after
// an authoring edit the checkpoint list, the instance tally and the JUnit
// export show the checkpoint pending until it is judged again (checkpoints.go:355).
func TestReadsShowAResultOfAnObsoleteDefinitionAsPending(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeProgLabWith(t, dir, "{ status: 200 }")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "prog"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	if res, err := h.eng.RunCheckpoint(ctx, "prog", "page-up", Socket); err != nil || res.Status != "pass" {
		t.Fatalf("page-up: %+v %v", res, err)
	}
	pageUp := func() *state.CheckpointResult {
		cps, err := h.eng.Checkpoints("prog", Socket)
		if err != nil {
			t.Fatal(err)
		}
		for _, cp := range cps {
			if cp.ID == "page-up" {
				return cp.Result
			}
		}
		t.Fatal("page-up is declared")
		return nil
	}
	if r := pageUp(); r == nil || r.Status != "pass" {
		t.Fatalf("before the edit the list shows the pass: %+v", r)
	}
	if v, err := h.eng.View("prog", Socket); err != nil || v.Checkpoints.Objective.Passed != 1 || v.Checkpoints.Objective.Total != 1 {
		t.Fatalf("before the edit the tally counts the pass: %+v %v", v.Checkpoints, err)
	}
	if xml, _ := h.eng.JUnit("prog", Socket); strings.Contains(string(xml), "not evaluated") {
		t.Fatalf("before the edit JUnit reports the pass:\n%s", xml)
	}
	// The author changes what the checkpoint asserts; the old pass speaks
	// for nothing until it is judged again.
	writeProgLabWith(t, dir, "{ status: 204 }")
	if r := pageUp(); r != nil {
		t.Fatalf("the list must show an edited checkpoint pending, not its old verdict: %+v", r)
	}
	if v, err := h.eng.View("prog", Socket); err != nil || v.Checkpoints.Objective.Passed != 0 || v.Checkpoints.Objective.Total != 1 {
		t.Fatalf("the tally must count an edited checkpoint as pending: %+v %v", v.Checkpoints, err)
	}
	if xml, _ := h.eng.JUnit("prog", Socket); !strings.Contains(string(xml), "not evaluated") {
		t.Fatalf("JUnit must report an edited checkpoint as not evaluated:\n%s", xml)
	}
}

// The rendered ladder never says ready while a current gate baseline lacks
// a pass: after an authoring edit to a gate baseline the view shows seeded
// beside baseline 0/1 until it is judged again, and the persisted stage
// is untouched — a read writes nothing (view.go:150).
func TestLadderIsCappedWhileAGateBaselineLacksACurrentPass(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	write := func(expect string) {
		lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: capped, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: " + expect + "\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
		if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("{ status: 200 }")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "capped"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	v, err := h.eng.View("capped", Socket)
	if err != nil || v.Ladder.Stage != string(state.StageReady) || v.Checkpoints.Baseline.Passed != 1 {
		t.Fatalf("after create: ladder %+v tally %+v %v", v.Ladder, v.Checkpoints, err)
	}
	// The author changes what the gate baseline asserts: the old pass no
	// longer verifies the current baseline, so the instance is not ready.
	write("{ status: 204 }")
	v, err = h.eng.View("capped", Socket)
	if err != nil || v.Checkpoints.Baseline.Passed != 0 || v.Checkpoints.Baseline.Total != 1 {
		t.Fatalf("the tally shows the edited baseline pending: %+v %v", v.Checkpoints, err)
	}
	if v.Ladder.Stage != string(state.StageSeeded) || v.Ladder.Rank != state.StageSeeded.Rank() || v.Ladder.Label != "seeded" {
		t.Fatalf("the ladder must not say ready beside baseline 0/1: %+v", v.Ladder)
	}
	if inst, _ := h.store.GetInstance("capped"); inst.Stage != state.StageReady {
		t.Fatalf("a read writes nothing: the persisted stage stays %s until a job judges the baseline", inst.Stage)
	}
	if views, err := h.eng.Views(); err != nil || len(views) != 1 || views[0].Ladder.Stage != string(state.StageSeeded) {
		t.Fatalf("the list renders the same cap: %+v %v", views, err)
	}
	// Judged again: the fake answers 200, so the new expectation fails and
	// verify records the regression the read already showed.
	vj, err := h.eng.VerifyAs(ctx, "capped", "", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(vj.ID); j.State != state.JobSucceeded {
		t.Fatalf("verify: %+v\n%s", j, journalOf(h, vj.ID))
	}
	if inst, _ := h.store.GetInstance("capped"); inst.Stage != state.StageSeeded {
		t.Fatalf("verify records what it finds: stage %s", inst.Stage)
	}
	// The author restores the expectation and verifies: ready again.
	write("{ status: 200 }")
	vj, err = h.eng.VerifyAs(ctx, "capped", "", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(vj.ID); j.State != state.JobSucceeded {
		t.Fatalf("verify: %+v\n%s", j, journalOf(h, vj.ID))
	}
	if v, _ := h.eng.View("capped", Socket); v.Ladder.Stage != string(state.StageReady) || v.Checkpoints.Baseline.Passed != 1 {
		t.Fatalf("judged green again, the ladder is ready: %+v %+v", v.Ladder, v.Checkpoints)
	}
}

// A recorded position is read as the current playbook stands: after an
// authoring edit to the step's checkpoint its pass reads as pending, and
// after the step is renamed the position falls to the first step with no
// statuses — exactly what PutProgress would now refuse — while the store
// keeps what was recorded (progress.go:179).
func TestProgressIsReadAsTheCurrentPlaybookStands(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeProgLabWith(t, dir, "{ status: 200 }")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "prog"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	if res, err := h.eng.RunCheckpoint(ctx, "prog", "page-up", Socket); err != nil || res.Status != "pass" {
		t.Fatalf("page-up: %+v %v", res, err)
	}
	claim := state.Progress{CurrentStep: "look", Steps: map[string]state.StepProgress{"look": {Status: "pass"}}}
	if _, err := h.eng.PutProgress("prog", "walk", claim, Socket); err != nil {
		t.Fatal(err)
	}
	p, err := h.eng.Progress("prog", "walk", Socket)
	if err != nil || p.CurrentStep != "look" || p.Steps["look"].Status != "pass" {
		t.Fatalf("the recorded position reads back: %+v %v", p, err)
	}
	// The author changes what the step checks: the pass speaks for nothing
	// until the checkpoint is judged again.
	writeProgLabWith(t, dir, "{ status: 204 }")
	p, err = h.eng.Progress("prog", "walk", Socket)
	if err != nil || p.CurrentStep != "look" {
		t.Fatalf("the step still exists, so the position holds: %+v %v", p, err)
	}
	if sp, has := p.Steps["look"]; has {
		t.Fatalf("a pass its checkpoint's current result does not back must read as pending: %+v", sp)
	}
	if stored, err := h.store.GetProgress("prog", "walk"); err != nil || stored.Steps["look"].Status != "pass" {
		t.Fatalf("a read writes nothing: the store keeps what was recorded: %+v %v", stored, err)
	}
	// The author renames the step: the position falls to the first step.
	pb, err := os.ReadFile(filepath.Join(dir, "playbooks", "walk.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "playbooks", "walk.yaml"), []byte(strings.Replace(string(pb), "id: look", "id: gaze", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err = h.eng.Progress("prog", "walk", Socket)
	if err != nil || p.CurrentStep != "gaze" || len(p.Steps) != 0 {
		t.Fatalf("a renamed step: the position falls to the first step with no statuses: %+v %v", p, err)
	}
}

// Evidence ids stay monotonic across the engine's appends: every append
// goes through one journal per instance, so entries recorded within the
// same millisecond list in the order they were appended, and destroy
// forgets the journal with the rest of the instance's in-memory state
// (lab.go:100).
func TestEvidenceIdsStayMonotonicAcrossEngineAppends(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeGateLab(t, dir)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "gate"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	// Sixty-four entries in one millisecond, each through the accessor the
	// engine's writers use: their ids must list in append order.
	at := time.Date(2026, 9, 5, 22, 0, 0, 500_000_000, time.UTC)
	var ids []string
	for i := 0; i < 64; i++ {
		stored, err := h.eng.journal("gate").Append(evidence.Entry{At: at, Type: evidence.TypeLifecycle, Instance: "gate", Lifecycle: &evidence.Lifecycle{Event: "probe", Detail: strconv.Itoa(i)}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, stored.ID)
	}
	entries, err := h.eng.Evidence("gate", EvidenceFilter{Type: "lifecycle"}, Socket)
	if err != nil {
		t.Fatal(err)
	}
	var listed []string
	for _, en := range entries {
		if en.Lifecycle != nil && en.Lifecycle.Event == "probe" {
			listed = append(listed, en.ID)
		}
	}
	if len(listed) != 64 {
		t.Fatalf("64 probe entries listed, got %d", len(listed))
	}
	for i := range ids {
		if listed[i] != ids[i] {
			t.Fatalf("entry %d listed out of append order: appended %s, listed %s", i, ids[i], listed[i])
		}
	}
	dj, err := h.eng.DestroyAs(ctx, "gate", "gate", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(dj.ID); j.State != state.JobSucceeded {
		t.Fatalf("destroy: %+v\n%s", j, journalOf(h, dj.ID))
	}
	h.eng.journalMu.Lock()
	_, cached := h.eng.journals["gate"]
	h.eng.journalMu.Unlock()
	if cached {
		t.Fatal("destroy forgets the instance's journal")
	}
}

// A checkpoint or seed reaches a service only through its recorded
// container: when the container stopped outside a job and another
// listener took its ephemeral port, the run errors and the seed fails —
// nothing is judged or delivered through the wrong door (lab.go:154).
func TestTargetsRefuseAServiceNotRunningItsRecordedContainer(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: gate, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "gate"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	if res, err := h.eng.RunCheckpoint(ctx, "gate", "web-up", Socket); err != nil || res.Status != "pass" {
		t.Fatalf("the live service passes: %+v %v", res, err)
	}
	svc, err := h.eng.Service("gate", "web")
	if err != nil || svc == nil || svc.Ports[80] == 0 {
		t.Fatalf("web publishes port 80: %+v %v", svc, err)
	}
	// The container stops outside any job; the kernel hands its ephemeral
	// port to an unrelated listener that answers 200 to everything.
	if err := h.fake.Stop(ctx, svc.Container, 0); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(svc.Ports[80]))
	if err != nil {
		t.Fatalf("the stopped container's port is free to take: %v", err)
	}
	defer ln.Close()
	var hits int64
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt64(&hits, 1)
			w.WriteHeader(200)
		}))
	}()
	res, err := h.eng.RunCheckpoint(ctx, "gate", "web-up", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "error" || res.Error == nil || !strings.Contains(res.Error.Cause, "not running its recorded container") {
		t.Fatalf("a run must not be judged through the impostor: %+v", res)
	}
	lv, err := h.eng.instanceView("gate")
	if err != nil {
		t.Fatal(err)
	}
	runner := &seed.Runner{Resolver: &instanceTarget{e: h.eng, lv: lv}}
	if _, perr := runner.Run(ctx, seed.Run{Instance: "gate", Name: "probe", Generator: "http-requests", Count: 3, Params: map[string]any{"service": "web", "path": "/"}, SeedValue: "0123456789abcdef", Epoch: time.Now()}); perr == nil {
		t.Fatal("a seed must not deliver through the impostor")
	}
	if n := atomic.LoadInt64(&hits); n != 0 {
		t.Fatalf("the impostor received %d requests; it must receive none", n)
	}
}

// A job's row reconciliation keeps a result a permitted concurrent run
// records meanwhile: both write under the instance lock, so the pending
// row for a changed definition never replaces the run's fresh verdict
// (lab.go:282).
func TestReconcileKeepsAResultRecordedMeanwhile(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	write := func(expect string) {
		lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: race, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: " + expect + "\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
		if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("{ status: 200 }")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "race"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	// The author changes the expectation: the next reconciliation wants a
	// pending row for web-up. A run of the changed checkpoint lands in the
	// window between the reconciliation's read and its write.
	write("{ status: 204 }")
	lv, err := h.eng.instanceView("race")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	beforeEnsureWrite = func(string) {
		done := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(done)
			if res, err := h.eng.RunCheckpoint(ctx, "race", "web-up", Socket); err != nil || res.Status != "fail" {
				t.Errorf("the run judges the changed checkpoint (the fake answers 200, 204 is expected): %+v %v", res, err)
			}
		}()
		// Without the lock the run records here; with it the run waits for
		// the reconciliation to finish, and this returns without it.
		select {
		case <-done:
		case <-time.After(300 * time.Millisecond):
		}
	}
	defer func() { beforeEnsureWrite = nil }()
	if err := h.eng.ensureResultRows(lv); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	rows, _ := h.store.ListCheckpointResults("race")
	if len(rows) != 1 || rows[0].Status != "fail" || rows[0].Definition != lab.DefinitionDigest(lv.checkpoints[0]) {
		t.Fatalf("the run's verdict for the current definition must stand, never a pending row over it: %+v", rows)
	}
}

// The container adapter judges only the service's own container: a
// stranger running under the predictable name — not managed by this
// instance, not the container the row names — is absent to it, never a
// running lab (lab.go:232).
func TestContainerCheckpointsIgnoreAStrangerUnderTheServiceName(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: strangers, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-running\n    adapter: container\n    params: { service: web }\n    expect: { state: running }\n    retries: { attempts: 1 }\n    hint: Is the web container running?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "strangers"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	if res, err := h.eng.RunCheckpoint(ctx, "strangers", "web-running", Socket); err != nil || res.Status != "pass" {
		t.Fatalf("the lab's own container passes: %+v %v", res, err)
	}
	svc, err := h.eng.Service("strangers", "web")
	if err != nil || svc == nil {
		t.Fatalf("web: %+v %v", svc, err)
	}
	// The lab's container is removed outside any job and a stranger —
	// another instance's, or anyone's — comes up under the same name.
	if err := h.fake.Remove(ctx, svc.Container); err != nil {
		t.Fatal(err)
	}
	image := "docker.io/library/busybox@sha256:" + strings.Repeat("d", 64)
	if err := h.fake.Pull(ctx, image); err != nil {
		t.Fatal(err)
	}
	if _, err := h.fake.Create(ctx, runtime.ContainerSpec{Name: svc.Container, Image: image, Labels: map[string]string{runtime.LabelManaged: "true", runtime.LabelInstance: "other", runtime.LabelService: "web"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.fake.Start(ctx, svc.Container); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.fake.Inspect(ctx, svc.Container); st == nil || !st.Running {
		t.Fatalf("the stranger runs under the name: %+v", st)
	}
	res, err := h.eng.RunCheckpoint(ctx, "strangers", "web-running", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "fail" || !strings.Contains(res.Message, "state absent") {
		t.Fatalf("a stranger under the service's name is absent to the adapter, never running: %+v", res)
	}
}

// An attestation stands until reset: a verify, a create's re-verify and a
// run keep a human's confirmation instead of re-judging it to "awaiting";
// reset clears it (verify.go:528).
func TestAnAttestationStandsUntilReset(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: att, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: confirmed\n    adapter: attest\n    class: objective\n    params: { prompt: \"Did you look at the page?\" }\n    retries: { attempts: 1 }\n    hint: Open the page and confirm.\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "att"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	rowOf := func() state.CheckpointResult {
		rows, _ := h.store.ListCheckpointResults("att")
		for _, r := range rows {
			if r.ID == "confirmed" {
				return r
			}
		}
		t.Fatal("confirmed has a row")
		return state.CheckpointResult{}
	}
	if r := rowOf(); r.Status != "fail" {
		t.Fatalf("at create an attest checkpoint awaits its human: %+v", r)
	}
	if res, err := h.eng.Attest(ctx, "att", "confirmed", "looked", Socket); err != nil || res.Status != "attested" {
		t.Fatalf("attest: %+v %v", res, err)
	}
	vj, err := h.eng.VerifyAs(ctx, "att", "", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(vj.ID); j.State != state.JobSucceeded {
		t.Fatalf("verify: %+v\n%s", j, journalOf(h, vj.ID))
	}
	if r := rowOf(); r.Status != "attested" {
		t.Fatalf("a verify must keep the attestation, not re-judge it: %+v\n%s", r, journalOf(h, vj.ID))
	}
	if !strings.Contains(journalOf(h, vj.ID), "a human's confirmation stands until reset") {
		t.Fatalf("the verify journal says the attestation stood:\n%s", journalOf(h, vj.ID))
	}
	if res, err := h.eng.RunCheckpoint(ctx, "att", "confirmed", Socket); err != nil || res.Status != "attested" {
		t.Fatalf("a run of an attested checkpoint returns the standing attestation: %+v %v", res, err)
	}
	rj, err := h.eng.ResetAs(ctx, "att", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(rj.ID); j.State != state.JobSucceeded {
		t.Fatalf("reset: %+v\n%s", j, journalOf(h, rj.ID))
	}
	if r := rowOf(); r.Status != "fail" {
		t.Fatalf("reset clears the attestation; the checkpoint awaits its human again: %+v", r)
	}
}

// A seed or verify job resumed after a reboot restores the lab first: the
// create path walks the instance as a reconcile — in the job's journal —
// before the job's own steps, so the resumed verify judges a running lab
// (engine.go:1430).
func TestAResumedVerifyRestoresTheLabFirst(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: gate, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "gate"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	// The host reboots while a verify job is running: every container
	// stops, the job record stays running, and the next start resumes it.
	h.fake.Close()
	if err := runtime.Reboot(h.world); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := h.store.PutJob(state.Job{ID: "job_resumed_verify", Kind: "verify", Instance: "gate", State: state.JobRunning, Stage: "verifying", Started: now}); err != nil {
		t.Fatal(err)
	}
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	j := h.wait("job_resumed_verify")
	journal := journalOf(h, "job_resumed_verify")
	if j.State != state.JobSucceeded {
		t.Fatalf("the resumed verify: %+v\n%s", j, journal)
	}
	if !strings.Contains(journal, "the lab is restored before the verify") || !strings.Contains(journal, "alive web ok") {
		t.Fatalf("the resumed verify restores the lab first, in its own journal:\n%s", journal)
	}
	if n := strings.Count(journal, "checkpoint web-up "); n != 1 {
		t.Fatalf("the restore judges nothing; the verify judges once — %d evaluations of web-up:\n%s", n, journal)
	}
	rows, _ := h.store.ListCheckpointResults("gate")
	if len(rows) != 1 || rows[0].Status != "pass" {
		t.Fatalf("the verify judged a running lab: %+v\n%s", rows, journal)
	}
	if inst, _ := h.store.GetInstance("gate"); inst.Stage != state.StageReady {
		t.Fatalf("the lab is ready again after the resumed verify: stage %s\n%s", inst.Stage, journal)
	}
	jobs, _ := h.store.ListJobs("gate")
	for _, jb := range jobs {
		if jb.Kind == "reconcile" {
			t.Fatalf("no separate reconcile job: the resumed verify restored the lab itself: %+v", jobs)
		}
	}
}

// An attestation that lands after a verify read its rows and before the
// attest checkpoint's evaluation began still stands: a machine evaluation
// never replaces a human's confirmation, whatever the order of the two
// (the guard lives in record).
func TestAnAttestationLandingBeforeTheEvaluationStands(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: att2, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: confirmed\n    adapter: attest\n    class: objective\n    params: { prompt: \"Did you look at the page?\" }\n    retries: { attempts: 1 }\n    hint: Open the page and confirm.\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "att2"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	// The human confirms in the window between the verify's read of the
	// rows and its evaluation of the checkpoint.
	beforeEvaluate = func(string) {
		beforeEvaluate = nil
		if res, err := h.eng.Attest(ctx, "att2", "confirmed", "looked", Socket); err != nil || res.Status != "attested" {
			t.Errorf("attest: %+v %v", res, err)
		}
	}
	defer func() { beforeEvaluate = nil }()
	vj, err := h.eng.VerifyAs(ctx, "att2", "", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(vj.ID); j.State != state.JobSucceeded {
		t.Fatalf("verify: %+v\n%s", j, journalOf(h, vj.ID))
	}
	rows, _ := h.store.ListCheckpointResults("att2")
	if len(rows) != 1 || rows[0].Status != "attested" {
		t.Fatalf("the confirmation stands over the machine's evaluation: %+v\n%s", rows, journalOf(h, vj.ID))
	}
	if !strings.Contains(journalOf(h, vj.ID), "a human's confirmation stands until reset") {
		t.Fatalf("the verify journal says the confirmation stood:\n%s", journalOf(h, vj.ID))
	}
}

// A verify that was not resumed never restarts the lab it is asked to
// judge: a service stopped outside a job is the regression the pre-flight
// exists to surface — the gate baseline red, the ladder back to seeded,
// the container left as found.
func TestAVerifyNeverRestartsTheLabItJudges(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: judged, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "judged"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	svc, _ := h.eng.Service("judged", "web")
	if err := h.fake.Stop(ctx, svc.Container, 0); err != nil {
		t.Fatal(err)
	}
	vj, err := h.eng.VerifyAs(ctx, "judged", "", Socket)
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(vj.ID)
	journal := journalOf(h, vj.ID)
	if j.State != state.JobSucceeded {
		t.Fatalf("a verify that finds a regression succeeds and records it: %+v\n%s", j, journal)
	}
	if strings.Contains(journal, "restored") || strings.Contains(journal, "alive web") {
		t.Fatalf("a verify judges the lab as it is; it never restores it:\n%s", journal)
	}
	if st, _ := h.fake.Inspect(ctx, svc.Container); st == nil || st.Running {
		t.Fatalf("the stopped container is left as found: %+v", st)
	}
	rows, _ := h.store.ListCheckpointResults("judged")
	if len(rows) != 1 || rows[0].Status == "pass" {
		t.Fatalf("the gate baseline is red against a stopped service: %+v", rows)
	}
	if inst, _ := h.store.GetInstance("judged"); inst.Stage != state.StageSeeded {
		t.Fatalf("the regression moves the ladder back to seeded: stage %s\n%s", inst.Stage, journal)
	}
}

// A seed resumed after a reboot restores the lab (judging nothing), runs
// its seed, then ends with the verify that returns the ladder to ready —
// one judgement, after the seed.
func TestAResumedSeedRestoresRunsThenVerifies(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: seeded, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\nseeds:\n  probe: { generator: http-requests, count: 2, params: { service: web, path: / } }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "seeded"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	h.fake.Close()
	if err := runtime.Reboot(h.world); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := h.store.PutJob(state.Job{ID: "job_resumed_seed", Kind: "seed", Instance: "seeded", Target: "probe", State: state.JobRunning, Stage: "seeding probe", Started: now}); err != nil {
		t.Fatal(err)
	}
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	j := h.wait("job_resumed_seed")
	journal := journalOf(h, "job_resumed_seed")
	if j.State != state.JobSucceeded {
		t.Fatalf("the resumed seed: %+v\n%s", j, journal)
	}
	// The restore's own journal names the standing seed it does not re-run
	// ("standing seeds not re-run: probe"); the seed job's run is the last
	// mention of it, and the one judgement comes after that.
	restore, seeded, judged := strings.Index(journal, "the lab is restored before the seed"), strings.LastIndex(journal, "probe"), strings.Index(journal, "checkpoint web-up ")
	if restore < 0 || seeded < 0 || judged < 0 || !(restore < seeded && seeded < judged) {
		t.Fatalf("restore, then the seed, then one judgement (%d, %d, %d):\n%s", restore, seeded, judged, journal)
	}
	if n := strings.Count(journal, "checkpoint web-up "); n != 1 {
		t.Fatalf("web-up judged once, not by the restore and again by the verify: %d\n%s", n, journal)
	}
	if inst, _ := h.store.GetInstance("seeded"); inst.Stage != state.StageReady {
		t.Fatalf("the ladder returns to ready: stage %s\n%s", inst.Stage, journal)
	}
}

// A reconcile re-verifies the baselines and leaves the objectives as they
// stand: no objective is re-judged, and PDR-W101 — a create's warning —
// is never raised for an objective a learner earned.
func TestAReconcileReverifiesBaselinesOnly(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: recon, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n  - id: page-visible\n    adapter: http\n    class: objective\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Open the page.\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "recon"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	if !strings.Contains(journalOf(h, job.ID), pdr.CodeObjectiveGreenAtCreate) {
		t.Fatalf("the create warns about the objective green at create:\n%s", journalOf(h, job.ID))
	}
	objectiveRow := func() state.CheckpointResult {
		rows, _ := h.store.ListCheckpointResults("recon")
		for _, r := range rows {
			if r.ID == "page-visible" {
				return r
			}
		}
		t.Fatal("page-visible has a row")
		return state.CheckpointResult{}
	}
	before := objectiveRow()
	h.fake.Close()
	if err := runtime.Reboot(h.world); err != nil {
		t.Fatal(err)
	}
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ := h.store.ListJobs("recon")
	if len(jobs) != 2 || jobs[0].Kind != "reconcile" {
		t.Fatalf("expected a reconcile job, got %+v", jobs)
	}
	if j := h.wait(jobs[0].ID); j.State != state.JobSucceeded {
		t.Fatalf("reconcile: %+v\n%s", j, journalOf(h, jobs[0].ID))
	}
	journal := journalOf(h, jobs[0].ID)
	if strings.Contains(journal, "checkpoint page-visible") || strings.Contains(journal, pdr.CodeObjectiveGreenAtCreate) {
		t.Fatalf("a reconcile re-verifies baselines only and raises no W101:\n%s", journal)
	}
	if !strings.Contains(journal, "checkpoint web-up ") || !strings.Contains(journal, "baseline 1/1 · objectives 1/1") {
		t.Fatalf("the baseline is re-verified and the summary counts every row:\n%s", journal)
	}
	if after := objectiveRow(); after.Job != before.Job || after.At != before.At {
		t.Fatalf("the objective's verdict stands as the learner earned it: before %+v, after %+v", before, after)
	}
	warnings := 0
	entries, _ := h.eng.Evidence("recon", EvidenceFilter{Type: "lifecycle"}, Socket)
	for _, en := range entries {
		if en.Lifecycle != nil && en.Lifecycle.Code == pdr.CodeObjectiveGreenAtCreate {
			warnings++
		}
	}
	if warnings != 1 {
		t.Fatalf("one W101 in evidence — the create's — not %d", warnings)
	}
}

// A resumed seed's trailing judgement re-verifies the baselines only,
// whatever the seed is named: a playbook sharing the seed's name does not
// get its objectives re-judged the way a verify scoped to that playbook
// would.
func TestAResumedSeedJudgesBaselinesOnlyWhateverItsName(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "playbooks"), 0o755)
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: named, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\nseeds:\n  probe: { generator: http-requests, count: 2, params: { service: web, path: / } }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
	pb := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Playbook\nmetadata: { name: probe, title: Probe }\nsteps:\n  - id: look\n    title: Look\n    context: web\n    body: Look at the page.\n    checkpoint:\n      id: page-visible\n      adapter: http\n      params: { url: http://web:80/ }\n      expect: { status: 200 }\n      retries: { attempts: 1 }\n      hint: The page is always up.\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "playbooks", "probe.yaml"), []byte(pb), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "named"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	h.fake.Close()
	if err := runtime.Reboot(h.world); err != nil {
		t.Fatal(err)
	}
	if err := h.store.PutJob(state.Job{ID: "job_named_seed", Kind: "seed", Instance: "named", Target: "probe", State: state.JobRunning, Stage: "seeding probe", Started: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	j := h.wait("job_named_seed")
	journal := journalOf(h, "job_named_seed")
	if j.State != state.JobSucceeded {
		t.Fatalf("the resumed seed: %+v\n%s", j, journal)
	}
	if strings.Contains(journal, "checkpoint page-visible") {
		t.Fatalf("the seed's trailing judgement is baselines only; the playbook that shares its name is not a scope:\n%s", journal)
	}
	if n := strings.Count(journal, "checkpoint web-up "); n != 1 {
		t.Fatalf("the baseline judged once: %d\n%s", n, journal)
	}
	if inst, _ := h.store.GetInstance("named"); inst.Stage != state.StageReady {
		t.Fatalf("the ladder returns to ready: stage %s\n%s", inst.Stage, journal)
	}
}

// A restore cut off by another stop still ends ready: a resumed seed whose
// containers are running but whose ladder stands below ready judges the
// baselines after its seed, keyed on the recorded stage, not on whether
// the containers happen to be running.
func TestAnInterruptedRestoreStillEndsReady(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: cutoff, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\nseeds:\n  probe: { generator: http-requests, count: 2, params: { service: web, path: / } }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "cutoff"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	// The engine stopped after a restore had brought the containers back
	// but before the judgement: containers running, ladder at seeded, the
	// seed job still recorded running.
	if err := h.eng.demoteAll("cutoff", state.StageSeeded); err != nil {
		t.Fatal(err)
	}
	if err := h.store.PutJob(state.Job{ID: "job_cutoff_seed", Kind: "seed", Instance: "cutoff", Target: "probe", State: state.JobRunning, Stage: "verifying", Started: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	j := h.wait("job_cutoff_seed")
	journal := journalOf(h, "job_cutoff_seed")
	if j.State != state.JobSucceeded {
		t.Fatalf("the re-resumed seed: %+v\n%s", j, journal)
	}
	if strings.Contains(journal, "restored before") {
		t.Fatalf("the containers run and the stage is seeded: nothing to restore:\n%s", journal)
	}
	if n := strings.Count(journal, "checkpoint web-up "); n != 1 {
		t.Fatalf("the baseline is judged once after the seed: %d\n%s", n, journal)
	}
	if inst, _ := h.store.GetInstance("cutoff"); inst.Stage != state.StageReady {
		t.Fatalf("the ladder returns to ready: stage %s\n%s", inst.Stage, journal)
	}
}

// A reconcile that recreated a container judges the objectives once too:
// the data the old container held is gone, so a verdict earned inside it
// no longer describes the lab — and still raises no W101.
func TestAReconcileReJudgesObjectivesWhenAContainerWasRecreated(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: rebuilt, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n  - id: page-visible\n    adapter: http\n    class: objective\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Open the page.\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "rebuilt"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	svc, _ := h.eng.Service("rebuilt", "web")
	h.fake.Close()
	if err := runtime.Reboot(h.world); err != nil {
		t.Fatal(err)
	}
	h.open()
	// The container vanished while the host was down.
	if err := h.fake.Remove(ctx, svc.Container); err != nil {
		t.Fatal(err)
	}
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ := h.store.ListJobs("rebuilt")
	if len(jobs) != 2 || jobs[0].Kind != "reconcile" {
		t.Fatalf("expected a reconcile job, got %+v", jobs)
	}
	if j := h.wait(jobs[0].ID); j.State != state.JobSucceeded {
		t.Fatalf("reconcile: %+v\n%s", j, journalOf(h, jobs[0].ID))
	}
	journal := journalOf(h, jobs[0].ID)
	if !strings.Contains(journal, "checkpoint page-visible") {
		t.Fatalf("a recreated container: the objectives are judged again:\n%s", journal)
	}
	if strings.Contains(journal, pdr.CodeObjectiveGreenAtCreate) {
		t.Fatalf("no W101 under a reconcile:\n%s", journal)
	}
	rows, _ := h.store.ListCheckpointResults("rebuilt")
	for _, r := range rows {
		if r.ID == "page-visible" && r.Job != jobs[0].ID {
			t.Fatalf("the objective's verdict is the reconcile's, not the old container's: %+v", r)
		}
	}
}

// A create resumed after a host reboot re-walks in the reconcile posture:
// containers that kept their data are not initialised or seeded twice,
// and the lab reaches ready.
func TestAResumedCreateKeepsTheDataItFinds(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	library := lab.DirLibrary(filepath.Join("testdata", "modules"))
	h.eng.opts.Library = library
	dir := t.TempDir()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: kept2, version: 1.0.0 }
services:
  web: { use: modules/init-web@1.0 }
  prometheus:
    image: docker.io/prom/prometheus@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    endpoints: [ { purpose: ui, port: 9090 }, { purpose: api, port: 9090 } ]
    readiness: { probe: { port: 9090, path: /-/ready }, typical: 100ms, budget: 10s }
seeds:
  warm: { generator: http-requests, count: 5, params: { service: prometheus, path: "/api/v1/query?query=up" } }
checkpoints:
  - id: web-up
    adapter: http
    params: { url: http://web:80/ }
    expect: { status: 200 }
    retries: { attempts: 1 }
`
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "kept2"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	if n := h.fake.Queries("pdr-kept2-prometheus"); n != 5 {
		t.Fatalf("the standing seed sent 5 queries, counted %d", n)
	}
	// The host reboots while the create is still recorded running at its
	// last rung: every container stops; the next start resumes the create.
	h.fake.Close()
	if err := runtime.Reboot(h.world); err != nil {
		t.Fatal(err)
	}
	resumed := *job
	resumed.State, resumed.Stage, resumed.Finished = state.JobRunning, "verifying", nil
	if err := h.store.PutJob(resumed); err != nil {
		t.Fatal(err)
	}
	h.open()
	h.eng.opts.Library = library
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	j := h.wait(job.ID)
	journal := journalOf(h, job.ID)
	if j.State != state.JobSucceeded {
		t.Fatalf("the resumed create: %+v\n%s", j, journal)
	}
	if !strings.Contains(journal, "init web skipped reconcile: the container restarted with its data") || !strings.Contains(journal, "standing seeds not re-run: warm") {
		t.Fatalf("a resumed create keeps the data it finds — init and standing seeds not run twice:\n%s", journal)
	}
	// The reopened fake counts from zero: a second seeding would show.
	if n := h.fake.Queries("pdr-kept2-prometheus"); n != 0 {
		t.Fatalf("no second seeding: %d queries", n)
	}
	if inst, _ := h.store.GetInstance("kept2"); inst.Stage != state.StageReady {
		t.Fatalf("ready again: stage %s\n%s", inst.Stage, journal)
	}
}

// saysRunning wraps a runtime so one container inspects as running even
// after the fake stopped it: a product whose container stays up while its
// readiness endpoint no longer answers.
type saysRunning struct {
	runtime.Runtime
	name string
}

func (s *saysRunning) Inspect(ctx context.Context, name string) (*runtime.ContainerState, error) {
	st, err := s.Runtime.Inspect(ctx, name)
	if st != nil && name == s.name {
		st.Running = true
	}
	return st, err
}

// The container adapter's healthy fact is the readiness probe answered
// now, on the live container: a container that keeps running while its
// product stops answering is not healthy, whatever the ladder recorded
// (lab.go:242).
func TestContainerHealthFollowsTheLiveProbe(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: health, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-healthy\n    adapter: container\n    params: { service: web }\n    expect: { healthy: true }\n    retries: { attempts: 1 }\n    hint: Is the web service healthy?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "health"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	if res, err := h.eng.RunCheckpoint(ctx, "health", "web-healthy", Socket); err != nil || res.Status != "pass" {
		t.Fatalf("a live, answering service is healthy: %+v %v", res, err)
	}
	// The product stops answering its readiness probe while the container
	// keeps running: the fake's listener goes away, the inspection still
	// says running, the ladder still says healthy.
	svc, _ := h.eng.Service("health", "web")
	if err := h.fake.Stop(ctx, svc.Container, 0); err != nil {
		t.Fatal(err)
	}
	h.eng.opts.Runtime = &saysRunning{Runtime: h.fake, name: svc.Container}
	res, err := h.eng.RunCheckpoint(ctx, "health", "web-healthy", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "fail" || !strings.Contains(res.Message, "healthy false") {
		t.Fatalf("healthy is the probe's answer now, not the ladder's record: %+v", res)
	}
}

// An instance whose secret store cannot be read is judged by nothing: a
// checkpoint run, a verify and a job's own failure record are refused —
// PDR-E412 — rather than produced with an empty redaction filter, which
// would persist observed values, messages and journal lines the filter
// never saw (lab.go:133).
func TestAnUnreadableSecretStoreRefusesEveryRecord(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: sealed, version: 1.0.0 }\nsecrets:\n  tok: { kind: token }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "sealed"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	rows0, _ := h.store.ListCheckpointResults("sealed")
	ev0, err := h.eng.Evidence("sealed", EvidenceFilter{}, Socket)
	if err != nil || len(rows0) != 1 || len(ev0) == 0 {
		t.Fatalf("the create judged and journaled: %+v %d %v", rows0, len(ev0), err)
	}
	// The secrets directory is replaced by a plain file — as root, a mode
	// change would refuse nothing — so the store cannot be listed and no
	// filter can be built.
	secretsDir := h.eng.secretStore("sealed").Dir()
	if err := os.RemoveAll(secretsDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretsDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := h.eng.RunCheckpoint(ctx, "sealed", "web-up", Socket)
	if err == nil || code(err) != pdr.CodeSecretStoreUnreadable || res != nil {
		t.Fatalf("a run with no filter must be refused, never judged: %+v %v", res, err)
	}
	rows1, _ := h.store.ListCheckpointResults("sealed")
	if len(rows1) != 1 || !rows1[0].At.Equal(rows0[0].At) {
		t.Fatalf("the refused run recorded a result: %+v", rows1)
	}
	if ev1, _ := h.eng.Evidence("sealed", EvidenceFilter{}, Socket); len(ev1) != len(ev0) {
		t.Fatalf("the refused run wrote evidence: %d entries, had %d", len(ev1), len(ev0))
	}
	job, err = h.eng.VerifyAs(ctx, "sealed", "", Socket)
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(job.ID)
	journal := journalOf(h, job.ID)
	if j.State != state.JobFailed || j.Error == nil || j.Error.Code != pdr.CodeSecretStoreUnreadable {
		t.Fatalf("the verify fails refused, its record the store's failure: %+v\n%s", j, journal)
	}
	if strings.Contains(journal, "checkpoint web-up") {
		t.Fatalf("nothing is judged or journaled without the filter:\n%s", journal)
	}
	if rows2, _ := h.store.ListCheckpointResults("sealed"); len(rows2) != 1 || !rows2[0].At.Equal(rows0[0].At) {
		t.Fatalf("the refused verify recorded a result: %+v", rows2)
	}
}

// A start finds a service's container replaced — removed, and another
// created and started under its name with the same labels while the
// engine was down. Its rows name a container that no longer exists, and
// every dial and route would refuse the replacement; the start reconciles
// the instance rather than leave it recorded ready and unusable (engine.go:1355).
func TestStartReconcilesAServiceReplacedWhileTheEngineWasDown(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: swapped, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "swapped"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	svc, err := h.eng.Service("swapped", "web")
	if err != nil || svc == nil || svc.ContainerID == "" {
		t.Fatalf("web records its container: %+v %v", svc, err)
	}
	recorded := svc.ContainerID
	// While the engine is down the container is removed, and another is
	// created and started under its name from the same spec: the same
	// labels, another identity, host ports of its own.
	spec := h.fake.Spec(svc.Container)
	if spec == nil {
		t.Fatal("the fake records the container's spec")
	}
	if err := h.fake.Remove(ctx, svc.Container); err != nil {
		t.Fatal(err)
	}
	if _, err := h.fake.Create(ctx, *spec); err != nil {
		t.Fatal(err)
	}
	if err := h.fake.Start(ctx, svc.Container); err != nil {
		t.Fatal(err)
	}
	replacement, _ := h.fake.Inspect(ctx, svc.Container)
	if replacement == nil || !replacement.Running || replacement.ID == recorded {
		t.Fatalf("the replacement runs under the name with another identity: %+v", replacement)
	}
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ := h.store.ListJobs("swapped")
	var reconcile *state.Job
	for i := range jobs {
		if jobs[i].Kind == "reconcile" {
			reconcile = &jobs[i]
		}
	}
	if reconcile == nil {
		t.Fatalf("a lab not running its recorded container is reconciled at start; jobs: %+v", jobs)
	}
	if j := h.wait(reconcile.ID); j.State != state.JobSucceeded {
		t.Fatalf("reconcile: %+v\n%s", j, journalOf(h, reconcile.ID))
	}
	svc, _ = h.eng.Service("swapped", "web")
	now, _ := h.fake.Inspect(ctx, svc.Container)
	if svc.ContainerID == recorded || now == nil || svc.ContainerID != now.ID || svc.Ports[80] == 0 || svc.Ports[80] != now.Ports[80] {
		t.Fatalf("the rows name the container that runs now: row %s ports %v, running %+v", svc.ContainerID, svc.Ports, now)
	}
	if inst, _ := h.store.GetInstance("swapped"); inst.Stage != state.StageReady {
		t.Fatalf("ready again after the reconcile: stage %s", inst.Stage)
	}
	if res, err := h.eng.RunCheckpoint(ctx, "swapped", "web-up", Socket); err != nil || res.Status != "pass" {
		t.Fatalf("the lab is usable again: %+v %v", res, err)
	}
	// Nothing to do on the next start: the rows are true again.
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if after, _ := h.store.ListJobs("swapped"); len(after) != len(jobs) {
		t.Fatalf("an idle start launched jobs: %+v", after)
	}
}

// The container adapter's healthy fact is attributed to the inspected
// container run: a probe answered by a listener that took the port after
// the container stopped — the window the target's dial closes — is not
// the service's health (lab.go:277).
func TestContainerHealthIsBoundToTheProbedRun(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: bound, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-healthy\n    adapter: container\n    params: { service: web }\n    expect: { healthy: true }\n    retries: { attempts: 1 }\n    hint: Is the web service healthy?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "bound"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	if res, err := h.eng.RunCheckpoint(ctx, "bound", "web-healthy", Socket); err != nil || res.Status != "pass" {
		t.Fatalf("a live, answering service is healthy: %+v %v", res, err)
	}
	svc, err := h.eng.Service("bound", "web")
	if err != nil || svc == nil || svc.Ports[80] == 0 {
		t.Fatalf("web publishes port 80: %+v %v", svc, err)
	}
	// Between the adapter's inspection and its probe the container stops
	// and an unrelated listener binds its freed host port, answering 200
	// to everything: the probe reaches that listener.
	var hits int64
	var mu sync.Mutex
	var impostor net.Listener
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		if impostor != nil {
			_ = impostor.Close()
		}
	}()
	probe := h.eng.opts.Probe
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool {
		if err := h.fake.Stop(ctx, svc.Container, 0); err != nil {
			t.Error(err)
			return false
		}
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(svc.Ports[80]))
		if err != nil {
			t.Errorf("the stopped container's port is free to take: %v", err)
			return false
		}
		mu.Lock()
		impostor = ln
		mu.Unlock()
		go func() {
			_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt64(&hits, 1)
				w.WriteHeader(200)
			}))
		}()
		return probe(ctx, url, expect)
	}
	res, err := h.eng.RunCheckpoint(ctx, "bound", "web-healthy", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt64(&hits); n != 1 {
		t.Fatalf("the probe reached the impostor once, got %d", n)
	}
	if res.Status != "fail" || !strings.Contains(res.Message, "healthy false") {
		t.Fatalf("an answer from whoever holds the port after the container stopped is nobody's health: %+v", res)
	}
}

// A secret store that lost a value — one declared file deleted, or the
// whole directory — is no filter either: the containers were configured
// with the value, the store no longer knows it, and a run, a verify or a
// job's journal line would otherwise persist product output the filter
// could not recognise. Every record is refused (PDR-E412), from the kind
// record a deleted file leaves, from what the engine generated, and after
// a restart from the plan alone — until the instance is destroyed, the one
// job that proceeds with the filter that can be built (lab.go:136).
func TestALostSecretValueRefusesEveryRecord(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: lost, version: 1.0.0 }\nsecrets:\n  tok: { kind: token }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "lost"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	store := h.eng.secretStore("lost")
	rows0, _ := h.store.ListCheckpointResults("lost")
	refused := func(when string) {
		t.Helper()
		res, err := h.eng.RunCheckpoint(ctx, "lost", "web-up", Socket)
		if err == nil || code(err) != pdr.CodeSecretStoreUnreadable || res != nil {
			t.Fatalf("%s: a run without tok's value must be refused, never judged: %+v %v", when, res, err)
		}
		if !strings.Contains(err.Error(), "tok") {
			t.Fatalf("%s: the refusal names the missing secret: %v", when, err)
		}
	}
	// One declared value deleted: its kind record remains.
	if err := os.Remove(store.Path("tok")); err != nil {
		t.Fatal(err)
	}
	refused("value file deleted")
	// The whole directory deleted: nothing on disk names tok; the engine
	// still knows what its secrets step generated.
	if err := os.RemoveAll(store.Dir()); err != nil {
		t.Fatal(err)
	}
	refused("directory removed")
	// And after a restart, from the plan of an instance whose containers
	// were configured with every declared value.
	h.open()
	refused("engine restarted")
	if rows1, _ := h.store.ListCheckpointResults("lost"); len(rows1) != 1 || !rows1[0].At.Equal(rows0[0].At) {
		t.Fatalf("a refused run recorded a result: %+v", rows1)
	}
	// A verify is refused before anything is evaluated — nothing regenerates
	// a value the containers were configured with.
	job, err = h.eng.VerifyAs(ctx, "lost", "", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobFailed || j.Error == nil || j.Error.Code != pdr.CodeSecretStoreUnreadable {
		t.Fatalf("the verify fails refused: %+v\n%s", j, journalOf(h, job.ID))
	}
	// Destroy is the remedy, and it proceeds.
	job, err = h.eng.DestroyAs(ctx, "lost", "lost", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("destroy proceeds with the filter that can be built: %+v\n%s", j, journalOf(h, job.ID))
	}
	if _, err := h.store.GetInstance("lost"); err == nil {
		t.Fatal("the instance is gone after the destroy")
	}
}

// The redaction filter's expectation is the history of what was generated,
// never the current plan: an authoring edit that declares a new secret
// adds nothing to expect until the next walk of the create path generates
// it — so after a restart a reset (or up, or reconcile) still journals its
// first step and generates the value, instead of refusing it before the
// secrets step for a value that never existed (lab.go:183).
func TestAnAddedSecretIsGeneratedAfterARestart(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	write := func(secrets string) {
		lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: grow, version: 1.0.0 }\nsecrets:\n" + secrets + "services:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
		if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("  tok: { kind: token }\n")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "grow"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	// The author declares a second secret; the engine restarts before any
	// job runs against the new declaration.
	write("  tok: { kind: token }\n  tok2: { kind: token }\n")
	h.open()
	job, err = h.eng.ResetAs(ctx, "grow", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("the reset generates the added secret instead of refusing its own first step: %+v\n%s", j, journalOf(h, job.ID))
	}
	store := h.eng.secretStore("grow")
	if v, err := store.Value("tok2"); err != nil || v == "" {
		t.Fatalf("tok2 is generated by the reset: %q %v", v, err)
	}
	if res, err := h.eng.RunCheckpoint(ctx, "grow", "web-up", Socket); err != nil || res.Status != "pass" {
		t.Fatalf("the lab is judged again with both values held: %+v %v", res, err)
	}
}

// A secret once generated stays expected until the instance is destroyed:
// an authoring edit that drops the declaration does not drop the value a
// container was configured with, so when the store then loses that value
// — the directory removed, its kind record with it — every record is still
// refused (PDR-E412) rather than persisted through a filter that never
// knew the value (lab.go:215).
func TestARemovedSecretStaysExpectedUntilDestroy(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	write := func(secrets string) {
		lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: shrink, version: 1.0.0 }\n" + secrets + "services:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
		if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("secrets:\n  tok: { kind: token }\n")
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "shrink"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	// The author drops the declaration and resets: the walk generates
	// nothing new, and tok's value stays in the store, still expected.
	write("")
	job, err = h.eng.ResetAs(ctx, "shrink", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("reset: %+v\n%s", j, journalOf(h, job.ID))
	}
	if res, err := h.eng.RunCheckpoint(ctx, "shrink", "web-up", Socket); err != nil || res.Status != "pass" {
		t.Fatalf("with tok's value still held the lab is judged: %+v %v", res, err)
	}
	// The store loses everything — value and kind record: the history
	// alone remembers tok, and the filter refuses without it.
	if err := os.RemoveAll(h.eng.secretStore("shrink").Dir()); err != nil {
		t.Fatal(err)
	}
	res, err := h.eng.RunCheckpoint(ctx, "shrink", "web-up", Socket)
	if err == nil || code(err) != pdr.CodeSecretStoreUnreadable || res != nil || !strings.Contains(err.Error(), "tok") {
		t.Fatalf("a run without tok's value must be refused, naming tok: %+v %v", res, err)
	}
	// Destroy — the remedy — proceeds, and takes the history with it.
	job, err = h.eng.DestroyAs(ctx, "shrink", "shrink", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("destroy: %+v\n%s", j, journalOf(h, job.ID))
	}
}

// A database from before the generated-secrets history existed holds none
// for what earlier releases generated: the next start brings every
// instance's history up to what its secret store shows — kind records and
// values present — while the store still has them, so a directory deleted
// later is still a lost value, refused, never an empty filter over
// containers that hold the old credentials (sqlite.go:102).
func TestAStartRemembersWhatAnOlderReleaseGenerated(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: legacy, version: 1.0.0 }\nsecrets:\n  tok: { kind: token }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	// The instance is created by an engine that records no history — the
	// release before the table existed.
	h.eng.opts.Store = &unrecordingStore{Store: h.store}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "legacy"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	if hist, _ := h.store.GeneratedSecrets("legacy"); len(hist) != 0 {
		t.Fatalf("the older release recorded no history: %v", hist)
	}
	// The upgraded engine starts on the same database and secret store.
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if hist, _ := h.store.GeneratedSecrets("legacy"); strings.Join(hist, ",") != "tok" {
		t.Fatalf("the start remembers what the store shows generated: %v", hist)
	}
	// The store is lost afterwards: the history alone remembers tok.
	if err := os.RemoveAll(h.eng.secretStore("legacy").Dir()); err != nil {
		t.Fatal(err)
	}
	res, err := h.eng.RunCheckpoint(ctx, "legacy", "web-up", Socket)
	if err == nil || code(err) != pdr.CodeSecretStoreUnreadable || res != nil || !strings.Contains(err.Error(), "tok") {
		t.Fatalf("a run without tok's value must be refused, naming tok: %+v %v", res, err)
	}
}

// unrecordingStore is a store from before the generated-secrets history:
// it records nothing a secrets step generated.
type unrecordingStore struct{ state.Store }

func (u *unrecordingStore) AddGeneratedSecrets(string, []string) error { return nil }

// The healthy rung is attributed to the container that was probed: a
// service that exits during its readiness wait, its host port taken by an
// unrelated listener that answers the probe, is a failed rung — never
// recorded healthy on another process's answer (the rule the container adapter and the connected rung apply).
func TestHealthyIsBoundToTheContainerThatAnswered(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: dying, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	impostor := &impostorOnProbe{t: t, fake: h.fake, container: "pdr-dying-web"}
	defer impostor.close()
	h.eng.opts.Probe = impostor.probe
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "dying"})
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(job.ID)
	journal := journalOf(h, job.ID)
	if strings.Contains(journal, "healthy web ok") {
		t.Fatalf("a probe answered by the impostor after the container stopped must not record healthy:\n%s", journal)
	}
	if j.State != state.JobFailed || j.Error == nil || !strings.Contains(j.Error.Message, "stopped during its readiness wait") {
		t.Fatalf("the create fails naming the container that stopped: %+v\n%s", j, journal)
	}
	if n := atomic.LoadInt64(&impostor.hits); n == 0 {
		t.Fatal("the impostor was never asked: the scenario did not happen")
	}
}

// impostorOnProbe answers the readiness probe as an unrelated listener on
// the container's freed host port: on the first probe it stops the
// container, binds its port, and serves 200 to everything.
type impostorOnProbe struct {
	t         *testing.T
	fake      *runtime.Fake
	container string
	once      sync.Once
	mu        sync.Mutex
	ln        net.Listener
	hits      int64
}

func (i *impostorOnProbe) probe(ctx context.Context, url string, expect int) bool {
	i.once.Do(func() {
		u, err := neturl.Parse(url)
		if err != nil {
			i.t.Error(err)
			return
		}
		if err := i.fake.Stop(ctx, i.container, 0); err != nil {
			i.t.Error(err)
			return
		}
		ln, err := net.Listen("tcp", "127.0.0.1:"+u.Port())
		if err != nil {
			i.t.Errorf("the stopped container's port is free to take: %v", err)
			return
		}
		i.mu.Lock()
		i.ln = ln
		i.mu.Unlock()
		go func() {
			_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt64(&i.hits, 1)
				w.WriteHeader(200)
			}))
		}()
	})
	return httpProbe(ctx, url, expect)
}

func (i *impostorOnProbe) close() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.ln != nil {
		_ = i.ln.Close()
	}
}

// The connected rung is attributed to the recorded container run, as the
// target's dial is: a service that exits after its readiness probe, its
// endpoint's host port taken by an unrelated listener, is a failed rung,
// named — never a connected one on the impostor's accept (lab.go:441).
func TestConnectedIsBoundToTheRecordedContainerRun(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: gone, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	// Between the healthy record and the connected rung the container
	// stops and an unrelated listener binds its freed ui port, accepting
	// every connection: the engine's own log line is the seam.
	var once sync.Once
	var mu sync.Mutex
	var impostor net.Listener
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		if impostor != nil {
			_ = impostor.Close()
		}
	}()
	h.eng.opts.Logf = func(format string, args ...any) {
		if !strings.Contains(fmt.Sprintf(format, args...), "healthy web ok") {
			return
		}
		once.Do(func() {
			svc, err := h.eng.Service("gone", "web")
			if err != nil || svc == nil || svc.Ports[80] == 0 {
				t.Errorf("web publishes port 80 at healthy: %+v %v", svc, err)
				return
			}
			if err := h.fake.Stop(ctx, svc.Container, 0); err != nil {
				t.Error(err)
				return
			}
			ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(svc.Ports[80]))
			if err != nil {
				t.Errorf("the stopped container's port is free to take: %v", err)
				return
			}
			mu.Lock()
			impostor = ln
			mu.Unlock()
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					_ = c.Close()
				}
			}()
		})
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "gone"})
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(job.ID)
	journal := journalOf(h, job.ID)
	if !strings.Contains(journal, "healthy web ok") {
		t.Fatalf("the scenario did not happen — web never became healthy:\n%s", journal)
	}
	if strings.Contains(journal, "connected web ok") {
		t.Fatalf("an accept by the impostor on the freed port must not make the service connected:\n%s", journal)
	}
	if j.State != state.JobFailed || j.Error == nil || !strings.Contains(j.Error.Cause, "not running its recorded container") {
		t.Fatalf("the create fails naming the stopped container: %+v\n%s", j, journal)
	}
}

// The connected rung is attributed to the run readiness was proven on: the
// same container restarted between its readiness proof and the rung keeps
// its id and its ports, but its run never passed readiness — an accept from
// it proves nothing, and the rung fails, named; a re-run proves readiness
// again (lab.go:452).
func TestConnectedRefusesARunThatNeverPassedReadiness(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: rerun, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	// Between the healthy record and the connected rung the container is
	// restarted from outside: the same id, the same ports, another run.
	var once sync.Once
	h.eng.opts.Logf = func(format string, args ...any) {
		if !strings.Contains(fmt.Sprintf(format, args...), "healthy web ok") {
			return
		}
		once.Do(func() {
			if err := h.fake.Stop(ctx, "pdr-rerun-web", 0); err != nil {
				t.Error(err)
				return
			}
			if err := h.fake.Start(ctx, "pdr-rerun-web"); err != nil {
				t.Error(err)
			}
		})
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "rerun"})
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(job.ID)
	journal := journalOf(h, job.ID)
	if !strings.Contains(journal, "healthy web ok") {
		t.Fatalf("the scenario did not happen — web never became healthy:\n%s", journal)
	}
	if strings.Contains(journal, "connected web ok") {
		t.Fatalf("a run that never passed readiness must not be connected:\n%s", journal)
	}
	if j.State != state.JobFailed || j.Error == nil || !strings.Contains(j.Error.Cause, "restarted after its readiness probe") {
		t.Fatalf("the create fails naming the restart: %+v\n%s", j, journal)
	}
	svc, _ := h.eng.Service("rerun", "web")
	st, _ := h.fake.Inspect(ctx, "pdr-rerun-web")
	if svc == nil || st == nil || svc.StartedAt == nil || st.StartedAt.Equal(*svc.StartedAt) {
		t.Fatalf("the row still records the run readiness was proven on, not the restart: row %v, running %v", svc.StartedAt, st.StartedAt)
	}
}

// A service that declares readiness but no endpoints is still held to its
// run at the connected rung: the recorded container is inspected once,
// endpoints or none, and a run that never passed readiness — the same
// container restarted after its proof — fails the rung instead of being
// treated as connected without a look (lab.go:462).
func TestConnectedValidatesTheRunWithoutEndpoints(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: mute, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	h.eng.opts.Logf = func(format string, args ...any) {
		if !strings.Contains(fmt.Sprintf(format, args...), "healthy web ok") {
			return
		}
		once.Do(func() {
			if err := h.fake.Stop(ctx, "pdr-mute-web", 0); err != nil {
				t.Error(err)
				return
			}
			if err := h.fake.Start(ctx, "pdr-mute-web"); err != nil {
				t.Error(err)
			}
		})
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "mute"})
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(job.ID)
	journal := journalOf(h, job.ID)
	if !strings.Contains(journal, "healthy web ok") {
		t.Fatalf("the scenario did not happen — web never became healthy:\n%s", journal)
	}
	if strings.Contains(journal, "connected web ok") {
		t.Fatalf("a run that never passed readiness must not be connected, endpoints or none:\n%s", journal)
	}
	if j.State != state.JobFailed || j.Error == nil || !strings.Contains(j.Error.Cause, "restarted after its readiness probe") {
		t.Fatalf("the create fails naming the restart: %+v\n%s", j, journal)
	}
}

// A start reconciles a service whose container was restarted while the
// engine was down: the same id, the same ports, another run — one that
// never passed readiness. The reconcile proves readiness again for the run
// that is running and records its start; the next start finds nothing to do
// (engine.go:1373).
func TestStartReconcilesAServiceRestartedWhileTheEngineWasDown(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: bounced, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n    hint: Is the web service answering on port 80?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "bounced"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	svc, err := h.eng.Service("bounced", "web")
	if err != nil || svc == nil || svc.StartedAt == nil {
		t.Fatalf("web records the run readiness was proven on: %+v %v", svc, err)
	}
	proven := *svc.StartedAt
	// While the engine is down the container is stopped and started again:
	// the same id, the same ports, another run.
	if err := h.fake.Stop(ctx, svc.Container, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.fake.Start(ctx, svc.Container); err != nil {
		t.Fatal(err)
	}
	restarted, _ := h.fake.Inspect(ctx, svc.Container)
	if restarted == nil || !restarted.Running || restarted.ID != svc.ContainerID || restarted.StartedAt.Equal(proven) {
		t.Fatalf("the restart keeps the id and starts a new run: %+v", restarted)
	}
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ := h.store.ListJobs("bounced")
	var reconcile *state.Job
	for i := range jobs {
		if jobs[i].Kind == "reconcile" {
			reconcile = &jobs[i]
		}
	}
	if reconcile == nil {
		t.Fatalf("a run that never passed readiness is reconciled at start; jobs: %+v", jobs)
	}
	if j := h.wait(reconcile.ID); j.State != state.JobSucceeded {
		t.Fatalf("reconcile: %+v\n%s", j, journalOf(h, reconcile.ID))
	}
	if journal := journalOf(h, reconcile.ID); !strings.Contains(journal, "healthy web ok") {
		t.Fatalf("readiness is proven again for the running run:\n%s", journal)
	}
	svc, _ = h.eng.Service("bounced", "web")
	now, _ := h.fake.Inspect(ctx, svc.Container)
	if svc.StartedAt == nil || now == nil || !svc.StartedAt.Equal(now.StartedAt) || svc.ContainerID != now.ID {
		t.Fatalf("the row records the run that runs now: row %v/%s, running %v/%s", svc.StartedAt, svc.ContainerID, now.StartedAt, now.ID)
	}
	if inst, _ := h.store.GetInstance("bounced"); inst.Stage != state.StageReady {
		t.Fatalf("ready again after the reconcile: stage %s", inst.Stage)
	}
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if after, _ := h.store.ListJobs("bounced"); len(after) != len(jobs) {
		t.Fatalf("an idle start launched jobs: %+v", after)
	}
}

// stallPull is a runtime whose pull of the exec image never answers until
// its context ends — a registry that hangs; every other pull is the fake's.
type stallPull struct{ *runtime.Fake }

func (s *stallPull) Pull(ctx context.Context, image string) error {
	if strings.Contains(image, "exec-conformance") {
		<-ctx.Done()
		return ctx.Err()
	}
	return s.Fake.Pull(ctx, image)
}

// The exec-seed budget bounds the pull and the user resolution as well as
// the container: a stalled registry cannot hold a create past it (seeds.go:153).
func TestAnExecSeedsPreparationIsBoundedByItsBudget(t *testing.T) {
	h := newHarness(t)
	h.eng.opts.Runtime = &stallPull{Fake: h.fake}
	old := execSeedBudget
	execSeedBudget = 300 * time.Millisecond
	t.Cleanup(func() { execSeedBudget = old })
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "playbooks"), 0o755)
	image := "docker.io/podaro/exec-conformance@sha256:" + strings.Repeat("e", 64)
	lab := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: stalled, version: 1.0.0 }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
seeds:
  orders: { generator: { exec: { image: IMAGE, args: [pass] } }, count: 1 }
checkpoints:
  - id: up
    adapter: container
    params: { service: web }
    expect: { state: running }
    retries: { attempts: 1 }
`
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(strings.ReplaceAll(lab, "IMAGE", image)), 0o644)
	start := time.Now()
	job, err := h.eng.Create(context.Background(), CreateRequest{Path: dir, Name: "stalled"})
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(job.ID)
	if j.State != state.JobFailed || j.Error == nil || j.Error.Code != pdr.CodeExecPull || !strings.Contains(j.Error.Cause, "deadline") {
		t.Fatalf("a stalled pull must fail the seed within its budget: %+v\n%s", j, journalOf(h, job.ID))
	}
	if took := time.Since(start); took > 8*time.Second {
		t.Fatalf("the create took %s against a seed budget of %s", took, execSeedBudget)
	}
}

// countInspect counts the inspections of one container — what a dial to
// the lab needs first (the ownership-checked path of round 16).
type countInspect struct {
	*runtime.Fake
	name string
	n    atomic.Int32
}

func (c *countInspect) Inspect(ctx context.Context, name string) (*runtime.ContainerState, error) {
	if name == c.name {
		c.n.Add(1)
	}
	return c.Fake.Inspect(ctx, name)
}

// A built-in seed is refused before its generator runs: with no filter to
// be built the seed must not touch the lab, and a retry must not inject
// again (seeds.go:99).
func TestABuiltInSeedIsRefusedBeforeItRuns(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "playbooks"), 0o755)
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: sealedseed, version: 1.0.0 }\nsecrets:\n  tok: { kind: token }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\nseeds:\n  probe: { generator: http-requests, count: 2, params: { service: web, path: / } }\ncheckpoints:\n  - id: web-up\n    adapter: http\n    params: { url: http://web:80/ }\n    expect: { status: 200 }\n    retries: { attempts: 1 }\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "sealedseed"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	// The secrets directory is replaced by a plain file — as root, a mode
	// change would refuse nothing — so no filter can be built.
	secretsDir := h.eng.secretStore("sealedseed").Dir()
	if err := os.RemoveAll(secretsDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretsDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	counter := &countInspect{Fake: h.fake, name: containerName("sealedseed", "web")}
	h.eng.opts.Runtime = counter
	sj, err := h.eng.SeedAs(ctx, "sealedseed", "probe", Socket)
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(sj.ID)
	if j.State != state.JobFailed || j.Error == nil || j.Error.Code != pdr.CodeSecretStoreUnreadable {
		t.Fatalf("the seed must be refused with PDR-E412: %+v\n%s", j, journalOf(h, sj.ID))
	}
	if n := counter.n.Load(); n != 0 {
		t.Fatalf("the generator touched the lab before the refusal: %d inspection(s) of the web container", n)
	}
}

// cutInitOutput answers the init helper's run with streams the cap cut
// inside a secret — the first bytes of the value at the very end — and
// leaves every other run to the fake.
type cutInitOutput struct {
	*runtime.Fake
	value func() string
	exit  int
}

func (c *cutInitOutput) Run(ctx context.Context, spec runtime.RunSpec) (*runtime.RunResult, error) {
	if spec.Name != initHelperName(spec.Labels[runtime.LabelInstance], strings.TrimPrefix(spec.Labels[runtime.LabelRun], "init-")) {
		return c.Fake.Run(ctx, spec)
	}
	v := c.value()
	now := time.Now().UTC()
	return &runtime.RunResult{ExitCode: c.exit, Started: now, Finished: now, Stdout: []byte("init said " + v[:len(v)-3]), StdoutTruncated: true, Stderr: []byte("helper warned " + v[:len(v)-4]), StderrTruncated: true}, nil
}

// The init helper's streams are trimmed of a value's trailing fragment
// before they are filtered when the cap cut them, as an exec run's are:
// nothing of the value reaches the journal, the evidence or the error
// (create.go:266).
func TestInitOutputIsTrimmedBeforeRedaction(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit int
	}{{"cutinit", 0}, {"cutinitfail", 1}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			h.eng.opts.Library = lab.DirLibrary(filepath.Join("testdata", "modules"))
			h.eng.opts.Runtime = &cutInitOutput{Fake: h.fake, exit: tc.exit, value: func() string { v, _ := h.eng.secretStore(tc.name).Value("tok"); return v }}
			dir := t.TempDir()
			body := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: " + tc.name + ", version: 1.0.0 }\nsecrets:\n  tok: { kind: token }\nservices:\n  web: { use: modules/init-web@1.0 }\n"
			_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644)
			job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: tc.name})
			if err != nil {
				t.Fatal(err)
			}
			j := h.wait(job.ID)
			if (tc.exit == 0) != (j.State == state.JobSucceeded) {
				t.Fatalf("job state %s for exit %d\n%s", j.State, tc.exit, journalOf(h, job.ID))
			}
			value, _ := h.eng.secretStore(tc.name).Value("tok")
			if len(value) < 16 {
				t.Fatalf("no generated value to look for (%d bytes)", len(value))
			}
			needle := value[:8]
			ev, _ := h.eng.Evidence(tc.name, EvidenceFilter{}, Socket)
			raw, _ := json.Marshal(ev)
			journal := journalOf(h, job.ID)
			jobErr := ""
			if j.Error != nil {
				jobErr = j.Error.Message + " " + j.Error.Cause + " " + j.Error.Next
			}
			if strings.Contains(string(raw), needle) || strings.Contains(journal, needle) || strings.Contains(jobErr, needle) {
				t.Fatalf("a fragment of the value leaked — evidence %v, journal %v, job error %v", strings.Contains(string(raw), needle), strings.Contains(journal, needle), strings.Contains(jobErr, needle))
			}
			if !strings.Contains(string(raw), "init said") {
				t.Fatalf("the helper's output is still journaled, minus the fragment")
			}
		})
	}
}

// An init helper left behind by an interrupted run — the engine stopped
// between podman create and the cleanup — holds the deterministic helper
// name; the next attempt removes the owned leftover before using the name
// again, and refuses a stranger under it (create.go:253).
// The fake refuses a run whose name is in use, as podman
// create does.
func TestAStaleInitHelperIsRemovedBeforeItsNameIsReused(t *testing.T) {
	initImage := "docker.io/curlimages/curl@sha256:" + strings.Repeat("c", 64)
	for _, tc := range []struct {
		name, owner string
		service     string // a service label makes the holder a service, never a helper (round 39)
		succeeds    bool
	}{{"stalehelper", "stalehelper", "", true}, {"heldhelper", "someone-else", "", false}, {"servicehelper", "servicehelper", "init-web", false}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			h.eng.opts.Library = lab.DirLibrary(filepath.Join("testdata", "modules"))
			if err := h.fake.Pull(ctx, initImage); err != nil {
				t.Fatal(err)
			}
			helper := initHelperName(tc.name, "web")
			labels := map[string]string{runtime.LabelInstance: tc.owner, runtime.LabelManaged: "true", runtime.LabelRun: "init-web"}
			if tc.service != "" {
				labels[runtime.LabelService] = tc.service
			}
			if _, err := h.fake.Create(ctx, runtime.ContainerSpec{Name: helper, Image: initImage, Labels: labels}); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			body := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: " + tc.name + ", version: 1.0.0 }\nservices:\n  web: { use: modules/init-web@1.0 }\n"
			_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644)
			job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: tc.name})
			if err != nil {
				t.Fatal(err)
			}
			j := h.wait(job.ID)
			if tc.succeeds {
				if j.State != state.JobSucceeded {
					t.Fatalf("the owned leftover must be removed and the create succeed: %+v\n%s", j, journalOf(h, job.ID))
				}
				if st, err := h.fake.Inspect(ctx, helper); err == nil && st != nil {
					t.Fatalf("the helper is cleaned up after its run, as always")
				}
				return
			}
			if j.State != state.JobFailed || j.Error == nil || !strings.Contains(j.Error.Message+j.Error.Cause, "does not own") {
				t.Fatalf("a container that is not this helper under the helper's name is refused: %+v\n%s", j, journalOf(h, job.ID))
			}
			if st, err := h.fake.Inspect(ctx, helper); err != nil || st == nil || st.Labels[runtime.LabelInstance] != tc.owner {
				t.Fatalf("the holder is never removed: %+v %v", st, err)
			}
		})
	}
}

// A service named like a helper is a service: web's init helper and the
// service init-web share no name, and the init step never removes a
// service container (create.go:256).
func TestAServiceNamedLikeAHelperIsNeverRemoved(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.opts.Library = lab.DirLibrary(filepath.Join("testdata", "modules"))
	dir := t.TempDir()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: twins, version: 1.0.0 }
services:
  web: { use: modules/init-web@1.0 }
  init-web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
`
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "twins"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	st, err := h.fake.Inspect(ctx, containerName("twins", "init-web"))
	if err != nil || st == nil || !st.Running || st.Labels[runtime.LabelService] != "init-web" {
		t.Fatalf("the init-web service container must survive web's init: %+v %v", st, err)
	}
	if initHelperName("twins", "web") == containerName("twins", "init-web") {
		t.Fatal("the helper's name must never spell a service container's")
	}
}

// Two instances never share a network: foo's internal network and foo-int's
// primary network are different names (lab.go:244).
func TestInstanceNamesNeverShareANetwork(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: NAME, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\n"
	for _, name := range []string{"foo", "foo-int"} {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(strings.ReplaceAll(lab, "NAME", name)), 0o644)
		job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: name})
		if err != nil {
			t.Fatal(err)
		}
		if j := h.wait(job.ID); j.State != state.JobSucceeded {
			t.Fatalf("create %s: %+v\n%s", name, j, journalOf(h, job.ID))
		}
	}
	if internalNetworkName("foo") == "pdr-foo-int" || !h.fake.Internal(internalNetworkName("foo")) || h.fake.Internal("pdr-foo-int") {
		t.Fatalf("foo's internal network %q must not be foo-int's primary network", internalNetworkName("foo"))
	}
}

// swapOnRemove is the race between the init step's inspection of a stale
// helper and its removal: on the first removal of the helper, another
// process has replaced the container under the helper's name (create.go:265).
type swapOnRemove struct {
	runtime.Runtime
	fake    *runtime.Fake
	image   string
	mu      sync.Mutex
	targets map[string]string // name → the id an inspection saw before the swap
	swapped map[string]bool
}

func (s *swapOnRemove) Remove(ctx context.Context, ref string) error {
	s.mu.Lock()
	for name, id := range s.targets {
		if (ref == name || ref == id) && !s.swapped[name] {
			s.swapped[name] = true
			s.mu.Unlock()
			_ = s.fake.Remove(ctx, name)
			_, _ = s.fake.Create(ctx, runtime.ContainerSpec{Name: name, Image: s.image, Labels: map[string]string{runtime.LabelInstance: "someone-else", runtime.LabelManaged: "true"}})
			return s.Runtime.Remove(ctx, ref)
		}
	}
	s.mu.Unlock()
	return s.Runtime.Remove(ctx, ref)
}

func (s *swapOnRemove) didSwap(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.swapped[name]
}

// A stale helper is removed by the id its inspection saw, never by its
// name: a container another process placed under the name between the
// inspection and the removal is not the one inspected, so it stands, and
// the helper's run then refuses the name in use — the create fails, and
// nothing that is not Podaro's own is removed (create.go:265).
func TestAHelperReplacedAfterItsInspectionIsNeverRemoved(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.eng.opts.Library = lab.DirLibrary(filepath.Join("testdata", "modules"))
	initImage := "docker.io/curlimages/curl@sha256:" + strings.Repeat("c", 64)
	if err := h.fake.Pull(ctx, initImage); err != nil {
		t.Fatal(err)
	}
	helper := initHelperName("swapped", "web")
	staleID, err := h.fake.Create(ctx, runtime.ContainerSpec{Name: helper, Image: initImage, Labels: map[string]string{runtime.LabelInstance: "swapped", runtime.LabelManaged: "true", runtime.LabelRun: "init-web"}})
	if err != nil {
		t.Fatal(err)
	}
	swap := &swapOnRemove{Runtime: h.eng.opts.Runtime, fake: h.fake, image: initImage, targets: map[string]string{helper: staleID}, swapped: map[string]bool{}}
	h.eng.opts.Runtime = swap
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte("apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: swapped, version: 1.0.0 }\nservices:\n  web: { use: modules/init-web@1.0 }\n"), 0o644)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "swapped"})
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(job.ID)
	if !swap.didSwap(helper) {
		t.Fatalf("the race never happened: the stale helper was not removed at all: %+v\n%s", j, journalOf(h, job.ID))
	}
	st, ierr := h.fake.Inspect(ctx, helper)
	if ierr != nil || st == nil || st.Labels[runtime.LabelInstance] != "someone-else" {
		t.Fatalf("the container that took the helper's name must stand: %+v %v (job %+v)\n%s", st, ierr, j, journalOf(h, job.ID))
	}
	if j.State != state.JobFailed || j.Error == nil || !strings.Contains(j.Error.Message+j.Error.Cause, "already in use") {
		t.Fatalf("the helper's run must refuse the name in use: %+v\n%s", j, journalOf(h, job.ID))
	}
}

// Every removal the engine makes after an inspection names the id the
// inspection saw — a service container at destroy, a leftover the sweep
// found — so a container another process placed under the name meanwhile
// stands, and the destroy still succeeds: nothing of the instance remains
// (round 45 re-read: D150's rule at every removal, not only the helper's).
func TestDestroyRemovesOnlyWhatItInspected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "swept"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	image := "docker.io/library/busybox@sha256:" + strings.Repeat("a", 64)
	if err := h.fake.Pull(ctx, image); err != nil {
		t.Fatal(err)
	}
	web := containerName("swept", "web")
	webSt, err := h.fake.Inspect(ctx, web)
	if err != nil || webSt == nil {
		t.Fatalf("web: %+v %v", webSt, err)
	}
	// A leftover a crashed run left, labeled for the instance: the sweep's.
	leftover := "pdr-swept-run-deadbeef"
	leftID, err := h.fake.Create(ctx, runtime.ContainerSpec{Name: leftover, Image: image, Labels: map[string]string{runtime.LabelInstance: "swept", runtime.LabelManaged: "true", runtime.LabelRun: leftover}})
	if err != nil {
		t.Fatal(err)
	}
	swap := &swapOnRemove{Runtime: h.eng.opts.Runtime, fake: h.fake, image: image, targets: map[string]string{web: webSt.ID, leftover: leftID}, swapped: map[string]bool{}}
	h.eng.opts.Runtime = swap
	d, err := h.eng.Destroy(ctx, "swept", "swept")
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(d.ID)
	for _, name := range []string{web, leftover} {
		if !swap.didSwap(name) {
			t.Fatalf("%s: the race never happened: %+v\n%s", name, j, journalOf(h, d.ID))
		}
		if st, err := h.fake.Inspect(ctx, name); err != nil || st == nil || st.Labels[runtime.LabelInstance] != "someone-else" {
			t.Fatalf("%s: the container that took the name must stand: %+v %v (job %+v)\n%s", name, st, err, j, journalOf(h, d.ID))
		}
	}
	if j.State != state.JobSucceeded {
		t.Fatalf("nothing of the instance remains, so the destroy succeeds: %+v\n%s", j, journalOf(h, d.ID))
	}
}

// startByRef records what the engine hands the runtime's Start.
type startByRef struct {
	runtime.Runtime
	mu   sync.Mutex
	refs []string
}

func (s *startByRef) Start(ctx context.Context, ref string) error {
	s.mu.Lock()
	s.refs = append(s.refs, ref)
	s.mu.Unlock()
	return s.Runtime.Start(ctx, ref)
}

// A service is started by the id its create answered and its row records,
// never by the name another process may reuse after removing the
// container (the service-container instance of the one-shot run's rule).
func TestAServiceIsStartedByItsRecordedId(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	starts := &startByRef{Runtime: h.eng.opts.Runtime}
	h.eng.opts.Runtime = starts
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "byid"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	rows, _ := h.store.ListServices("byid")
	if len(rows) != 1 || rows[0].ContainerID == "" {
		t.Fatalf("the row records the container's id: %+v", rows)
	}
	starts.mu.Lock()
	defer starts.mu.Unlock()
	if len(starts.refs) == 0 {
		t.Fatal("the service was never started")
	}
	for _, ref := range starts.refs {
		if ref != rows[0].ContainerID || ref == rows[0].Container {
			t.Fatalf("a start must name the recorded id, never the name: %q (id %q, name %q)", ref, rows[0].ContainerID, rows[0].Container)
		}
	}
}

// inspectAround records what the engine hands the runtime's Inspect right
// after a service's create and right after its start.
type inspectAround struct {
	runtime.Runtime
	mu                      sync.Mutex
	created, started        bool
	afterCreate, afterStart []string
}

func (r *inspectAround) Create(ctx context.Context, spec runtime.ContainerSpec) (string, error) {
	id, err := r.Runtime.Create(ctx, spec)
	r.mu.Lock()
	r.created = true
	r.mu.Unlock()
	return id, err
}

func (r *inspectAround) Start(ctx context.Context, ref string) error {
	r.mu.Lock()
	r.started = true
	r.mu.Unlock()
	return r.Runtime.Start(ctx, ref)
}

func (r *inspectAround) Inspect(ctx context.Context, ref string) (*runtime.ContainerState, error) {
	r.mu.Lock()
	switch {
	case r.started && len(r.afterStart) == 0:
		r.afterStart = append(r.afterStart, ref)
	case r.created && !r.started:
		r.afterCreate = append(r.afterCreate, ref)
	}
	r.mu.Unlock()
	return r.Runtime.Inspect(ctx, ref)
}

// After a service's create the engine inspects the container by the id
// the create answered and the row records — before the start and right
// after it — never by the name a container another process placed there
// meanwhile would answer to, so a replacement's state and ports are never
// taken for this service's (engine.go:2081).
func TestAServiceIsInspectedByItsRecordedIdAroundItsStart(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	around := &inspectAround{Runtime: h.eng.opts.Runtime}
	h.eng.opts.Runtime = around
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "byidi"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	rows, _ := h.store.ListServices("byidi")
	if len(rows) != 1 || rows[0].ContainerID == "" {
		t.Fatalf("the row records the container's id: %+v", rows)
	}
	around.mu.Lock()
	defer around.mu.Unlock()
	if len(around.afterCreate) == 0 || len(around.afterStart) == 0 {
		t.Fatalf("the engine inspects after the create and after the start: %v %v", around.afterCreate, around.afterStart)
	}
	for _, ref := range append(append([]string{}, around.afterCreate...), around.afterStart...) {
		if ref != rows[0].ContainerID {
			t.Fatalf("an inspection around the start must name the recorded id, never the name: %q (id %q)", ref, rows[0].ContainerID)
		}
	}
}

// An inspection after the readiness probe that the runtime cannot answer
// is the checkpoint's error, never a health value: `healthy: false` must
// not pass, nor `healthy: true` fail, on a question the engine could not
// answer (lab.go:400).
func TestAFailedPostProbeInspectionIsAnError(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: probed, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-healthy\n    adapter: container\n    params: { service: web }\n    expect: { healthy: true }\n    retries: { attempts: 1 }\n    hint: Is the web service healthy?\n  - id: web-unhealthy\n    class: objective\n    adapter: container\n    params: { service: web }\n    expect: { healthy: false }\n    retries: { attempts: 1 }\n    hint: Is the web service down?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "probed"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	// The runtime answers the inspection before the probe and refuses the
	// one after it.
	failing := &inspectFails{Runtime: h.fake}
	h.eng.opts.Runtime = failing
	probe := h.eng.opts.Probe
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool {
		ok := probe(ctx, url, expect)
		failing.fail.Store(true)
		return ok
	}
	for _, id := range []string{"web-healthy", "web-unhealthy"} {
		failing.fail.Store(false)
		res, err := h.eng.RunCheckpoint(ctx, "probed", id, Socket)
		if err != nil {
			t.Fatal(err)
		}
		if res.Status != "error" || res.Error == nil || res.Error.Code != pdr.CodeCheckpointError || !strings.Contains(res.Error.Cause, "after its probe") {
			t.Fatalf("%s: an inspection the runtime cannot answer is an error, never a health value: %+v", id, res)
		}
	}
}

// inspectFails is a runtime whose Inspect refuses while fail is set.
type inspectFails struct {
	runtime.Runtime
	fail atomic.Bool
}

func (r *inspectFails) Inspect(ctx context.Context, ref string) (*runtime.ContainerState, error) {
	if r.fail.Load() {
		return nil, errors.New("the runtime did not answer")
	}
	return r.Runtime.Inspect(ctx, ref)
}

// A readiness probe that consumes the attempt's time answered nothing:
// the container checkpoint times out (PDR-E401) rather than record an
// unhealthy service it never observed — `healthy: false` must not pass on
// a probe that never answered (lab.go:407).
func TestAProbeThatOutlivesTheAttemptIsATimeout(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: slowprobe, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: web-down\n    class: objective\n    adapter: container\n    params: { service: web }\n    expect: { healthy: false }\n    timeout: 300ms\n    retries: { attempts: 1 }\n    hint: Is the web service down?\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "slowprobe"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	// The probe blocks until the attempt's context ends, then reports
	// nothing: the service was never observed.
	h.eng.opts.Probe = func(ctx context.Context, url string, expect int) bool {
		<-ctx.Done()
		return false
	}
	res, err := h.eng.RunCheckpoint(ctx, "slowprobe", "web-down", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "error" || res.Error == nil || res.Error.Code != pdr.CodeCheckpointTimeout {
		t.Fatalf("a probe that outlived the attempt is a timeout, never healthy false: %+v", res)
	}
}

// An attestation whose record a concurrent machine run passed on the way
// used to be discarded by the freshness check — its start was the
// earlier one — leaving the machine failure as the latest result against
// the contract that an attestation stands until reset (checkpoints.go:350).
// A human's confirmation is never
// the older observation, and the freshness mark never moves back.
func TestAnAttestationStandsOverAConcurrentRun(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	tpl := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: att, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: confirmed\n    adapter: attest\n    class: objective\n    params: { prompt: \"Did you look at the page?\" }\n    retries: { attempts: 1 }\n    hint: Open the page and confirm.\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "att"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	rowOf := func() state.CheckpointResult {
		rows, _ := h.store.ListCheckpointResults("att")
		for _, r := range rows {
			if r.ID == "confirmed" {
				return r
			}
		}
		t.Fatal("confirmed has a row")
		return state.CheckpointResult{}
	}
	// The attestation's ticket is taken, then a machine run of the same
	// checkpoint records first (it takes a later ticket). No sleep is
	// needed now that order is a counter, not a clock (round 69).
	attestSeq := h.eng.evalTicket()
	if res, err := h.eng.RunCheckpoint(ctx, "att", "confirmed", Socket); err != nil || res.Status != "fail" {
		t.Fatalf("a machine run of an unattested attest checkpoint fails: %+v %v", res, err)
	}
	lv, err := h.eng.instanceView("att")
	if err != nil {
		t.Fatal(err)
	}
	var cp lab.FlatCheckpoint
	for _, c := range lv.checkpoints {
		if c.ID == "confirmed" {
			cp = c
		}
	}
	res := verify.Result{Status: verify.StatusAttested, Observed: map[string]any{"attested": true, "by": "looked"}, Expected: map[string]any{"attested": true}, Message: "looked"}
	rec, err := h.eng.record(lv, cp, res, "", attestSeq)
	if err != nil {
		t.Fatal(err)
	}
	if rec.superseded || rec.latest.Status != "attested" {
		t.Fatalf("the attestation stands over the concurrent machine run: superseded=%v latest=%+v", rec.superseded, rec.latest)
	}
	if r := rowOf(); r.Status != "attested" {
		t.Fatalf("the latest result is the attestation: %+v", r)
	}
	// The mark did not move back: a machine evaluation begun before the
	// run above is still the older observation.
	if res, err := h.eng.RunCheckpoint(ctx, "att", "confirmed", Socket); err != nil || res.Status != "attested" {
		t.Fatalf("a later run returns the standing attestation: %+v %v", res, err)
	}
}

// An attestation begun before a reset cleared the results belongs to the
// generation that reset ended: recorded after it, it stays in evidence
// only, and the post-reset "awaiting" stands — round 60's exemption from
// freshness would have let it overwrite the reset's result (checkpoints.go:338).
// One begun after the reset stands.
func TestAnAttestationBegunBeforeAResetDoesNotSurviveIt(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	tpl := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: att, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: confirmed\n    adapter: attest\n    class: objective\n    params: { prompt: \"Did you look at the page?\" }\n    retries: { attempts: 1 }\n    hint: Open the page and confirm.\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "att"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	rowOf := func() state.CheckpointResult {
		rows, _ := h.store.ListCheckpointResults("att")
		for _, r := range rows {
			if r.ID == "confirmed" {
				return r
			}
		}
		t.Fatal("confirmed has a row")
		return state.CheckpointResult{}
	}
	// The attestation's ticket is captured, then a reset runs to
	// completion and turns the generation past it.
	attestSeq := h.eng.evalTicket()
	rj, err := h.eng.ResetAs(ctx, "att", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(rj.ID); j.State != state.JobSucceeded {
		t.Fatalf("reset: %+v\n%s", j, journalOf(h, rj.ID))
	}
	if r := rowOf(); r.Status != "fail" {
		t.Fatalf("after the reset the checkpoint awaits its human: %+v", r)
	}
	lv, err := h.eng.instanceView("att")
	if err != nil {
		t.Fatal(err)
	}
	var cp lab.FlatCheckpoint
	for _, c := range lv.checkpoints {
		if c.ID == "confirmed" {
			cp = c
		}
	}
	res := verify.Result{Status: verify.StatusAttested, Observed: map[string]any{"attested": true, "by": "late"}, Expected: map[string]any{"attested": true}, Message: "late"}
	rec, err := h.eng.record(lv, cp, res, "", attestSeq)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.superseded || rec.latest.Status != "fail" {
		t.Fatalf("an attestation begun before the reset stays in evidence only: superseded=%v latest=%+v", rec.superseded, rec.latest)
	}
	if r := rowOf(); r.Status != "fail" {
		t.Fatalf("the reset's result stands: %+v", r)
	}
	// A confirmation given after the reset stands.
	if res, err := h.eng.Attest(ctx, "att", "confirmed", "looked again", Socket); err != nil || res.Status != "attested" {
		t.Fatalf("a post-reset attestation: %+v %v", res, err)
	}
	if r := rowOf(); r.Status != "attested" {
		t.Fatalf("a post-reset attestation is the latest result: %+v", r)
	}
}

// An attestation held between its guards and its record while a reset
// runs to completion began before that reset: it stays in evidence only
// and the reset's result stands — the start used to be taken after the
// guard, so the held request read as post-reset (checkpoints.go:535).
// Attest answers the standing result.
// An exec checkpoint whose params carry a key the adapter does not read
// — `arguments` for `args` — is refused before anything is pulled or
// run: the extension would otherwise run without its authored
// configuration and answer a verdict nobody asked for.
// The validator refuses the same at file:line; the engine
// refuses it for a definition that reaches the hook by any other road.
func TestAnExecCheckpointWithAParameterTheAdapterSkipsIsRefused(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	image := "docker.io/podaro/exec-conformance@sha256:" + strings.Repeat("e", 64)
	tpl := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: judged, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: judged\n    adapter: exec\n    params: { image: " + image + ", args: [pass] }\n    retries: { attempts: 1 }\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "judged"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	lv, err := h.eng.instanceView("judged")
	if err != nil {
		t.Fatal(err)
	}
	cp := lab.FlatCheckpoint{Checkpoint: lab.Checkpoint{ID: "typo", Adapter: "exec", Params: map[string]any{"image": image, "arguments": []any{"fail"}}, Retries: &lab.Retries{Attempts: 1}}, ResolvedClass: "objective"}
	res := h.eng.execHook(lv)(ctx, cp, time.Second)
	if res.Status != verify.StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointError || !strings.Contains(res.Error.Message, "params.arguments") {
		t.Fatalf("a parameter the adapter would skip is refused, never run without: %+v", res)
	}
}

// An attestation a reset outran, when the reset's re-create failed before
// it recorded anything for the checkpoint: the confirmation is kept in
// evidence only and nothing stands, so the attest answers an error naming
// the evidence — never `attested`, which the checkpoint list does not
// show.
func TestAnAttestationOutrunByAFailedResetIsNotAnsweredAttested(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	tpl := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: att, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: confirmed\n    adapter: attest\n    class: objective\n    params: { prompt: \"Did you look at the page?\" }\n    retries: { attempts: 1 }\n    hint: Open the page and confirm.\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "att"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	held := make(chan struct{})
	released := make(chan struct{})
	beforeAttestRecord = func(string) { close(held); <-released }
	t.Cleanup(func() { beforeAttestRecord = nil })
	type answer struct {
		res *state.CheckpointResult
		err error
	}
	done := make(chan answer, 1)
	go func() {
		res, err := h.eng.Attest(ctx, "att", "confirmed", "looked", Socket)
		done <- answer{res, err}
	}()
	<-held
	beforeAttestRecord = nil
	// The authoring directory grows a EULA-gated service: the reset's own
	// read of the lab is fine (the licenses list matches), the results are
	// cleared, and the re-create fails at the license gate — before it
	// records a row for any checkpoint.
	grown := strings.Replace(tpl, "checkpoints:\n", "  gated:\n    image: docker.io/acme/gated@sha256:"+strings.Repeat("a", 64)+"\n    eula: { id: acme-terms, name: Acme Terms, url: https://acme.example/terms }\nlicenses: [acme-terms]\ncheckpoints:\n", 1)
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(grown), 0o644); err != nil {
		t.Fatal(err)
	}
	rj, err := h.eng.ResetAs(ctx, "att", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(rj.ID); j.State != state.JobFailed || j.Error == nil || j.Error.Code != pdr.CodeLicenseRequired {
		t.Fatalf("the reset fails at the license gate after clearing the results: %+v\n%s", j, journalOf(h, rj.ID))
	}
	if rows, _ := h.store.ListCheckpointResults("att"); len(rows) != 0 {
		t.Fatalf("nothing stands after the failed reset: %+v", rows)
	}
	close(released)
	a := <-done
	if a.err == nil {
		t.Fatalf("an attestation nothing stands for is not answered attested: %+v", a.res)
	}
	var pe *pdr.Error
	if !errors.As(a.err, &pe) || pe.Code != pdr.CodeInstanceBusy || !strings.HasPrefix(pe.Evidence, "/api/v1alpha1/instances/att/evidence/ev_") {
		t.Fatalf("the answer names the evidence the confirmation is kept in: %v", a.err)
	}
	cps, err := h.eng.Checkpoints("att", Socket)
	if err != nil {
		t.Fatal(err)
	}
	for _, cp := range cps {
		if cp.ID == "confirmed" && cp.Result != nil {
			t.Fatalf("the checkpoint is pending, not attested: %+v", cp.Result)
		}
	}
}

// A confirmation of a condition never shown is not recorded: once the
// authoring directory's attest checkpoint no longer names a prompt the
// adapter can read (`promt`), `POST …/attest` refuses and nothing is
// attested — the definition is read as the adapter reads it, before any
// row is written.
func TestAMalformedAttestDefinitionIsRefused(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	tpl := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: att, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: confirmed\n    adapter: attest\n    class: objective\n    params: { prompt: \"Did you look at the page?\" }\n    retries: { attempts: 1 }\n    hint: Open the page and confirm.\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "att"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	// The author mistypes the prompt's key: the checkpoint now names no
	// condition the adapter can read.
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(strings.Replace(tpl, "params: { prompt:", "params: { promt:", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if res, err := h.eng.Attest(ctx, "att", "confirmed", "looked", Socket); err == nil {
		t.Fatalf("a confirmation of a condition never shown was recorded: %+v", res)
	}
	rows, _ := h.store.ListCheckpointResults("att")
	for _, r := range rows {
		if r.ID == "confirmed" && r.Status == "attested" {
			t.Fatalf("nothing is attested: %+v", r)
		}
	}
}

func TestAnAttestationHeldAcrossAResetStaysInEvidenceOnly(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	tpl := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: att, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: confirmed\n    adapter: attest\n    class: objective\n    params: { prompt: \"Did you look at the page?\" }\n    retries: { attempts: 1 }\n    hint: Open the page and confirm.\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "att"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	rowOf := func() state.CheckpointResult {
		rows, _ := h.store.ListCheckpointResults("att")
		for _, r := range rows {
			if r.ID == "confirmed" {
				return r
			}
		}
		t.Fatal("confirmed has a row")
		return state.CheckpointResult{}
	}
	held := make(chan struct{})
	released := make(chan struct{})
	beforeAttestRecord = func(string) { close(held); <-released }
	t.Cleanup(func() { beforeAttestRecord = nil })
	type answer struct {
		res *state.CheckpointResult
		err error
	}
	done := make(chan answer, 1)
	go func() {
		res, err := h.eng.Attest(ctx, "att", "confirmed", "looked", Socket)
		done <- answer{res, err}
	}()
	<-held
	beforeAttestRecord = nil // the reset's own writes are not held
	rj, err := h.eng.ResetAs(ctx, "att", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(rj.ID); j.State != state.JobSucceeded {
		t.Fatalf("reset: %+v\n%s", j, journalOf(h, rj.ID))
	}
	close(released)
	a := <-done
	if a.err != nil {
		t.Fatal(a.err)
	}
	if a.res.Status != "fail" {
		t.Fatalf("Attest answers the standing result — the reset's awaiting row, not the held confirmation: %+v", a.res)
	}
	if r := rowOf(); r.Status != "fail" {
		t.Fatalf("the reset's result stands; the held attestation is in evidence only: %+v", r)
	}
}
