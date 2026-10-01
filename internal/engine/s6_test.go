// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The S6 acceptance at engine level (plan S6; spec 0001 §1; User Manual
// §2): `up` on grafana-prometheus-intro reaches ready honestly on the
// fake's products — four baselines green, two objectives red, secrets
// generated and rendered, files copied in, evidence recording every run;
// an objective flips green when its condition is made true by hand; the
// seed the step names runs on demand; reset returns to a verified
// baseline and clears objective progress while evidence keeps the history.
func TestSmallTemplateReachesReady(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Template: "grafana-prometheus-intro", Name: "intro"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	v, err := h.eng.View("intro", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if v.Ladder.Stage != string(state.StageReady) || v.Ladder.Condensed != "●●●●●●●" || v.Ladder.Label != "ready" {
		t.Fatalf("ladder: %+v", v.Ladder)
	}
	if v.Checkpoints.Baseline.Passed != 4 || v.Checkpoints.Baseline.Total != 4 || v.Checkpoints.Objective.Passed != 0 || v.Checkpoints.Objective.Failed != 2 || v.Checkpoints.Objective.Total != 2 {
		t.Fatalf("tally must read baseline 4/4 · objectives 0/2: %+v", v.Checkpoints)
	}
	journal := journalOf(h, job.ID)
	for _, want := range []string{"secrets ok 1 declared · generated grafana", "init grafana skipped", "init prometheus skipped", "connected grafana ok ui :3000", "connected prometheus ok ui :9090, api :9090",
		"seeded ok no standing seeds · step actions run when pressed: query-load", "checkpoint prometheus-ready pass", "checkpoint grafana-healthy pass", "checkpoint self-scrape-up pass", "checkpoint grafana-scraped pass",
		"checkpoint traffic-observed fail", "checkpoint dashboard-exists fail", "verified ok baseline 4/4 · objectives 0/2", "ready ok"} {
		if !strings.Contains(journal, want) {
			t.Errorf("journal lacks %q:\n%s", want, journal)
		}
	}
	if strings.Contains(journal, pdr.CodeObjectiveGreenAtCreate) {
		t.Fatalf("no objective may be green at create:\n%s", journal)
	}
	// Secrets: generated once, 0600, rendered into the env file — and the
	// fake Grafana only accepts the rendered password.
	secretPath := filepath.Join(h.dir, "instances", "intro", "secrets", "grafana")
	password, err := os.ReadFile(secretPath)
	if err != nil || len(password) != 24 {
		t.Fatalf("secret: %q %v", password, err)
	}
	if fi, _ := os.Stat(secretPath); fi.Mode().Perm() != 0o600 {
		t.Fatalf("secret mode %o", fi.Mode().Perm())
	}
	envRaw, _ := os.ReadFile(filepath.Join(h.dir, "instances", "intro", "env", "grafana.env"))
	if !strings.Contains(string(envRaw), "GF_SECURITY_ADMIN_PASSWORD="+string(password)+"\n") || strings.Contains(string(envRaw), "${secret") {
		t.Fatalf("env rendering: %q", envRaw)
	}
	// Files were copied into both containers (content hashed, never stored
	// by the fake).
	if files := h.fake.Files("pdr-intro-grafana"); len(files) != 1 || files[0].Path != "/etc/grafana/provisioning/datasources/prometheus.yaml" {
		t.Fatalf("grafana files: %+v", files)
	}
	if files := h.fake.Files("pdr-intro-prometheus"); len(files) != 1 || files[0].Path != "/etc/prometheus/prometheus.yml" || files[0].Mode != 0o644 {
		t.Fatalf("prometheus files: %+v", files)
	}
	// Both containers joined the internal network beside the lab network.
	if spec := h.fake.Spec("pdr-intro-grafana"); spec == nil || spec.Network != "pdr-intro" || strings.Join(spec.Networks, ",") != "pdr-intro_int" {
		t.Fatalf("networks: %+v", spec)
	}
	if !h.fake.Internal("pdr-intro_int") {
		t.Fatal("the second network must be internal")
	}
	// The checkpoints surface: definitions with their latest results.
	cps, err := h.eng.Checkpoints("intro", Socket)
	if err != nil || len(cps) != 6 {
		t.Fatalf("checkpoints: %+v %v", cps, err)
	}
	byID := map[string]CheckpointView{}
	for _, cp := range cps {
		byID[cp.ID] = cp
	}
	if r := byID["dashboard-exists"].Result; r == nil || r.Status != "fail" || r.Hint == "" || !strings.Contains(r.Message, "no such element") || r.Evidence == "" || r.Job != job.ID {
		t.Fatalf("dashboard-exists at create: %+v", r)
	}
	if r := byID["traffic-observed"].Result; r == nil || r.Status != "fail" || !strings.Contains(r.Message, "expected ≥ 200") {
		t.Fatalf("traffic-observed at create: %+v", r)
	}
	if r := byID["self-scrape-up"].Result; r == nil || r.Status != "pass" || string(r.Observed) != `{"json_path":"1","status":200}` {
		t.Fatalf("self-scrape-up: %+v", r)
	}
	if byID["traffic-observed"].Playbook != "first-dashboard" || byID["traffic-observed"].Step != "drive-real-traffic" || byID["prometheus-ready"].Source != "template" {
		t.Fatalf("sources: %+v %+v", byID["traffic-observed"], byID["prometheus-ready"])
	}

	// Make the objective true by hand — the learner's act, through the
	// product's own API with the revealed credential — then verify it.
	value, err := h.eng.Reveal(ctx, "intro", "grafana", Actor{Subject: "jross", Mechanism: "session"})
	if err != nil || value != string(password) {
		t.Fatalf("reveal: %q %v", value, err)
	}
	if audit, _ := h.store.ListAudit("intro"); len(audit) != 1 || audit[0].Action != "reveal" || audit[0].Detail != "grafana" || audit[0].Actor != "jross" {
		t.Fatalf("the reveal must be audited: %+v", audit)
	}
	secretsList, _ := h.eng.Secrets("intro", Socket)
	if len(secretsList) != 1 || secretsList[0].Name != "grafana" || secretsList[0].Kind != "password" || secretsList[0].Reveals != 1 || secretsList[0].Created == nil {
		t.Fatalf("secrets listing: %+v", secretsList)
	}
	if raw, _ := json.Marshal(secretsList); strings.Contains(string(raw), string(password)) {
		t.Fatal("a secret value in the secrets listing")
	}
	grafana, _ := h.eng.Service("intro", "grafana")
	base := fmt.Sprintf("http://127.0.0.1:%d", grafana.Ports[3000])
	req, _ := http.NewRequest(http.MethodPost, base+"/api/dashboards/db", strings.NewReader(`{"dashboard":{"title":"Lab Overview"}}`))
	req.SetBasicAuth("admin", value)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("create the dashboard by hand: %v %v", resp, err)
	}
	resp.Body.Close()
	res, err := h.eng.RunCheckpoint(ctx, "intro", "dashboard-exists", Socket)
	if err != nil || res.Status != "pass" || string(res.Observed) != `{"json_path":"Lab Overview","status":200}` {
		t.Fatalf("dashboard-exists after the act: %+v %v", res, err)
	}
	if v, _ := h.eng.View("intro", Socket); v.Checkpoints.Objective.Passed != 1 || v.Checkpoints.Objective.Failed != 1 || v.Ladder.Stage != "ready" {
		t.Fatalf("tally after one objective: %+v", v.Checkpoints)
	}
	// Evidence shows both runs of the checkpoint.
	runs, err := h.eng.Evidence("intro", EvidenceFilter{Type: "checkpoint"}, Socket)
	if err != nil {
		t.Fatal(err)
	}
	var dash []string
	for _, e := range runs {
		if e.Checkpoint != nil && e.Checkpoint.ID == "dashboard-exists" {
			dash = append(dash, e.Checkpoint.Status)
		}
	}
	if strings.Join(dash, ",") != "fail,pass" {
		t.Fatalf("evidence must show both runs: %v", dash)
	}
	// The step's seed runs on demand and moves the counter; the objective
	// follows.
	sj, err := h.eng.SeedAs(ctx, "intro", "query-load", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(sj.ID); j.State != state.JobSucceeded {
		t.Fatalf("seed job: %+v\n%s", j, journalOf(h, sj.ID))
	}
	if n := h.fake.Queries("pdr-intro-prometheus"); n < 200 {
		t.Fatalf("the seed must have queried prometheus 200 times: %d", n)
	}
	res, err = h.eng.RunCheckpoint(ctx, "intro", "traffic-observed", Socket)
	if err != nil || res.Status != "pass" {
		t.Fatalf("traffic-observed after the seed: %+v %v", res, err)
	}
	seeds, _ := h.eng.Evidence("intro", EvidenceFilter{Type: "seed"}, Socket)
	if len(seeds) != 1 || seeds[0].Seed == nil || seeds[0].Seed.Name != "query-load" || seeds[0].Seed.Count != 200 || len(seeds[0].Seed.SeedValue) != 16 {
		t.Fatalf("seed evidence: %+v", seeds)
	}
	if _, err := h.eng.SeedAs(ctx, "intro", "nope", Socket); code(err) != pdr.CodeSeedNotFound {
		t.Fatalf("unknown seed: %v", err)
	}
	// Progress: a pass is accepted only with a result behind it.
	pb, err := h.eng.Playbook("intro", "first-dashboard", Socket)
	if err != nil || len(pb.StepList) != 4 || pb.StepList[1].Actions[0].Label != "Send query-load · 200 requests" || pb.StepList[2].Checkpoint.ID != "dashboard-exists" || pb.StepList[2].Actions[0].Reveal != "grafana" {
		t.Fatalf("playbook: %+v %v", pb, err)
	}
	p0, _ := h.eng.Progress("intro", "first-dashboard", Socket)
	if p0.CurrentStep != "meet-the-stack" || len(p0.Steps) != 0 {
		t.Fatalf("empty progress: %+v", p0)
	}
	if _, err := h.eng.PutProgress("intro", "first-dashboard", state.Progress{CurrentStep: "build-a-dashboard", Steps: map[string]state.StepProgress{"meet-the-stack": {Status: "pass"}}}, Socket); code(err) != pdr.CodeProgressRefused {
		t.Fatalf("a pass on a step without a checkpoint: %v", err)
	}
	if _, err := h.eng.PutProgress("intro", "first-dashboard", state.Progress{Steps: map[string]state.StepProgress{"drive-real-traffic": {Status: "fail"}}}, Socket); code(err) != pdr.CodeProgressRefused {
		t.Fatalf("a status the result does not support: %v", err)
	}
	if _, err := h.eng.PutProgress("intro", "first-dashboard", state.Progress{CurrentStep: "nope"}, Socket); code(err) != pdr.CodeProgressRefused {
		t.Fatalf("an unknown step: %v", err)
	}
	stored, err := h.eng.PutProgress("intro", "first-dashboard", state.Progress{CurrentStep: "leave-with-receipts", Steps: map[string]state.StepProgress{"meet-the-stack": {Status: "skipped"}, "drive-real-traffic": {Status: "pass"}, "build-a-dashboard": {Status: "pass"}}}, Socket)
	if err != nil || len(stored.Steps) != 3 || stored.Steps["build-a-dashboard"].At.IsZero() {
		t.Fatalf("progress write: %+v %v", stored, err)
	}
	// A verify job re-evaluates everything and keeps the ladder at ready.
	vj, err := h.eng.VerifyAs(ctx, "intro", "", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(vj.ID); j.State != state.JobSucceeded {
		t.Fatalf("verify job: %+v", j)
	}
	if v, _ := h.eng.View("intro", Socket); v.Checkpoints.Objective.Passed != 2 || v.Checkpoints.Baseline.Passed != 4 || v.Ladder.Stage != "ready" {
		t.Fatalf("after verify: %+v %s", v.Checkpoints, v.Ladder.Stage)
	}
	if _, err := h.eng.VerifyAs(ctx, "intro", "nope", Socket); code(err) != pdr.CodePlaybookNotFound {
		t.Fatalf("verify of an unknown playbook: %v", err)
	}
	// JUnit loads and carries the class split.
	xmlRaw, err := h.eng.JUnit("intro", Socket)
	if err != nil {
		t.Fatal(err)
	}
	var suites struct {
		Tests    int `xml:"tests,attr"`
		Failures int `xml:"failures,attr"`
		Suites   []struct {
			Name  string `xml:"name,attr"`
			Tests int    `xml:"tests,attr"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal(xmlRaw, &suites); err != nil || suites.Tests != 6 || suites.Failures != 0 || len(suites.Suites) != 2 || suites.Suites[0].Name != "baseline" || suites.Suites[0].Tests != 4 {
		t.Fatalf("junit: %+v %v\n%s", suites, err, xmlRaw)
	}
	if strings.Contains(string(xmlRaw), string(password)) {
		t.Fatal("a secret in the JUnit export")
	}

	// Reset: the preview names what goes and what stays; the job takes the
	// containers down, clears objective progress, re-creates, re-verifies.
	plan, err := h.eng.ResetPlanFor("intro")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(plan.Destroyed, "\n") + "\n--\n" + strings.Join(plan.Survives, "\n")
	for _, want := range []string{"container grafana and the data inside it", "container prometheus and the data inside it", "objective progress: 2 objective checkpoint(s) return to red, playbook positions clear", "data sent by seed query-load", "--\ninstance intro and its hostnames", "secrets (credentials stay the same)", "evidence (immutable; the history stays)", "baselines re-verified"} {
		if !strings.Contains(joined, want) {
			t.Errorf("reset plan lacks %q:\n%s", want, joined)
		}
	}
	evidenceBefore, _ := h.eng.Evidence("intro", EvidenceFilter{}, Socket)
	rj, err := h.eng.ResetAs(ctx, "intro", Actor{Subject: "jross", Mechanism: "session"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(rj.ID); j.State != state.JobSucceeded {
		t.Fatalf("reset job: %+v\n%s", j, journalOf(h, rj.ID))
	}
	// Every latest result is cleared with the containers — the baselines'
	// too, so the tally never shows a stale green over a lab being rebuilt —
	// and the re-create re-verifies them all.
	if rjournal := journalOf(h, rj.ID); !strings.Contains(rjournal, "progress ok results cleared: 4 baseline · 2 objective (re-verified below); playbook progress cleared; evidence kept") || !strings.Contains(rjournal, "verified ok baseline 4/4 · objectives 0/2") {
		t.Fatalf("reset journal:\n%s", rjournal)
	}
	v, _ = h.eng.View("intro", Socket)
	if v.Ladder.Stage != "ready" || v.Checkpoints.Baseline.Passed != 4 || v.Checkpoints.Objective.Passed != 0 || v.Checkpoints.Objective.Total != 2 {
		t.Fatalf("after reset: %+v %s", v.Checkpoints, v.Ladder.Stage)
	}
	if p, _ := h.eng.Progress("intro", "first-dashboard", Socket); len(p.Steps) != 0 || p.CurrentStep != "meet-the-stack" {
		t.Fatalf("reset must clear objective progress: %+v", p)
	}
	if secret2, _ := os.ReadFile(secretPath); string(secret2) != string(password) {
		t.Fatal("secrets survive a reset")
	}
	evidenceAfter, _ := h.eng.Evidence("intro", EvidenceFilter{}, Socket)
	if len(evidenceAfter) <= len(evidenceBefore) {
		t.Fatalf("evidence is immutable and grows: %d → %d", len(evidenceBefore), len(evidenceAfter))
	}
	for i, e := range evidenceBefore {
		if evidenceAfter[i].ID != e.ID {
			t.Fatalf("evidence history rewritten at %d", i)
		}
	}
	var resetAudited bool
	for _, e := range evidenceAfter {
		if e.Type == evidence.TypeAudit && e.Audit != nil && e.Audit.Action == "reset" && e.Audit.Actor == "jross" {
			resetAudited = true
		}
	}
	if !resetAudited {
		t.Fatal("the reset must appear in the evidence audit stream")
	}
	// The dashboard is gone with the container; the objective is red again.
	res, _ = h.eng.RunCheckpoint(ctx, "intro", "dashboard-exists", Socket)
	if res.Status != "fail" {
		t.Fatalf("after reset the objective is red again: %+v", res)
	}
	// Nothing anywhere carries the secret value except the store, the env
	// file, and what the fake Grafana read from it.
	scan := func(path string) {
		_ = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || strings.Contains(p, "/secrets/") || strings.HasSuffix(p, ".env") {
				return nil
			}
			raw, _ := os.ReadFile(p)
			if strings.Contains(string(raw), string(password)) {
				t.Errorf("secret value found in %s", p)
			}
			return nil
		})
	}
	scan(h.dir)
	for _, id := range []string{job.ID, sj.ID, vj.ID, rj.ID} {
		if strings.Contains(journalOf(h, id), string(password)) {
			t.Fatalf("secret value in the journal of %s", id)
		}
	}
	// Destroy takes everything, the internal network and the evidence too.
	dj, err := h.eng.Destroy(ctx, "intro", "intro")
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(dj.ID); j.State != state.JobSucceeded {
		t.Fatalf("destroy: %+v", j)
	}
	if objs, _ := h.fake.Objects(ctx, "intro"); !objs.Empty() {
		t.Fatalf("leftovers: %+v", objs)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "instances", "intro")); !os.IsNotExist(err) {
		t.Fatal("instance directory survives destroy")
	}
}

// A baseline that fails at create: the job fails with PDR-E411, the
// containers run, the ladder stops at seeded, and `up` again re-verifies.
func TestGateBaselineFailureStopsAtSeeded(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: gated, version: 1.0.0 }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
checkpoints:
  - id: web-answers
    adapter: http
    params: { url: http://web:80/ }
    expect: { status: 200 }
    retries: { attempts: 1 }
  - id: never-there
    adapter: http
    params: { url: http://web:80/ }
    expect: { body_contains: "not in the page" }
    retries: { attempts: 2, backoff: 10ms }
  - id: soft
    adapter: http
    params: { url: http://web:80/ }
    expect: { status: 418 }
    severity: warn
    retries: { attempts: 1 }
`
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "gated"})
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(job.ID)
	if j.State != state.JobFailed || j.Error == nil || j.Error.Code != pdr.CodeBaselineFailed || !strings.Contains(j.Error.Message, "never-there") || strings.Contains(j.Error.Message, "soft") {
		t.Fatalf("gate baseline failure: %+v", j)
	}
	if j.Error.Evidence == "" || !strings.Contains(j.Error.Cause, "baseline 1/3") {
		t.Fatalf("anatomy: %+v", j.Error)
	}
	v, _ := h.eng.View("gated", Socket)
	if v.Ladder.Stage != string(state.StageSeeded) || v.Checkpoints.Baseline.Passed != 1 || v.Checkpoints.Baseline.Total != 3 {
		t.Fatalf("ladder after a gate failure: %+v %+v", v.Ladder, v.Checkpoints)
	}
	if st, _ := h.fake.Inspect(ctx, "pdr-gated-web"); st == nil || !st.Running {
		t.Fatal("the containers keep running")
	}
	// Remove the failing gate; `up` again resumes: re-verify, ready.
	body = strings.Replace(body, `    expect: { body_contains: "not in the page" }`, `    expect: { body_contains: "fake" }`, 1)
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644)
	again, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "gated"})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if j := h.wait(again.ID); j.State != state.JobSucceeded {
		t.Fatalf("resumed create: %+v\n%s", j, journalOf(h, again.ID))
	}
	v, _ = h.eng.View("gated", Socket)
	if v.Ladder.Stage != string(state.StageReady) || v.Checkpoints.Baseline.Passed != 2 {
		t.Fatalf("ready with the warn baseline red: %+v %+v", v.Ladder, v.Checkpoints)
	}
	if !strings.Contains(journalOf(h, again.ID), "verified warn baseline 2/3") {
		t.Fatalf("the warn baseline is journaled:\n%s", journalOf(h, again.ID))
	}
	// A verify that finds a gate baseline red regresses the ladder to
	// seeded; one that finds it green again restores ready.
	body = strings.Replace(body, `    expect: { body_contains: "fake" }`, `    expect: { body_contains: "not in the page" }`, 1)
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644)
	vj, _ := h.eng.VerifyAs(ctx, "gated", "", Socket)
	if j := h.wait(vj.ID); j.State != state.JobSucceeded {
		t.Fatalf("verify is a successful run whatever it finds: %+v", j)
	}
	if v, _ := h.eng.View("gated", Socket); v.Ladder.Stage != string(state.StageSeeded) {
		t.Fatalf("a red gate baseline regresses the ladder: %+v", v.Ladder)
	}
	body = strings.Replace(body, `    expect: { body_contains: "not in the page" }`, `    expect: { body_contains: "fake" }`, 1)
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644)
	vj, _ = h.eng.VerifyAs(ctx, "gated", "", Socket)
	h.wait(vj.ID)
	if v, _ := h.eng.View("gated", Socket); v.Ladder.Stage != string(state.StageReady) {
		t.Fatalf("a green gate baseline restores ready: %+v", v.Ladder)
	}
}

// An objective green at create is PDR-W101: journaled, in evidence, and
// the create still succeeds.
func TestObjectiveGreenAtCreateWarnsW101(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "playbooks"), 0o755)
	lab := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: eager, version: 1.0.0 }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
`
	pb := `apiVersion: lab.podaro.dev/v1alpha1
kind: Playbook
metadata: { name: walk, title: Walk }
steps:
  - id: look
    title: Look
    context: web
    body: Look at the page.
    checkpoint:
      id: page-up
      adapter: http
      params: { url: http://web:80/ }
      expect: { status: 200 }
      hint: The page is always up.
  - id: confirm
    title: Confirm
    body: Say so.
    checkpoint:
      id: seen
      adapter: attest
      params: { prompt: "I saw the page." }
      hint: Just say so.
`
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "playbooks", "walk.yaml"), []byte(pb), 0o644)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "eager"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	journal := journalOf(h, job.ID)
	if !strings.Contains(journal, "checkpoint page-up warn PDR-W101") || !strings.Contains(journal, "checkpoint seen fail") {
		t.Fatalf("W101 for the eager objective, the attest one red:\n%s", journal)
	}
	warnings, _ := h.eng.Evidence("eager", EvidenceFilter{Type: "lifecycle"}, Socket)
	var found bool
	for _, e := range warnings {
		if e.Lifecycle != nil && e.Lifecycle.Code == pdr.CodeObjectiveGreenAtCreate && strings.Contains(e.Lifecycle.Detail, "page-up") {
			found = true
		}
	}
	if !found {
		t.Fatalf("W101 must be in evidence: %+v", warnings)
	}
	v, _ := h.eng.View("eager", Socket)
	if v.Ladder.Stage != "ready" || v.Checkpoints.Objective.Passed != 1 || v.Checkpoints.Objective.Total != 2 {
		t.Fatalf("tally: %+v", v.Checkpoints)
	}
	// Attest: only attest checkpoints take a confirmation; the result is
	// attested, never a pass, and progress may then record it.
	if _, err := h.eng.Attest(ctx, "eager", "page-up", "", Socket); code(err) != pdr.CodeAttestRefused {
		t.Fatalf("attesting a machine-judged checkpoint: %v", err)
	}
	res, err := h.eng.Attest(ctx, "eager", "seen", "looked twice", Actor{Subject: "alice", Mechanism: "session"})
	if err != nil || res.Status != "attested" || !strings.Contains(res.Message, "attested by alice: looked twice") {
		t.Fatalf("attest: %+v %v", res, err)
	}
	if _, err := h.eng.PutProgress("eager", "walk", state.Progress{CurrentStep: "confirm", Steps: map[string]state.StepProgress{"confirm": {Status: "attested"}, "look": {Status: "pass"}}}, Socket); err != nil {
		t.Fatalf("progress backed by results: %v", err)
	}
	if v, _ := h.eng.View("eager", Socket); v.Checkpoints.Objective.Passed != 2 {
		t.Fatalf("attested counts as earned in the tally: %+v", v.Checkpoints)
	}
	if _, err := h.eng.RunCheckpoint(ctx, "eager", "nope", Socket); code(err) != pdr.CodeCheckpointNotFound {
		t.Fatalf("unknown checkpoint: %v", err)
	}
	if _, err := h.eng.Reveal(ctx, "eager", "nope", Socket); code(err) != pdr.CodeSecretNotFound {
		t.Fatalf("unknown secret: %v", err)
	}
	if _, err := h.eng.EvidenceEntry("eager", "ev_nope", Socket); code(err) != pdr.CodeEvidenceNotFound {
		t.Fatalf("unknown evidence: %v", err)
	}
	entries, _ := h.eng.Evidence("eager", EvidenceFilter{Type: "checkpoint"}, Socket)
	if len(entries) == 0 {
		t.Fatal("no checkpoint evidence")
	}
	if got, err := h.eng.EvidenceEntry("eager", entries[0].ID, Socket); err != nil || got.ID != entries[0].ID {
		t.Fatalf("evidence entry: %+v %v", got, err)
	}
}

// Exec checkpoints and an exec seed run through the runner on the fake:
// the conformance fixture's behaviors map to Spec 0002 §6, and a root
// image is refused before anything runs.
func TestExecCheckpointsAndSeedsOnTheFake(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "playbooks"), 0o755)
	image := "docker.io/podaro/exec-conformance@sha256:" + strings.Repeat("e", 64)
	root := "docker.io/podaro/exec-conformance-root@sha256:" + strings.Repeat("b", 64)
	lab := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: judged, version: 1.0.0 }
secrets:
  tok: { kind: token }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
seeds:
  orders: { generator: { exec: { image: IMAGE, args: [pass] } }, count: 42 }
checkpoints:
  - id: judged-pass
    adapter: exec
    params: { image: IMAGE, args: [pass], secrets: [tok] }
    expect: { lag: 0 }
    retries: { attempts: 1 }
  - id: judged-fail
    adapter: exec
    params: { image: IMAGE, args: [fail] }
    expect: { lag: 0 }
    severity: warn
    retries: { attempts: 1 }
  - id: judged-crash
    adapter: exec
    params: { image: IMAGE, args: [crash] }
    severity: warn
    retries: { attempts: 1 }
  - id: judged-garbage
    adapter: exec
    params: { image: IMAGE, args: [garbage] }
    severity: warn
    retries: { attempts: 1 }
  - id: judged-slow
    adapter: exec
    params: { image: IMAGE, args: [sleep] }
    severity: warn
    timeout: 200ms
    retries: { attempts: 1 }
  - id: judged-root
    adapter: exec
    params: { image: ROOT, args: [pass] }
    severity: warn
    retries: { attempts: 1 }
`
	lab = strings.ReplaceAll(strings.ReplaceAll(lab, "IMAGE", image), "ROOT", root)
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "judged"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	cps, _ := h.eng.Checkpoints("judged", Socket)
	got := map[string]*state.CheckpointResult{}
	for _, cp := range cps {
		got[cp.ID] = cp.Result
	}
	want := map[string]struct{ status, code string }{
		"judged-pass": {"pass", ""}, "judged-fail": {"fail", ""}, "judged-crash": {"error", pdr.CodeExecExit},
		"judged-garbage": {"error", pdr.CodeExecOutput}, "judged-slow": {"error", pdr.CodeExecTimeout}, "judged-root": {"error", pdr.CodeExecRoot},
	}
	for id, w := range want {
		r := got[id]
		if r == nil || r.Status != w.status || (w.code != "" && (r.Error == nil || r.Error.Code != w.code)) {
			t.Errorf("%s: %+v, want %+v", id, r, w)
		}
	}
	if r := got["judged-pass"]; r == nil || string(r.Observed) != `{"lag":0}` || string(r.Expected) != `{"lag":0}` {
		t.Fatalf("exec observed/expected pass through: %+v", r)
	}
	if r := got["judged-crash"]; r == nil || r.Error == nil || !strings.Contains(r.Error.Cause, "crashing on purpose") {
		t.Fatalf("stderr excerpt in the error: %+v", r)
	}
	// The pass entry's evidence carries the capture (image, granted secrets).
	entries, _ := h.eng.Evidence("judged", EvidenceFilter{Type: "checkpoint"}, Socket)
	var capture string
	for _, e := range entries {
		if e.Checkpoint != nil && e.Checkpoint.ID == "judged-pass" {
			capture = string(e.Checkpoint.Observed)
		}
	}
	if !strings.Contains(strings.Join(strings.Fields(capture), ""), `"secrets":["tok"]`) || !strings.Contains(capture, image) {
		t.Fatalf("capture in evidence: %s", capture)
	}
	// Standing exec seed ran at create (no step names it) and reported.
	seeds, _ := h.eng.Evidence("judged", EvidenceFilter{Type: "seed"}, Socket)
	if len(seeds) != 1 || seeds[0].Seed.Kind != "exec" || seeds[0].Seed.Image != image || fmt.Sprint(seeds[0].Seed.Sent) != "map[events:42]" || !strings.Contains(seeds[0].Seed.Message, seeds[0].Seed.SeedValue) {
		t.Fatalf("exec seed evidence: %+v", seeds)
	}
	if !strings.Contains(journalOf(h, job.ID), "seed orders ok") {
		t.Fatalf("seed journaled:\n%s", journalOf(h, job.ID))
	}
	// The secret value never reached stdin, the journal, or evidence.
	tok, _ := os.ReadFile(filepath.Join(h.dir, "instances", "judged", "secrets", "tok"))
	if strings.Contains(journalOf(h, job.ID), string(tok)) {
		t.Fatal("secret in the journal")
	}
	_ = filepath.Walk(filepath.Join(h.dir, "instances", "judged", "evidence"), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			raw, _ := os.ReadFile(p)
			if strings.Contains(string(raw), string(tok)) {
				t.Errorf("secret in evidence %s", p)
			}
		}
		return nil
	})
	_ = io.Discard
}

// A no-readiness service pins the instance at alive (plan S4's decision
// holds): nothing above is claimed for it, and the create still succeeds.
func TestNoReadinessServicePinsTheLadder(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: mixed, version: 1.0.0 }
services:
  bare:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
  probed:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
`
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "mixed"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	svcs, _ := h.store.ListServices("mixed")
	stages := map[string]state.Stage{}
	for _, s := range svcs {
		stages[s.Name] = s.Stage
	}
	if stages["bare"] != state.StageAlive || stages["probed"] != state.StageReady {
		t.Fatalf("stages: %v", stages)
	}
	if inst, _ := h.store.GetInstance("mixed"); inst.Stage != state.StageAlive {
		t.Fatalf("the instance is only as high as its slowest rung: %s", inst.Stage)
	}
}

// journalOf flattens a job's journal for assertions.
func journalOf(h *harness, jobID string) string {
	events, _ := h.store.ListEvents(jobID)
	var lines []string
	for _, ev := range events {
		parts := []string{ev.Step}
		if ev.Service != "" {
			parts = append(parts, ev.Service)
		}
		parts = append(parts, ev.Status)
		if ev.Detail != "" {
			parts = append(parts, ev.Detail)
		}
		lines = append(lines, strings.Join(parts, " "))
	}
	return strings.Join(lines, "\n")
}

var _ = time.Second

// A reconcile after a reboot restarts the containers it finds and keeps
// what they hold: init is not run twice against a container that kept
// its filesystem, standing seeds are not injected twice, baselines
// re-verify and the ladder returns to ready (User Manual §8). A
// container that vanished is recreated, and for it — and the seeds — the
// create path runs again.
func TestReconcileKeepsTheDataItFinds(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	library := lab.DirLibrary(filepath.Join("testdata", "modules"))
	h.eng.opts.Library = library
	dir := t.TempDir()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: kept, version: 1.0.0 }
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
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "kept"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	journal := journalOf(h, job.ID)
	for _, want := range []string{"init web ok 2 requests", "seeded ok warm", "ready ok"} {
		if !strings.Contains(journal, want) {
			t.Fatalf("create journal lacks %q:\n%s", want, journal)
		}
	}
	if n := h.fake.Queries("pdr-kept-prometheus"); n != 5 {
		t.Fatalf("the standing seed sent 5 queries, counted %d", n)
	}
	seedRuns := func() int {
		entries, _ := h.eng.Evidence("kept", EvidenceFilter{Type: "seed"}, Socket)
		return len(entries)
	}
	if seedRuns() != 1 {
		t.Fatalf("one seed run in evidence, got %d", seedRuns())
	}

	// Reboot: every container stops; the next start reconciles.
	h.fake.Close()
	if err := runtime.Reboot(h.world); err != nil {
		t.Fatal(err)
	}
	h.open()
	h.eng.opts.Library = library
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ := h.store.ListJobs("kept")
	if len(jobs) != 2 || jobs[0].Kind != "reconcile" {
		t.Fatalf("expected a reconcile job, got %+v", jobs)
	}
	if j := h.wait(jobs[0].ID); j.State != state.JobSucceeded {
		t.Fatalf("reconcile: %+v\n%s", j, journalOf(h, jobs[0].ID))
	}
	journal = journalOf(h, jobs[0].ID)
	// A reconcile says what it re-verified, and its summary says which
	// run produced the counts (plan S9; Manual §8).
	for _, want := range []string{"init web skipped reconcile: the container restarted with its data", "seeded skipped reconcile: containers restarted with their data; standing seeds not re-run: warm", "verifying ok reconcile: baselines re-verified; the objectives keep their verdicts", "verified ok reconciled · baseline 1/1", "ready ok reconciled ·"} {
		if !strings.Contains(journal, want) {
			t.Errorf("reconcile journal lacks %q:\n%s", want, journal)
		}
	}
	if strings.Contains(journal, "init web ok") || strings.Contains(journal, "seeded ok") {
		t.Fatalf("a reconcile must not run init or standing seeds again:\n%s", journal)
	}
	if n := h.fake.Queries("pdr-kept-prometheus"); n != 0 {
		t.Fatalf("no seed traffic on reconcile, counted %d", n)
	}
	if seedRuns() != 1 {
		t.Fatalf("evidence still holds one seed run, got %d", seedRuns())
	}
	if inst, _ := h.store.GetInstance("kept"); inst.Stage != state.StageReady {
		t.Fatalf("after reconcile: stage %s", inst.Stage)
	}

	// A container removed behind the engine's back is recreated by the
	// next reconcile: its data is gone, so init runs for it and the
	// standing seeds run again.
	if err := h.fake.Remove(ctx, "pdr-kept-web"); err != nil {
		t.Fatal(err)
	}
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ = h.store.ListJobs("kept")
	if len(jobs) != 3 || jobs[0].Kind != "reconcile" {
		t.Fatalf("expected a second reconcile job, got %+v", jobs)
	}
	if j := h.wait(jobs[0].ID); j.State != state.JobSucceeded {
		t.Fatalf("second reconcile: %+v\n%s", j, journalOf(h, jobs[0].ID))
	}
	journal = journalOf(h, jobs[0].ID)
	for _, want := range []string{"init web ok 2 requests", "init prometheus skipped reconcile: the container restarted with its data", "seeded ok warm", "ready ok"} {
		if !strings.Contains(journal, want) {
			t.Errorf("recreate journal lacks %q:\n%s", want, journal)
		}
	}
	if seedRuns() != 2 {
		t.Fatalf("the seed ran again for the recreated lab: %d runs", seedRuns())
	}
}
