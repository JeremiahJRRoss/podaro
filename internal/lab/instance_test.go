// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	"path/filepath"
	"strings"
	"testing"
)

// The small template flattens to four baselines and two objectives, in
// declaration order, each naming where it lives; the seed a step invokes
// is an action, never a standing seed.
func TestFlattenCheckpointsAndSeedRoles(t *testing.T) {
	res, err := Validate(Options{Path: filepath.Join("..", "..", "scenarios", "grafana-prometheus-intro"), Library: EmbeddedLibrary()})
	if err != nil || !res.Valid() {
		t.Fatalf("validate: %v %+v", err, res.Findings)
	}
	cps := FlattenCheckpoints(res)
	var got []string
	for _, cp := range cps {
		got = append(got, cp.ID+":"+cp.ResolvedClass+":"+cp.Severity()+":"+cp.Source)
	}
	want := "prometheus-ready:baseline:gate:template,grafana-healthy:baseline:gate:template,self-scrape-up:baseline:gate:template,grafana-scraped:baseline:gate:template," +
		"traffic-observed:objective:gate:playbook first-dashboard · step drive-real-traffic,dashboard-exists:objective:gate:playbook first-dashboard · step build-a-dashboard"
	if strings.Join(got, ",") != want {
		t.Fatalf("flattened:\n got %s\nwant %s", strings.Join(got, ","), want)
	}
	if cps[4].Playbook != "first-dashboard" || cps[4].Step != "drive-real-traffic" || len(cps[4].Steps) != 1 || cps[4].Steps[0] != "first-dashboard/drive-real-traffic" || cps[4].Hint == "" {
		t.Fatalf("inline checkpoint facts: %+v", cps[4])
	}
	standing, actions := SeedRoles(res)
	if len(standing) != 0 || strings.Join(actions, ",") != "query-load" {
		t.Fatalf("seed roles: standing %v actions %v", standing, actions)
	}
	if pb := PlaybookNamed(res, "first-dashboard"); pb == nil || len(pb.Steps) != 4 {
		t.Fatalf("playbook: %+v", pb)
	}
	if PlaybookNamed(res, "nope") != nil {
		t.Fatal("unknown playbook must be nil")
	}
	if ep, ok := EndpointOf(res, "prometheus", "api"); !ok || ep.Port != 9090 || ep.Scheme != "http" {
		t.Fatalf("endpoint: %+v %v", ep, ok)
	}
	if ep, ok := EndpointOf(res, "grafana", ""); !ok || ep.Port != 3000 || ep.Purpose != "ui" {
		t.Fatalf("first endpoint: %+v %v", ep, ok)
	}
	if _, ok := EndpointOf(res, "grafana", "api"); ok {
		t.Fatal("grafana declares no api endpoint")
	}
	if eps := EndpointsOf(res, "prometheus"); len(eps) != 2 || eps[1].Purpose != "api" {
		t.Fatalf("endpoints: %+v", eps)
	}
	if InitOf(res, "grafana") != nil || ModuleNameOf(res, "grafana") != "grafana" || ModuleNameOf(res, "nope") != "" {
		t.Fatal("init/module facts")
	}

	// The conformance lab (the reconciliation plan's R1): a ref'd
	// checkpoint gains the referencing step and keeps its class; the seeds
	// are all step actions; the inline objectives count.
	conf, err := Validate(Options{Path: filepath.Join("..", "..", "hack", "fixtures", "conformance-lab"), Library: EmbeddedLibrary()})
	if err != nil || !conf.Valid() {
		t.Fatalf("conformance-lab: %v %+v", err, conf.Findings)
	}
	ccps := FlattenCheckpoints(conf)
	var answers *FlatCheckpoint
	objectives := 0
	for i := range ccps {
		if ccps[i].ID == "web-answers" {
			answers = &ccps[i]
		}
		if ccps[i].ResolvedClass == "objective" {
			objectives++
		}
	}
	if answers == nil || answers.ResolvedClass != "baseline" || strings.Join(answers.Steps, ",") != "conformance/receipts" {
		t.Fatalf("ref'd checkpoint: %+v", answers)
	}
	// Three inline objectives; receipts references the template's
	// baseline and adds no objective.
	if objectives != 3 {
		t.Fatalf("conformance objectives: %d", objectives)
	}
	standing, actions = SeedRoles(conf)
	if len(standing) != 0 || strings.Join(actions, ",") != "events,knock" {
		t.Fatalf("conformance seed roles: %v %v", standing, actions)
	}
	// Init blocks are effective (merged): a template's config.init.requests
	// replaces the module's list whole (spec 0003 §11 rule 2), under the
	// module's own helper image.
	merged, err := Validate(Options{Path: filepath.Join("testdata", "valid-init-merge"), Library: testLibrary()})
	if err != nil || !merged.Valid() {
		t.Fatalf("init-merge: %v %+v", err, merged.Findings)
	}
	if init := InitOf(merged, "target"); init == nil || len(init.Requests) != 3 || init.Image.Repository != "docker.io/curlimages/curl" {
		t.Fatalf("effective init: %+v", init)
	}
	if FlattenCheckpoints(nil) != nil {
		t.Fatal("nil result flattens to nothing")
	}
}

// The definition digest covers a module alias's resolved implementation:
// the same alias name over a different image is a different definition.
func TestDefinitionDigestCoversTheResolvedAlias(t *testing.T) {
	res := func(image string) *Result {
		return &Result{
			Template:    &Template{Checkpoints: []Checkpoint{{ID: "lag", Adapter: "kafka-lag", Expect: map[string]any{"lag": 0}}}},
			Composition: &Composition{Adapters: map[string]aliasOwner{"kafka-lag": {Module: "kafka", Exec: ExecSpec{Image: image, Args: []string{"--topic", "orders"}}}}},
		}
	}
	a := FlattenCheckpoints(res("ghcr.io/acme/lag@sha256:aaaa"))
	b := FlattenCheckpoints(res("ghcr.io/acme/lag@sha256:bbbb"))
	same := FlattenCheckpoints(res("ghcr.io/acme/lag@sha256:aaaa"))
	if len(a) != 1 || a[0].Exec == nil || a[0].Exec.Image != "ghcr.io/acme/lag@sha256:aaaa" {
		t.Fatalf("the alias resolves onto the flattened checkpoint: %+v", a)
	}
	if DefinitionDigest(a[0]) == DefinitionDigest(b[0]) {
		t.Fatal("a changed alias image must change the definition digest")
	}
	if DefinitionDigest(a[0]) != DefinitionDigest(same[0]) {
		t.Fatal("the same definition digests the same")
	}
	builtin := FlattenCheckpoints(&Result{Template: &Template{Checkpoints: []Checkpoint{{ID: "up", Adapter: "http"}}}, Composition: &Composition{}})
	if builtin[0].Exec != nil {
		t.Fatalf("a built-in adapter resolves no alias: %+v", builtin[0])
	}
}
