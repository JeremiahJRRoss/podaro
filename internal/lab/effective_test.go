// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	"path/filepath"
	"strings"
	"testing"
)

// Effective merges what create must hand the runtime, names what it
// cannot render yet, and writes env in --env-file form.
func TestEffectiveConfig(t *testing.T) {
	res, err := Validate(Options{Path: filepath.Join("..", "..", "scenarios", "grafana-prometheus-intro"), Library: EmbeddedLibrary()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Composition == nil {
		t.Fatal("no composition")
	}
	g := res.Composition.Effective("grafana")
	if g == nil || g.Env["GF_SECURITY_ALLOW_EMBEDDING"] != "true" || g.Env["GF_SECURITY_ADMIN_PASSWORD"] != "${secret:grafana}" {
		t.Fatalf("grafana env: %+v", g)
	}
	needs := strings.Join(g.NeedsRendering(), " | ")
	if !strings.Contains(needs, "env GF_SECURITY_ADMIN_PASSWORD references ${secret:grafana}") || !strings.Contains(needs, "config file(s) to render") {
		t.Fatalf("needs: %s", needs)
	}
	// A EULA's acceptance environment reaches the effective config of the
	// service that declares it (spec 0003 §7) — on the licence-gate
	// fixture, whose terms nobody holds.
	gated, err := Validate(Options{Path: filepath.Join("..", "..", "hack", "fixtures", "eula-lab"), Library: EmbeddedLibrary()})
	if err != nil || gated.Composition == nil {
		t.Fatalf("eula-lab: %v", err)
	}
	if sp := gated.Composition.Effective("gated"); sp == nil || sp.Env["ACCEPT_EXAMPLE_TERMS"] != "yes" {
		t.Fatalf("EULA env not injected: %+v", sp)
	}
	if res.Composition.Effective("nope") != nil {
		t.Fatal("unknown service must be nil")
	}
	var nilCfg *EffectiveConfig
	if nilCfg.NeedsRendering() != nil {
		t.Fatal("nil config needs nothing")
	}
	plain := &EffectiveConfig{Env: map[string]string{"B": "2", "A": "one two"}}
	if len(plain.NeedsRendering()) != 0 {
		t.Fatalf("plain env needs rendering: %v", plain.NeedsRendering())
	}
	if out, err := plain.EnvFile(); err != nil || out != "A=one two\nB=2\n" {
		t.Fatalf("env file: %q %v", out, err)
	}
	if _, err := (&EffectiveConfig{Env: map[string]string{"X": "a\nb"}}).EnvFile(); err == nil {
		t.Fatal("multi-line value accepted")
	}
	if _, err := (&EffectiveConfig{Env: map[string]string{"BAD KEY": "v"}}).EnvFile(); err == nil {
		t.Fatal("bad key accepted")
	}
	cmd := &EffectiveConfig{Args: []string{"--token=${secret:t}"}}
	if len(cmd.NeedsRendering()) != 1 {
		t.Fatalf("secret in args: %v", cmd.NeedsRendering())
	}
}
