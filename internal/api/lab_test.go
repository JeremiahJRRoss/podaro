// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// newCatalogServer is the socket door over an engine that knows the
// catalog, so a delivery create of the small template runs here.
func newCatalogServer(t *testing.T) (*httptest.Server, *engine.Engine) {
	t.Helper()
	t.Setenv(runtime.EnvFakeReadyDelay, "100ms")
	dir := t.TempDir()
	fake, err := runtime.NewFake(filepath.Join(dir, "world.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fake.Close)
	eng := engine.New(engine.Options{Store: state.NewMemory(), Runtime: fake, StateDir: dir, CatalogDir: filepath.Join("..", "..", "scenarios"), PollInterval: 50 * time.Millisecond})
	t.Cleanup(func() { shutdown(eng) })
	srv := httptest.NewServer(New(Options{Engine: eng}).SocketHandler())
	t.Cleanup(srv.Close)
	return srv, eng
}

func errCodeOf(out map[string]any) string {
	if e, ok := out["error"].(map[string]any); ok {
		return fmt.Sprint(e["code"])
	}
	return ""
}

// messageOf reads the §3 envelope's message.
func messageOf(out map[string]any) string {
	if e, ok := out["error"].(map[string]any); ok {
		return fmt.Sprint(e["message"])
	}
	return ""
}

// waitJob follows a 202 to its end.
func waitJob(t *testing.T, eng *engine.Engine, out map[string]any) {
	t.Helper()
	job, _ := out["job"].(map[string]any)
	id, _ := job["id"].(string)
	if id == "" {
		t.Fatalf("no job in %v", out)
	}
	j, err := eng.Wait(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if j.State != state.JobSucceeded {
		t.Fatalf("job %s: %+v", id, j)
	}
}

// The lab surface over the socket door (API §7–§10, plan S6), end to end
// on the small template: checkpoints with class and result, a synchronous
// run that is 200 on fail, attest refused on a machine adapter, playbooks
// and the progress rules, secrets without values and the audited reveal,
// the seed a step names, verify, evidence (JSON, one entry, JUnit), and
// reset with its preview.
func TestLabSurfaceOverTheSocketDoor(t *testing.T) {
	srv, eng := newCatalogServer(t)
	code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"template": "grafana-prometheus-intro", "name": "intro"})
	if code != http.StatusAccepted {
		t.Fatalf("create: %d %v", code, out)
	}
	waitJob(t, eng, out)

	code, out = call(t, srv, http.MethodGet, "/instances/intro", nil)
	inst := out["instance"].(map[string]any)
	tally := inst["checkpoints"].(map[string]any)
	if code != 200 || inst["ladder"].(map[string]any)["stage"] != "ready" || fmt.Sprint(tally["baseline"]) != "map[passed:4 total:4]" || fmt.Sprint(tally["objective"]) != "map[failed:2 passed:0 total:2]" {
		t.Fatalf("instance after create: %d %v", code, inst)
	}

	// Checkpoints: every one, with class and latest result.
	code, out = call(t, srv, http.MethodGet, "/instances/intro/checkpoints", nil)
	cps, _ := out["checkpoints"].([]any)
	if code != 200 || len(cps) != 6 {
		t.Fatalf("checkpoints: %d %v", code, out)
	}
	classes := map[string]int{}
	for _, c := range cps {
		cp := c.(map[string]any)
		classes[fmt.Sprint(cp["class"])]++
		if cp["result"] == nil || cp["result"].(map[string]any)["status"] == "" {
			t.Fatalf("every checkpoint carries its latest result: %v", cp)
		}
	}
	if classes["baseline"] != 4 || classes["objective"] != 2 {
		t.Fatalf("classes: %v", classes)
	}
	// A synchronous run is 200 on fail, with observed, expected, hint, and
	// the evidence pointer.
	code, out = call(t, srv, http.MethodPost, "/instances/intro/checkpoints/dashboard-exists/run", map[string]any{})
	res, _ := out["result"].(map[string]any)
	if code != 200 || res["status"] != "fail" || res["class"] != "objective" || res["hint"] == "" || !strings.HasPrefix(fmt.Sprint(res["evidence"]), "/api/v1alpha1/instances/intro/evidence/ev_") || res["observed"] == nil || res["expected"] == nil {
		t.Fatalf("run: %d %v", code, out)
	}
	if code, out := call(t, srv, http.MethodPost, "/instances/intro/checkpoints/nope/run", nil); code != 404 || errCodeOf(out) != "PDR-E403" {
		t.Fatalf("unknown checkpoint: %d %v", code, out)
	}
	if code, out := call(t, srv, http.MethodPost, "/instances/intro/checkpoints/dashboard-exists/attest", map[string]any{"note": "looked"}); code != 400 || errCodeOf(out) != "PDR-E410" {
		t.Fatalf("attest on a machine adapter: %d %v", code, out)
	}

	// Playbooks and progress.
	code, out = call(t, srv, http.MethodGet, "/instances/intro/playbooks", nil)
	pbs, _ := out["playbooks"].([]any)
	if code != 200 || len(pbs) != 1 || pbs[0].(map[string]any)["name"] != "first-dashboard" || fmt.Sprint(pbs[0].(map[string]any)["objectives"]) != "2" {
		t.Fatalf("playbooks: %d %v", code, out)
	}
	code, out = call(t, srv, http.MethodGet, "/instances/intro/playbooks/first-dashboard", nil)
	pb, _ := out["playbook"].(map[string]any)
	steps, _ := pb["step_list"].([]any)
	if code != 200 || len(steps) != 4 || steps[0].(map[string]any)["id"] != "meet-the-stack" {
		t.Fatalf("playbook: %d %v", code, out)
	}
	if code, out := call(t, srv, http.MethodGet, "/instances/intro/playbooks/nope", nil); code != 404 || errCodeOf(out) != "PDR-E407" {
		t.Fatalf("unknown playbook: %d %v", code, out)
	}
	code, out = call(t, srv, http.MethodGet, "/instances/intro/playbooks/first-dashboard/progress", nil)
	if code != 200 || out["current_step"] != "meet-the-stack" || len(out["steps"].(map[string]any)) != 0 {
		t.Fatalf("empty progress starts at the first step: %d %v", code, out)
	}
	// A pass the checkpoint's result does not back is refused (spec 0001 §8).
	code, out = call(t, srv, http.MethodPut, "/instances/intro/playbooks/first-dashboard/progress", map[string]any{"current_step": "build-a-dashboard", "steps": map[string]any{"build-a-dashboard": map[string]any{"status": "pass"}}})
	if code != 400 || errCodeOf(out) != "PDR-E406" {
		t.Fatalf("a forged pass must be refused: %d %v", code, out)
	}
	code, out = call(t, srv, http.MethodPut, "/instances/intro/playbooks/first-dashboard/progress", map[string]any{"current_step": "drive-real-traffic", "steps": map[string]any{"meet-the-stack": map[string]any{"status": "skipped"}}})
	if code != 200 || out["current_step"] != "drive-real-traffic" || out["steps"].(map[string]any)["meet-the-stack"].(map[string]any)["status"] != "skipped" {
		t.Fatalf("progress written: %d %v", code, out)
	}
	if code, out := call(t, srv, http.MethodGet, "/instances/intro/playbooks/first-dashboard/progress", nil); code != 200 || out["current_step"] != "drive-real-traffic" {
		t.Fatalf("progress persisted: %d %v", code, out)
	}

	// Secrets: names and metadata only; the reveal is audited.
	code, out = call(t, srv, http.MethodGet, "/instances/intro/secrets", nil)
	secretsList, _ := out["secrets"].([]any)
	if code != 200 || len(secretsList) != 1 {
		t.Fatalf("secrets: %d %v", code, out)
	}
	sec := secretsList[0].(map[string]any)
	if sec["name"] != "grafana" || sec["kind"] != "password" || fmt.Sprint(sec["reveals"]) != "0" || sec["created"] == nil {
		t.Fatalf("secret metadata: %v", sec)
	}
	if _, present := sec["value"]; present {
		t.Fatal("a listing never carries a value")
	}
	code, out = call(t, srv, http.MethodPost, "/instances/intro/secrets/grafana/reveal", nil)
	value, _ := out["value"].(string)
	if code != 200 || len(value) != 24 || out["remask_after"] != "30s" {
		t.Fatalf("reveal: %d %v", code, out)
	}
	if code, out := call(t, srv, http.MethodGet, "/instances/intro/secrets", nil); code != 200 || fmt.Sprint(out["secrets"].([]any)[0].(map[string]any)["reveals"]) != "1" {
		t.Fatalf("the reveal is counted: %d %v", code, out)
	}
	if code, out := call(t, srv, http.MethodPost, "/instances/intro/secrets/nope/reveal", nil); code != 404 || errCodeOf(out) != "PDR-E408" {
		t.Fatalf("unknown secret: %d %v", code, out)
	}
	code, out = call(t, srv, http.MethodGet, "/instances/intro/evidence?type=audit", nil)
	audits, _ := out["evidence"].([]any)
	var revealed bool
	for _, a := range audits {
		if au, _ := a.(map[string]any)["audit"].(map[string]any); au != nil && au["action"] == "reveal" && au["detail"] == "grafana" && au["mechanism"] == auth.MechanismSocket {
			revealed = true
		}
	}
	if code != 200 || !revealed {
		t.Fatalf("the reveal must be in the audit evidence: %d %v", code, out)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), value) {
		t.Fatal("the value leaked into evidence")
	}

	// The seed a step names runs on demand and its objective turns green.
	code, out = call(t, srv, http.MethodPost, "/instances/intro/seeds/query-load", nil)
	if code != http.StatusAccepted || out["job"].(map[string]any)["kind"] != "seed" {
		t.Fatalf("seed: %d %v", code, out)
	}
	waitJob(t, eng, out)
	if code, out := call(t, srv, http.MethodPost, "/instances/intro/seeds/nope", nil); code != 404 || errCodeOf(out) != "PDR-E405" {
		t.Fatalf("unknown seed: %d %v", code, out)
	}
	code, out = call(t, srv, http.MethodPost, "/instances/intro/checkpoints/traffic-observed/run", nil)
	if code != 200 || out["result"].(map[string]any)["status"] != "pass" {
		t.Fatalf("traffic-observed after the seed: %d %v", code, out)
	}

	// Verify: a job; the tally moves to 1/2.
	code, out = call(t, srv, http.MethodPost, "/instances/intro/verify", nil)
	if code != http.StatusAccepted || out["job"].(map[string]any)["kind"] != "verify" {
		t.Fatalf("verify: %d %v", code, out)
	}
	waitJob(t, eng, out)
	code, out = call(t, srv, http.MethodPost, "/instances/intro/verify", map[string]any{"playbook": "nope"})
	if code != 404 || errCodeOf(out) != "PDR-E407" {
		t.Fatalf("verify of an unknown playbook: %d %v", code, out)
	}
	if code, out := call(t, srv, http.MethodGet, "/instances/intro", nil); code != 200 || fmt.Sprint(out["instance"].(map[string]any)["checkpoints"].(map[string]any)["objective"]) != "map[failed:1 passed:1 total:2]" {
		t.Fatalf("tally after verify: %d %v", code, out)
	}

	// Evidence: the journal, one entry, JUnit.
	code, out = call(t, srv, http.MethodGet, "/instances/intro/evidence?type=checkpoint", nil)
	entries, _ := out["evidence"].([]any)
	if code != 200 || len(entries) < 8 {
		t.Fatalf("checkpoint evidence: %d %d entries", code, len(entries))
	}
	first := entries[0].(map[string]any)
	if code, out := call(t, srv, http.MethodGet, "/instances/intro/evidence/"+first["id"].(string), nil); code != 200 || out["entry"].(map[string]any)["id"] != first["id"] {
		t.Fatalf("one entry: %d %v", code, out)
	}
	if code, out := call(t, srv, http.MethodGet, "/instances/intro/evidence/ev_nope", nil); code != 404 || errCodeOf(out) != "PDR-E409" {
		t.Fatalf("unknown entry: %d %v", code, out)
	}
	if code, out := call(t, srv, http.MethodGet, "/instances/intro/evidence?since=yesterday", nil); code != 400 {
		t.Fatalf("a malformed since is 400: %d %v", code, out)
	}
	resp, err := http.Get(srv.URL + Prefix + "/instances/intro/evidence/report.junit.xml")
	if err != nil {
		t.Fatal(err)
	}
	xmlBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/xml") || !strings.Contains(string(xmlBody), `<testsuite name="baseline"`) || !strings.Contains(string(xmlBody), `<testsuite name="objective"`) {
		t.Fatalf("junit: %d %s %s", resp.StatusCode, resp.Header.Get("Content-Type"), xmlBody)
	}

	// Reset: the preview, then the job; objectives back to 0/2, progress cleared.
	code, out = call(t, srv, http.MethodGet, "/instances/intro/reset-plan", nil)
	plan, _ := out["reset_plan"].(map[string]any)
	if code != 200 || len(plan["destroyed"].([]any)) == 0 || len(plan["survives"].([]any)) == 0 {
		t.Fatalf("reset plan: %d %v", code, out)
	}
	code, out = call(t, srv, http.MethodPost, "/instances/intro/reset", nil)
	if code != http.StatusAccepted || out["job"].(map[string]any)["kind"] != "reset" {
		t.Fatalf("reset: %d %v", code, out)
	}
	waitJob(t, eng, out)
	if code, out := call(t, srv, http.MethodGet, "/instances/intro", nil); code != 200 || fmt.Sprint(out["instance"].(map[string]any)["checkpoints"]) != "map[baseline:map[passed:4 total:4] objective:map[failed:2 passed:0 total:2]]" {
		t.Fatalf("after reset: %d %v", code, out)
	}
	if code, out := call(t, srv, http.MethodGet, "/instances/intro/playbooks/first-dashboard/progress", nil); code != 200 || out["current_step"] != "meet-the-stack" {
		t.Fatalf("reset clears progress: %d %v", code, out)
	}
	// Malformed bodies are 400, never 500.
	resp, err = http.Post(srv.URL+Prefix+"/instances/intro/playbooks/first-dashboard/progress", "application/json", strings.NewReader("{not json"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 405 { // PUT is the verb; POST is not routed
		t.Fatalf("POST on progress: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodPut, srv.URL+Prefix+"/instances/intro/playbooks/first-dashboard/progress", strings.NewReader("{not json"))
	resp, err = srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&env)
	resp.Body.Close()
	if resp.StatusCode != 400 || errCodeOf(env) != "PDR-E406" {
		t.Fatalf("malformed progress: %d %v", resp.StatusCode, env)
	}
}

// The lab surface's statuses (API §3, §8–§10).
func TestLabStatusMapping(t *testing.T) {
	cases := map[string]int{"PDR-E403": 404, "PDR-E405": 404, "PDR-E407": 404, "PDR-E408": 404, "PDR-E409": 404, "PDR-E406": 400, "PDR-E410": 400, "PDR-E411": 500, "PDR-E404": 500}
	for code, want := range cases {
		if got := Status(code); got != want {
			t.Errorf("%s → %d, want %d", code, got, want)
		}
	}
}

// Scopes on the lab surface over the network door (API §2.4, §11): an
// instance-bound session reads its instance's checkpoints, verifies, runs
// checkpoints and reveals its own secrets, never another instance's; it
// cannot reset (operate); a read token cannot reveal (admin), an admin
// token can; every other instance is not found.
func TestLabSurfaceScopes(t *testing.T) {
	srv, api, authSvc := newNetworkServer(t)
	eng, store := engineOf[api], storeOf[api]
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	for _, name := range []string{"b1", "b2"} {
		job, err := eng.Create(context.Background(), engine.CreateRequest{Path: fixture, Name: name})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := eng.Wait(context.Background(), job.ID); err != nil {
			t.Fatal(err)
		}
	}
	// Gen is what a join would have copied from the credential: this
	// fixture builds the session by hand, and an instance-bound session
	// with no generation is one no join could produce.
	b1, err := store.GetInstance("b1")
	if err != nil {
		t.Fatal(err)
	}
	sess := &state.Session{ID: "s-b1", Subject: "alice", Mechanism: "instance-access", Instance: "b1", Gen: b1.AuditFrom, CSRF: "c-b1", Created: time.Now(), LastSeen: time.Now(), Expires: time.Now().Add(time.Hour)}
	if err := store.PutSession(*sess); err != nil {
		t.Fatal(err)
	}
	cookie, _ := authSvc.CookieValue(sess)
	bound := map[string]string{"Cookie": auth.CookieName + "=" + cookie, auth.CSRFHeader: sess.CSRF, "Content-Type": "application/json"}
	as := func(hdr map[string]string, method, path, body string) (int, map[string]any) {
		resp := do(t, srv, method, path, hdr, body)
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if code, out := as(bound, http.MethodGet, "/instances/b1/checkpoints", ""); code != 200 || len(out["checkpoints"].([]any)) != 0 {
		t.Fatalf("own checkpoints (none declared): %d %v", code, out)
	}
	for _, path := range []string{"/instances/b2/checkpoints", "/instances/b2/playbooks", "/instances/b2/secrets", "/instances/b2/evidence"} {
		if code, out := as(bound, http.MethodGet, path, ""); code != 404 || errCodeOf(out) != "PDR-E202" {
			t.Fatalf("%s must be not found for a bound session: %d %v", path, code, out)
		}
	}
	if code, out := as(bound, http.MethodPost, "/instances/b2/verify", "{}"); code != 404 || errCodeOf(out) != "PDR-E202" {
		t.Fatalf("verify of another instance: %d %v", code, out)
	}
	code, out := as(bound, http.MethodPost, "/instances/b1/verify", "{}")
	if code != http.StatusAccepted {
		t.Fatalf("a bound session verifies its instance: %d %v", code, out)
	}
	if _, err := eng.Wait(context.Background(), out["job"].(map[string]any)["id"].(string)); err != nil {
		t.Fatal(err)
	}
	if code, out := as(bound, http.MethodPost, "/instances/b1/reset", "{}"); code != 403 || errCodeOf(out) != "PDR-E304" {
		t.Fatalf("reset is outside the grant: %d %v", code, out)
	}
	// This used to require 403/PDR-E304 here, with the reason "seeds need
	// operate until S9 fills the grant". That was wrong: §2.4's grant
	// lists step seeds, attest and the learner's position among an
	// attendee's own writes, and S9 owns the *door* to such a session
	// (`pdi_`, `/join`, expiry, revoke), not what one may do once it
	// exists. The assertion was how the mistake stayed put, so it is
	// corrected rather than deleted.
	//
	// The fixture declares no seed, no checkpoint and no playbook, so the
	// answer is the engine's own not-found for each: the grant let the
	// request through and only the engine's reading of it refused.
	// Seeds are granted by the *step*, not by the endpoint: §2.4 says
	// "step seeds", and this fixture declares none, so the refusal is
	// right and its words say which rule refused (round 34). The grant's
	// seed half is exercised where a step seed exists.
	if code, out := as(bound, http.MethodPost, "/instances/b1/seeds/x", "{}"); code != 403 ||
		errCodeOf(out) != "PDR-E304" || !strings.Contains(messageOf(out), "step seeds only") {
		t.Fatalf("a seed no step invokes is outside the grant: %d %v", code, out)
	}
	if code, out := as(bound, http.MethodPost, "/instances/b1/checkpoints/x/attest", `{"note":"done"}`); errCodeOf(out) == "PDR-E304" {
		t.Fatalf("an attestation is in the grant: %d %v", code, out)
	}
	if code, out := as(bound, http.MethodPut, "/instances/b1/playbooks/x/progress", `{"current_step":"one"}`); errCodeOf(out) == "PDR-E304" {
		t.Fatalf("the learner's own position is in the grant: %d %v", code, out)
	}
	// And none of it on anyone else's lab.
	for _, c := range [][3]string{
		{http.MethodPost, "/instances/b2/seeds/x", "{}"},
		{http.MethodPost, "/instances/b2/checkpoints/x/attest", `{"note":"done"}`},
		{http.MethodPut, "/instances/b2/playbooks/x/progress", `{"current_step":"one"}`},
	} {
		if code, out := as(bound, c[0], c[1], c[2]); code != 404 || errCodeOf(out) != "PDR-E202" {
			t.Fatalf("%s %s on another instance: %d %v", c[0], c[1], code, out)
		}
	}
	// The grant is not a promotion: a read token still may not seed,
	// attest or write progress, which the §2.3 ladder puts at operate.
	roSecret, _, err := authSvc.CreateToken("ro-seed", auth.ScopeRead, "jross", auth.MechanismSocket)
	if err != nil {
		t.Fatal(err)
	}
	roSeed := map[string]string{"Authorization": "Bearer " + roSecret, "Content-Type": "application/json"}
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/instances/b1/seeds/x", "{}"},
		{http.MethodPost, "/instances/b1/checkpoints/x/attest", "{}"},
		{http.MethodPut, "/instances/b1/playbooks/x/progress", `{"current_step":"a"}`},
	} {
		if code, out := as(roSeed, c.method, c.path, c.body); code != 403 || errCodeOf(out) != "PDR-E304" {
			t.Fatalf("a read token must not %s %s: %d %v", c.method, c.path, code, out)
		}
	}
	// Logs are the one lab read the grant does not carry (API §7, D4):
	// a product's own output is where a lab's plumbing and an operator's
	// mistakes are visible. The refusal is by scope, on the attendee's
	// own instance, so it is the grant that stops it and not a lookup.
	if code, out := as(bound, http.MethodGet, "/instances/b1/services/web/logs", ""); code != 403 || errCodeOf(out) != "PDR-E304" {
		t.Fatalf("logs are outside the grant: %d %v", code, out)
	}
	// A bound session may reveal its own instance's secrets (there are
	// none on this fixture: E408, not a scope refusal).
	if code, out := as(bound, http.MethodPost, "/instances/b1/secrets/x/reveal", "{}"); code != 404 || errCodeOf(out) != "PDR-E408" {
		t.Fatalf("a bound session reaches its own reveal: %d %v", code, out)
	}
	if code, out := as(bound, http.MethodPost, "/instances/b2/secrets/x/reveal", "{}"); code != 404 || errCodeOf(out) != "PDR-E202" {
		t.Fatalf("another instance's reveal is not found: %d %v", code, out)
	}
	// Tokens: read reads and verifies but never reveals; admin reveals.
	readSecret, _, err := authSvc.CreateToken("ro", auth.ScopeRead, "jross", auth.MechanismSocket)
	if err != nil {
		t.Fatal(err)
	}
	ro := map[string]string{"Authorization": "Bearer " + readSecret, "Content-Type": "application/json"}
	// The same read the attendee is refused, a read token gets: §7 puts
	// logs at read, and the fake runtime's own record comes back.
	{
		resp := do(t, srv, http.MethodGet, "/instances/b1/services/web/logs", ro, "")
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), "podaro fake runtime") {
			t.Fatalf("a read token reads logs: %d %q", resp.StatusCode, string(body))
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Fatalf("logs are text, not JSON: %q", ct)
		}
	}
	// A service the template does not declare is named as such, with the
	// ones it does (PDR-E214).
	if code, out := as(ro, http.MethodGet, "/instances/b1/services/nope/logs", ""); code != 404 || errCodeOf(out) != "PDR-E214" {
		t.Fatalf("an unknown service: %d %v", code, out)
	}
	if code, out := as(ro, http.MethodGet, "/instances/b2/evidence", ""); code != 200 {
		t.Fatalf("a read token reads evidence: %d %v", code, out)
	}
	code, out = as(ro, http.MethodPost, "/instances/b1/secrets/x/reveal", "{}")
	details, _ := out["error"].(map[string]any)["details"].([]any)
	if code != 403 || errCodeOf(out) != "PDR-E304" || len(details) != 1 || details[0].(map[string]any)["hint"] != auth.ScopeAdmin {
		t.Fatalf("a read token must not reveal: %d %v", code, out)
	}
	if code, out := as(ro, http.MethodPost, "/instances/b1/reset", "{}"); code != 403 || errCodeOf(out) != "PDR-E304" {
		t.Fatalf("a read token must not reset: %d %v", code, out)
	}
	adminSecret, _, err := authSvc.CreateToken("adm", auth.ScopeAdmin, "jross", auth.MechanismSocket)
	if err != nil {
		t.Fatal(err)
	}
	adm := map[string]string{"Authorization": "Bearer " + adminSecret, "Content-Type": "application/json"}
	if code, out := as(adm, http.MethodPost, "/instances/b1/secrets/x/reveal", "{}"); code != 404 || errCodeOf(out) != "PDR-E408" {
		t.Fatalf("an admin token passes the reveal's scope check: %d %v", code, out)
	}
	// Cookie writes need the CSRF header on this surface too.
	noCSRF := map[string]string{"Cookie": auth.CookieName + "=" + cookie, "Content-Type": "application/json"}
	if code, out := as(noCSRF, http.MethodPost, "/instances/b1/verify", "{}"); code != 403 || errCodeOf(out) != "PDR-E305" {
		t.Fatalf("CSRF on a lab write: %d %v", code, out)
	}
}
