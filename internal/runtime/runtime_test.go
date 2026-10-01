// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The podman command lines are the contract with the host: loopback-only
// publishing, dropped capabilities, no new privileges, labels, env via
// file — never a value on the command line.
func TestCreateArgsPosture(t *testing.T) {
	args := CreateArgs(ContainerSpec{
		Name: "pdr-t1-web", Image: "docker.io/library/nginx@sha256:" + strings.Repeat("a", 64),
		Network: "pdr-t1", Alias: "web", Hostname: "web",
		Labels:  map[string]string{LabelInstance: "t1", LabelService: "web"},
		EnvFile: "/state/instances/t1/web.env", Publish: []int{8080, 80},
		CPU: "500m", Memory: "512MiB", Command: []string{"nginx", "-g", "daemon off;"},
	})
	got := strings.Join(args, " ")
	want := "create --name pdr-t1-web --network pdr-t1 --network-alias web --hostname web " +
		"--label dev.podaro/instance=t1 --label dev.podaro/service=web --env-file /state/instances/t1/web.env " +
		"--publish 127.0.0.1::80 --publish 127.0.0.1::8080 --cpus 0.5 --memory 512m " +
		"--security-opt no-new-privileges --cap-drop ALL docker.io/library/nginx@sha256:" + strings.Repeat("a", 64) +
		" nginx -g daemon off;"
	if got != want {
		t.Fatalf("create args:\n got %s\nwant %s", got, want)
	}
	if v := cpuValue("2"); v != "2" {
		t.Errorf("cpuValue(2) = %s", v)
	}
	if v := memoryValue("4GiB"); v != "4g" {
		t.Errorf("memoryValue(4GiB) = %s", v)
	}
}

func TestPodmanRefusesTags(t *testing.T) {
	p := &Podman{Exe: "podman", Exec: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		t.Fatalf("podman must not be invoked for a tag reference, got %v", args)
		return nil, nil
	}}
	if err := p.Pull(context.Background(), "docker.io/library/nginx:latest"); err == nil {
		t.Fatal("tag reference pulled")
	}
}

// Parsing pinned against the `podman inspect --format json` shape (Podman
// 4.x/5.x: Id, State.Running/ExitCode/StartedAt, NetworkSettings.Ports).
// Hand-written from the documented shape; a real VM confirms it at S10.
func TestParseInspect(t *testing.T) {
	out := []byte(`[{"Id":"abc123","State":{"Running":true,"ExitCode":0,"StartedAt":"2026-09-03T06:00:00.123456789Z"},
	"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"43127"}],"9200/tcp":[]}}}]`)
	st, err := ParseInspect(out)
	if err != nil {
		t.Fatal(err)
	}
	if st.ID != "abc123" || !st.Running || st.Ports[80] != 43127 || st.StartedAt.IsZero() {
		t.Fatalf("parsed %+v", st)
	}
	if _, ok := st.Ports[9200]; ok {
		t.Error("unbound port must not appear")
	}
	if st, err := ParseInspect([]byte("[]")); err != nil || st != nil {
		t.Errorf("empty inspect: %v %v", st, err)
	}
}

func TestPodmanObjectsUsesInstanceLabelFilters(t *testing.T) {
	var calls []string
	p := &Podman{Exe: "podman", Exec: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		switch args[0] {
		case "ps":
			return []byte(`[{"Names":["pdr-t1-web"]}]`), nil
		case "network":
			return []byte(`[{"name":"pdr-t1"}]`), nil
		case "volume":
			return []byte(`[]`), nil
		}
		return nil, nil
	}}
	o, err := p.Objects(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Containers) != 1 || len(o.Networks) != 1 || len(o.Volumes) != 0 || o.Empty() {
		t.Fatalf("objects = %+v", o)
	}
	secretLS := false
	for _, c := range calls {
		if strings.HasPrefix(c, "secret ls") {
			// Secret objects are named for the instance (a fixed-width
			// prefix), not label-filtered: not every Podman this release
			// supports filters secrets by label (plan S6).
			secretLS = true
			continue
		}
		if !strings.Contains(c, "--filter label=dev.podaro/instance=t1") {
			t.Errorf("call without the instance filter: %s", c)
		}
	}
	if !secretLS {
		t.Errorf("run secrets must be listed too: %v", calls)
	}
}

// testClock is a clock a test moves by hand, so a readiness delay is
// judged on it and never on the wall (round 53: a loaded CI runner passed
// the wall-clock delay before the "still starting" request went out).
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// The fake runtime: a started container answers real HTTP on loopback —
// 503 until its delay elapses on the fake's clock, then 200 — and the
// world survives a reload.
func TestFakeContainersServeReadiness(t *testing.T) {
	t.Setenv(EnvFakeReadyDelay, "300ms")
	path := filepath.Join(t.TempDir(), "world.json")
	f, err := NewFake(path)
	if err != nil {
		t.Fatal(err)
	}
	// The clock starts an hour ago, so the reloaded fake below (on the
	// wall clock) finds the delay long passed.
	clock := &testClock{t: time.Now().Add(-time.Hour)}
	f.now = clock.Now
	ctx := context.Background()
	image := "docker.io/library/nginx@sha256:" + strings.Repeat("b", 64)
	if err := f.Pull(ctx, image); err != nil {
		t.Fatal(err)
	}
	if err := f.EnsureNetwork(ctx, "pdr-t1", map[string]string{LabelInstance: "t1", LabelManaged: "true"}, false); err != nil {
		t.Fatal(err)
	}
	spec := ContainerSpec{Name: "pdr-t1-web", Image: image, Network: "pdr-t1", Labels: map[string]string{LabelInstance: "t1", LabelManaged: "true", LabelService: "web"}, Publish: []int{80}}
	id, err := f.Create(ctx, spec)
	if err != nil || id == "" {
		t.Fatalf("create: %v", err)
	}
	if id2, _ := f.Create(ctx, spec); id2 != id {
		t.Error("create is not idempotent")
	}
	if err := f.Start(ctx, "pdr-t1-web"); err != nil {
		t.Fatal(err)
	}
	st, _ := f.Inspect(ctx, "pdr-t1-web")
	url := "http://127.0.0.1:" + strconv.Itoa(st.Ports[80]) + "/"
	if resp, err := http.Get(url); err != nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("before the delay: %v %v", resp, err)
	}
	clock.Advance(299 * time.Millisecond)
	if resp, err := http.Get(url); err != nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a moment before the delay: %v %v", resp, err)
	}
	clock.Advance(time.Millisecond)
	if resp, err := http.Get(url); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("after the delay: %v %v", resp, err)
	}
	o, _ := f.Objects(ctx, "t1")
	if len(o.Containers) != 1 || len(o.Networks) != 1 {
		t.Fatalf("objects = %+v", o)
	}
	f.Close()

	// A reload (a restarted engine) finds the container running on the
	// same host port.
	g, err := NewFake(path)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	st2, _ := g.Inspect(ctx, "pdr-t1-web")
	if !st2.Running || st2.Ports[80] != st.Ports[80] {
		t.Fatalf("reloaded state %+v, want running on port %d", st2, st.Ports[80])
	}
	if resp, err := http.Get(url); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("after reload: %v %v", resp, err)
	}
	// A simulated reboot stops everything; Remove leaves nothing.
	g.Close()
	if err := Reboot(path); err != nil {
		t.Fatal(err)
	}
	h, _ := NewFake(path)
	defer h.Close()
	if st3, _ := h.Inspect(ctx, "pdr-t1-web"); st3.Running {
		t.Error("reboot must leave containers stopped")
	}
	if err := h.Remove(ctx, "pdr-t1-web"); err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveNetwork(ctx, "pdr-t1"); err != nil {
		t.Fatal(err)
	}
	if o, _ := h.Objects(ctx, "t1"); !o.Empty() {
		t.Errorf("objects remain: %+v", o)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("world file missing: %v", err)
	}
}

// Owned: a container or network found under Podaro's
// predictable name is adopted only when it is provably this instance's;
// anything else is refused, never started, never removed. An owned
// container whose spec digest differs is replaced, not resumed.
func TestOwnedRefusesForeignObjects(t *testing.T) {
	spec := ContainerSpec{Name: "pdr-t1-web", Image: "docker.io/library/nginx@sha256:abc", Labels: map[string]string{LabelManaged: "true", LabelInstance: "t1", LabelService: "web"}}
	mine := map[string]string{LabelManaged: "true", LabelInstance: "t1", LabelService: "web"}
	if err := Owned(mine, spec); err != nil {
		t.Fatalf("own container refused: %v", err)
	}
	cases := map[string]map[string]string{
		"unmanaged":      {},
		"other instance": {LabelManaged: "true", LabelInstance: "t2", LabelService: "web"},
		"other service":  {LabelManaged: "true", LabelInstance: "t1", LabelService: "db"},
	}
	for name, labels := range cases {
		if err := Owned(labels, spec); err == nil {
			t.Errorf("%s: adopted", name)
		}
	}
	if err := OwnedNetwork("pdr-t1", map[string]string{LabelManaged: "true", LabelInstance: "t1"}, map[string]string{LabelInstance: "t1"}); err != nil {
		t.Fatalf("own network refused: %v", err)
	}
	if err := OwnedNetwork("pdr-t1", map[string]string{"io.podman.compose.project": "x"}, map[string]string{LabelInstance: "t1"}); err == nil {
		t.Error("foreign network adopted")
	}
	if err := OwnedNetwork("pdr-t1", map[string]string{LabelManaged: "true", LabelInstance: "t2"}, map[string]string{LabelInstance: "t1"}); err == nil {
		t.Error("other instance's network adopted")
	}

	// The fake enforces the same rule end to end.
	f, err := NewFake(filepath.Join(t.TempDir(), "world.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx := context.Background()
	if err := f.EnsureNetwork(ctx, "pdr-t1", map[string]string{LabelInstance: "t9"}, false); err != nil {
		t.Fatal(err)
	}
	if err := f.EnsureNetwork(ctx, "pdr-t1", map[string]string{LabelManaged: "true", LabelInstance: "t1"}, false); err == nil {
		t.Fatal("fake adopted a foreign network")
	}
	_ = f.Pull(ctx, spec.Image)
	foreign := spec
	foreign.Labels = map[string]string{"com.example/owner": "someone-else"}
	foreign.Network = ""
	if _, err := f.Create(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Create(ctx, ContainerSpec{Name: spec.Name, Image: spec.Image, Labels: spec.Labels}); err == nil {
		t.Fatal("fake adopted a foreign container")
	}
	st, _ := f.Inspect(ctx, spec.Name)
	if st == nil || st.Labels["com.example/owner"] != "someone-else" || st.Image != spec.Image {
		t.Fatalf("fake inspect lacks ownership facts: %+v", st)
	}

	// Podman's inspect output carries the same facts.
	out := []byte(`[{"Id":"abc123","ImageName":"docker.io/library/nginx@sha256:abc","Config":{"Labels":{"dev.podaro/managed":"true","dev.podaro/instance":"t1"}},"State":{"Running":true,"ExitCode":0,"StartedAt":"2026-09-03T10:00:00Z"},"NetworkSettings":{"Ports":{}}}]`)
	pst, err := ParseInspect(out)
	if err != nil || pst.Image != spec.Image || pst.Labels[LabelInstance] != "t1" {
		t.Fatalf("ParseInspect ownership facts: %+v %v", pst, err)
	}
	labels, err := ParseNetworkLabels([]byte(`[{"name":"pdr-t1","labels":{"dev.podaro/managed":"true","dev.podaro/instance":"t1"}}]`))
	if err != nil || labels[LabelManaged] != "true" {
		t.Fatalf("ParseNetworkLabels: %v %v", labels, err)
	}
}

// A managed container is reused only while its spec digest matches; a
// changed env file, command, or port replaces it.
func TestCreateReplacesStaleManagedContainer(t *testing.T) {
	f, err := NewFake(filepath.Join(t.TempDir(), "world.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx := context.Background()
	image := "docker.io/library/nginx@sha256:abc"
	_ = f.Pull(ctx, image)
	envFile := filepath.Join(t.TempDir(), "web.env")
	_ = os.WriteFile(envFile, []byte("A=1\n"), 0o600)
	spec := ContainerSpec{Name: "pdr-t1-web", Image: image, Labels: map[string]string{LabelManaged: "true", LabelInstance: "t1", LabelService: "web"}, EnvFile: envFile, Command: []string{"nginx"}}
	id1, err := f.Create(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if id2, _ := f.Create(ctx, spec); id2 != id1 {
		t.Fatal("same spec must be reused")
	}
	d1, _ := spec.Digest()
	if got := f.Spec(spec.Name).Labels[LabelSpec]; got != d1 {
		t.Fatalf("spec label %q, digest %q", got, d1)
	}
	_ = os.WriteFile(envFile, []byte("A=2\n"), 0o600)
	d2, _ := spec.Digest()
	if d1 == d2 {
		t.Fatal("env content must change the digest")
	}
	id3, err := f.Create(ctx, spec)
	if err != nil || id3 == id1 {
		t.Fatalf("changed env must replace the container: %s %s %v", id1, id3, err)
	}
	spec.Command = []string{"nginx", "-g", "daemon off;"}
	if id4, _ := f.Create(ctx, spec); id4 == id3 {
		t.Fatal("changed command must replace the container")
	}
	if _, err := (ContainerSpec{Name: "x", EnvFile: "/nonexistent/env"}).Digest(); err == nil {
		t.Fatal("missing env file must fail the digest")
	}
}

// `podman container exists` distinguishes absent (1) from broken (125):
// only the former is nil, nil.
func TestInspectPropagatesPodmanFailures(t *testing.T) {
	dir := t.TempDir()
	script := func(name, code string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit "+code+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ctx := context.Background()
	absent := &Podman{Exe: script("absent", "1")}
	if st, err := absent.Inspect(ctx, "pdr-t1-web"); err != nil || st != nil {
		t.Fatalf("exit 1 must mean absent: %+v %v", st, err)
	}
	if _, exists, err := absent.InspectNetwork(ctx, "pdr-t1"); err != nil || exists {
		t.Fatalf("exit 1 must mean absent network: %v %v", exists, err)
	}
	broken := &Podman{Exe: script("broken", "125")}
	if _, err := broken.Inspect(ctx, "pdr-t1-web"); err == nil {
		t.Fatal("exit 125 must be an error, not absence")
	}
	if _, _, err := broken.InspectNetwork(ctx, "pdr-t1"); err == nil {
		t.Fatal("exit 125 must be an error for networks too")
	}
	if _, err := broken.Create(ctx, ContainerSpec{Name: "pdr-t1-web", Image: "img@sha256:x"}); err == nil {
		t.Fatal("create must not proceed after a failed inspection")
	}
	if err := broken.Remove(ctx, "pdr-t1-web"); err == nil {
		t.Fatal("remove must not proceed after a failed inspection")
	}
}

// A failed inspection never becomes a forced removal: with `container
// exists` broken (125) and `rm` willing, Remove returns the inspection
// error and `rm --force` is never invoked.
func TestRemoveNeverForcesAfterAFailedInspection(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	exe := filepath.Join(dir, "podman")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\ncase \"$1 $2\" in \"container exists\") exit 125;; esac\nexit 0\n"
	if err := os.WriteFile(exe, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &Podman{Exe: exe}
	if err := p.Remove(context.Background(), "pdr-t1-web"); err == nil {
		t.Fatal("a failed inspection must be returned, not swallowed")
	}
	calls, _ := os.ReadFile(log)
	if strings.Contains(string(calls), "rm") {
		t.Fatalf("rm must not run after a failed inspection: %s", calls)
	}
}

// A present container is removed with its anonymous volumes: an image's
// own VOLUME carries no instance label, so nothing else could find it.
func TestRemoveTakesAnonymousVolumes(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	exe := filepath.Join(dir, "podman")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\ncase \"$1\" in inspect) echo '[{\"Id\":\"abc\",\"State\":{\"Running\":false}}]';; esac\nexit 0\n"
	if err := os.WriteFile(exe, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &Podman{Exe: exe}
	if err := p.Remove(context.Background(), "pdr-t1-web"); err != nil {
		t.Fatal(err)
	}
	calls, _ := os.ReadFile(log)
	if !strings.Contains(string(calls), "rm --force --volumes pdr-t1-web") {
		t.Fatalf("the removal must take the container's anonymous volumes with it: %s", calls)
	}
}

// Entrypoint and command map to podman's --entrypoint (JSON form) and the
// trailing argv; env travels only as --env-file.
func TestCreateArgsEntrypointAndEnvFile(t *testing.T) {
	args := CreateArgs(ContainerSpec{Name: "pdr-t1-web", Image: "img@sha256:x", EnvFile: "/s/env/web.env", Entrypoint: []string{"/bin/sh", "-c"}, Command: []string{"echo", "hi there"}})
	joined := strings.Join(args, "\x00")
	for _, want := range []string{"--entrypoint\x00[\"/bin/sh\",\"-c\"]", "--env-file\x00/s/env/web.env", "img@sha256:x\x00echo\x00hi there"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args lack %q: %v", want, args)
		}
	}
	for _, a := range args {
		if strings.HasPrefix(a, "--env") && a != "--env-file" {
			t.Errorf("env value on argv: %s", a)
		}
	}
	f, _ := NewFake(filepath.Join(t.TempDir(), "w.json"))
	defer f.Close()
	ctx := context.Background()
	if _, exists, err := f.InspectNetwork(ctx, "pdr-none"); err != nil || exists {
		t.Fatalf("absent network: %v %v", exists, err)
	}
	_ = f.EnsureNetwork(ctx, "pdr-t1", map[string]string{LabelManaged: "true", LabelInstance: "t1"}, false)
	if labels, exists, err := f.InspectNetwork(ctx, "pdr-t1"); err != nil || !exists || labels[LabelInstance] != "t1" {
		t.Fatalf("network labels: %v %v %v", labels, exists, err)
	}
}

// RemoveNetwork never forces (a --force would take attached foreign
// containers with it) and treats `network exists` failures as failures.
func TestRemoveNetworkIsNeverForced(t *testing.T) {
	var calls [][]string
	p := &Podman{Exe: "podman", Exec: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, args)
		return nil, nil
	}}
	if err := p.RemoveNetwork(context.Background(), "pdr-t1"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || strings.Join(calls[1], " ") != "network rm pdr-t1" {
		t.Fatalf("argv: %v", calls)
	}
	dir := t.TempDir()
	broken := filepath.Join(dir, "podman")
	_ = os.WriteFile(broken, []byte("#!/bin/sh\nexit 125\n"), 0o755)
	if err := (&Podman{Exe: broken}).RemoveNetwork(context.Background(), "pdr-t1"); err == nil {
		t.Fatal("exit 125 on network exists must fail the removal")
	}
	absent := filepath.Join(dir, "absent")
	_ = os.WriteFile(absent, []byte("#!/bin/sh\nexit 1\n"), 0o755)
	if err := (&Podman{Exe: absent}).RemoveNetwork(context.Background(), "pdr-t1"); err != nil {
		t.Fatalf("absent network must be success: %v", err)
	}
}
