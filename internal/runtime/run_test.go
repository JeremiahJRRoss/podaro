// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

// The five walls as argv (Spec 0002 §2): the internal network only, stdin
// kept open, read-only rootfs with a 64 MiB /tmp, no capabilities, no new
// privileges, pids/cpu/memory capped, granted secrets as 0400 files owned
// by the image's user — and nothing else.
func TestRunCreateArgsWalls(t *testing.T) {
	spec := RunSpec{
		Name: "pdr-lab-run-abc", Image: "ghcr.io/acme/judge@sha256:" + strings.Repeat("a", 64), Network: "pdr-lab-int",
		Labels:  map[string]string{LabelInstance: "lab", LabelManaged: "true", LabelRun: "pdr-lab-run-abc"},
		EnvFile: "/state/instances/lab/env/run-abc.env", Command: []string{"--topic", "orders"},
		Secrets: []SecretFile{{Name: "hec-token", Source: "/s/hec-token"}, {Name: "admin", Source: "/s/admin"}},
		UID:     1000, GID: 1000, CPU: "1", Memory: "512MiB", Pids: 64,
	}
	got := strings.Join(RunCreateArgs(spec, map[string]string{"admin": "pdrs-x-admin", "hec-token": "pdrs-x-hec-token"}), " ")
	want := "create --name pdr-lab-run-abc --interactive --network pdr-lab-int" +
		" --label dev.podaro/instance=lab --label dev.podaro/managed=true --label dev.podaro/run=pdr-lab-run-abc" +
		" --env-file /state/instances/lab/env/run-abc.env" +
		" --read-only --tmpfs /tmp:rw,size=64m,mode=1777 --security-opt no-new-privileges --cap-drop ALL --pids-limit 64 --cpus 1 --memory 512m" +
		" --secret source=pdrs-x-admin,type=mount,target=/run/podaro/secrets/admin,mode=0400,uid=1000,gid=1000" +
		" --secret source=pdrs-x-hec-token,type=mount,target=/run/podaro/secrets/hec-token,mode=0400,uid=1000,gid=1000" +
		" " + spec.Image + " --topic orders"
	if got != want {
		t.Fatalf("run create args:\n got %s\nwant %s", got, want)
	}
	// Defaults (Spec 0002 §2): 500m CPU · 256 MiB · 128 pids · 64 MiB tmpfs.
	def := strings.Join(RunCreateArgs(RunSpec{Name: "r", Image: "i", Network: "n"}, nil), " ")
	for _, flag := range []string{"--pids-limit 128", "--cpus 0.5", "--memory 256m", "--tmpfs /tmp:rw,size=64m,mode=1777", "--read-only", "--cap-drop ALL", "--interactive"} {
		if !strings.Contains(def, flag) {
			t.Errorf("default run args lack %q: %s", flag, def)
		}
	}
	for _, never := range []string{"--publish", "--privileged", "--network host", "--user"} {
		if strings.Contains(def, never) {
			t.Errorf("run args must never carry %q: %s", never, def)
		}
	}
}

func TestNetworkCreateArgsInternal(t *testing.T) {
	labels := map[string]string{LabelInstance: "lab", LabelManaged: "true"}
	if got := strings.Join(NetworkCreateArgs("pdr-lab-int", labels, true), " "); got != "network create --internal --label dev.podaro/instance=lab --label dev.podaro/managed=true pdr-lab-int" {
		t.Fatalf("internal: %s", got)
	}
	if got := strings.Join(NetworkCreateArgs("pdr-lab", labels, false), " "); strings.Contains(got, "--internal") {
		t.Fatalf("the lab network keeps its route out (threat model B5, accepted residual): %s", got)
	}
}

// Lab containers join the internal network beside their own, and files
// change the spec digest, so a changed config file replaces the container.
func TestCreateArgsJoinsExtraNetworksAndFilesShapeTheDigest(t *testing.T) {
	spec := ContainerSpec{Name: "pdr-lab-grafana", Image: "docker.io/grafana/grafana@sha256:" + strings.Repeat("c", 64), Network: "pdr-lab", Networks: []string{"pdr-lab-int"}, Alias: "grafana"}
	got := strings.Join(CreateArgs(spec), " ")
	if !strings.Contains(got, "--network pdr-lab --network pdr-lab-int --network-alias grafana") {
		t.Fatalf("networks: %s", got)
	}
	d1, _ := spec.Digest()
	spec.Files = []FileSpec{{Path: "/etc/grafana/provisioning/datasources/prometheus.yaml", Mode: 0o644, Content: []byte("apiVersion: 1\n")}}
	d2, _ := spec.Digest()
	spec.Files[0].Content = []byte("apiVersion: 2\n")
	d3, _ := spec.Digest()
	if d1 == d2 || d2 == d3 {
		t.Fatalf("files must shape the digest: %s %s %s", d1, d2, d3)
	}
}

// recorder is an Exec seam that records command lines and answers by
// prefix.
type recorder struct {
	calls   []string
	answers map[string]func(args []string) ([]byte, error)
}

func (r *recorder) exec(ctx context.Context, name string, args ...string) ([]byte, error) {
	line := strings.Join(args, " ")
	r.calls = append(r.calls, line)
	for prefix, fn := range r.answers {
		if strings.HasPrefix(line, prefix) {
			return fn(args)
		}
	}
	return nil, nil
}

func (r *recorder) has(prefix string) bool {
	for _, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// copyIn walks up to an ancestor that exists: a file whose parent is
// absent in the image is copied as its parent directory (contents, `/.`),
// and a parent absent too as the grandparent — never a bind mount.
func TestCopyInWalksUpToAnExistingAncestor(t *testing.T) {
	rec := &recorder{answers: map[string]func([]string) ([]byte, error){}}
	missing := func(args []string) ([]byte, error) {
		return nil, &CommandError{Args: args, Stderr: `Error: "/tmp/defaults" could not be found on container c: no such file or directory`}
	}
	rec.answers["cp "] = func(args []string) ([]byte, error) {
		dst := args[2]
		switch dst {
		case "c:/tmp/defaults/default.yml", "c:/tmp/defaults":
			return missing(args)
		}
		return nil, nil
	}
	p := &Podman{Exe: "podman", Exec: rec.exec}
	files := []FileSpec{
		{Path: "/etc/prometheus/prometheus.yml", Mode: 0o644, Content: []byte("global: {}\n")},
		{Path: "/tmp/defaults/default.yml", Mode: 0o600, Content: []byte("defaults: {}\n")},
	}
	if err := p.copyIn(context.Background(), "c", files); err != nil {
		t.Fatal(err)
	}
	var cps []string
	for _, c := range rec.calls {
		if strings.HasPrefix(c, "cp ") {
			f := strings.Fields(c)
			cps = append(cps, f[1][strings.LastIndex(f[1], "/podaro-files-"):]+" → "+f[2])
		}
	}
	want := []string{
		"/podaro-files-*/etc/prometheus/prometheus.yml → c:/etc/prometheus/prometheus.yml",
		"/podaro-files-*/tmp/defaults/default.yml → c:/tmp/defaults/default.yml",
		"/podaro-files-*/tmp/defaults/. → c:/tmp/defaults",
		"/podaro-files-*/tmp/. → c:/tmp",
	}
	if len(cps) != len(want) {
		t.Fatalf("cp sequence: %v", cps)
	}
	for i := range want {
		got := cps[i]
		// The staging directory's random suffix is not what is pinned.
		got = got[:len("/podaro-files-")] + "*" + got[strings.Index(got[len("/podaro-files-"):], "/")+len("/podaro-files-"):]
		if got != want[i] {
			t.Errorf("cp %d = %s, want %s", i, got, want[i])
		}
	}
	// A refusal that is not "missing parent" stops the copy, named.
	rec2 := &recorder{answers: map[string]func([]string) ([]byte, error){"cp ": func(args []string) ([]byte, error) {
		return nil, &CommandError{Args: args, Stderr: "Error: permission denied"}
	}}}
	p2 := &Podman{Exe: "podman", Exec: rec2.exec}
	if err := p2.copyIn(context.Background(), "c", files[:1]); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("a real refusal must surface: %v", err)
	}
	if len(rec2.calls) != 1 {
		t.Fatalf("no walk-up on a real refusal: %v", rec2.calls)
	}
	// A create whose copy fails takes the container with it: a container
	// standing without its files would be adopted as complete by the next
	// attempt (the files are in the digest).
	rec3 := &recorder{answers: map[string]func([]string) ([]byte, error){
		"container exists": func(args []string) ([]byte, error) { return nil, &fakeExit{code: 1} },
		"create ":          func(args []string) ([]byte, error) { return []byte("c1d000000000001\n"), nil },
		"cp ": func(args []string) ([]byte, error) {
			return nil, &CommandError{Args: args, Stderr: "Error: permission denied"}
		},
	}}
	p3 := &Podman{Exe: "podman", Exec: rec3.exec}
	if _, err := p3.Create(context.Background(), ContainerSpec{Name: "c", Image: "img@sha256:x", Files: files[:1]}); err == nil {
		t.Fatal("create must fail when its files cannot be copied in")
	}
	if !rec3.has("rm --force --volumes c1d000000000001") {
		t.Fatalf("the half-made container must be removed: %v", rec3.calls)
	}
}

type fakeExit struct{ code int }

func (f *fakeExit) Error() string { return fmt.Sprintf("exit %d", f.code) }
func (f *fakeExit) ExitCode() int { return f.code }

// Run: secrets become objects, the container is created with the walls,
// started attached with the input on stdin, and everything is removed
// afterwards — on a timeout too.
func TestRunAttachesAndCleansUp(t *testing.T) {
	rec := &recorder{answers: map[string]func([]string) ([]byte, error){"create ": func([]string) ([]byte, error) { return []byte("c1d000000000001\n"), nil }}}
	var gotStdin []byte
	p := &Podman{Exe: "podman", Exec: rec.exec, Attach: func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, []byte, int, error) {
		rec.calls = append(rec.calls, "ATTACH "+strings.Join(args, " "))
		gotStdin = stdin
		return []byte(`{"contract":"podaro.dev/exec/v1","status":"pass"}`), []byte("chatter"), 0, nil
	}}
	secretFile := filepath.Join(t.TempDir(), "admin")
	_ = os.WriteFile(secretFile, []byte("s3cret"), 0o600)
	spec := RunSpec{Name: "pdr-lab-run-1", Image: "img@sha256:x", Network: "pdr-lab-int", Labels: map[string]string{LabelInstance: "lab"},
		Secrets: []SecretFile{{Name: "admin", Source: secretFile}}, UID: 1000, GID: 1000, Stdin: []byte(`{"contract":"podaro.dev/exec/v1"}`), Timeout: time.Second}
	res, err := p.Run(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || string(res.Stdout) != `{"contract":"podaro.dev/exec/v1","status":"pass"}` || string(res.Stderr) != "chatter" || res.TimedOut {
		t.Fatalf("result: %+v", res)
	}
	if string(gotStdin) != `{"contract":"podaro.dev/exec/v1"}` {
		t.Fatalf("stdin: %s", gotStdin)
	}
	secretName := SecretPrefix("lab")
	steps := []string{"secret create " + secretName, "create --name pdr-lab-run-1 --interactive --network pdr-lab-int", "ATTACH start --attach --interactive c1d000000000001", "rm --force --ignore --volumes c1d000000000001", "secret rm " + secretName}
	at := 0
	for _, c := range rec.calls {
		if at < len(steps) && strings.HasPrefix(c, steps[at]) {
			at++
		}
	}
	if at != len(steps) {
		t.Fatalf("run sequence: reached step %d of %v in %v", at, steps, rec.calls)
	}
	for _, c := range rec.calls {
		if strings.Contains(c, "s3cret") {
			t.Fatalf("a secret value on a command line: %s", c)
		}
	}
	// The secret object's name carries the instance whole, ended by an
	// underscore no instance name can carry: no other instance's prefix
	// matches, hyphens or not, and no hash can collide — `lab-41265` and
	// `lab-150237` shared a 32-bit one.
	for _, pair := range [][2]string{{"lab", "lab-2"}, {"lab-41265", "lab-150237"}} {
		a, b := SecretPrefix(pair[0]), SecretPrefix(pair[1])
		if a == b || strings.HasPrefix(a, b) || strings.HasPrefix(b, a) {
			t.Fatalf("the secret prefixes of %q and %q overlap: %q %q", pair[0], pair[1], a, b)
		}
	}

	// Timeout: the attach outlives the budget; the run reports TimedOut and
	// the container is killed (rm --force) all the same.
	rec2 := &recorder{answers: map[string]func([]string) ([]byte, error){"create ": func([]string) ([]byte, error) { return []byte("c1d000000000001\n"), nil }}}
	p2 := &Podman{Exe: "podman", Exec: rec2.exec, Attach: func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, []byte, int, error) {
		<-ctx.Done()
		return nil, []byte("killed"), -1, ctx.Err()
	}}
	res, err = p2.Run(context.Background(), RunSpec{Name: "pdr-lab-run-2", Image: "img@sha256:x", Network: "pdr-lab-int", Timeout: 20 * time.Millisecond})
	if err != nil || !res.TimedOut || res.ExitCode != -1 {
		t.Fatalf("timeout result: %+v %v", res, err)
	}
	if !rec2.has("rm --force --ignore --volumes c1d000000000001") {
		t.Fatalf("a timed-out run must be removed: %v", rec2.calls)
	}
	// A create the runtime refuses is an error, never a result, and the
	// secrets made before it are removed.
	rec3 := &recorder{answers: map[string]func([]string) ([]byte, error){"create ": func(args []string) ([]byte, error) {
		return nil, &CommandError{Args: args, Stderr: "Error: no such network"}
	}}}
	p3 := &Podman{Exe: "podman", Exec: rec3.exec}
	if _, err := p3.Run(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "no such network") {
		t.Fatalf("create refusal: %v", err)
	}
	if !rec3.has("secret rm " + secretName) {
		t.Fatalf("secrets must be removed after a refused create: %v", rec3.calls)
	}
}

// A secret create Podman answered with an error — the name in use first
// of all — made nothing, and nothing under that name is the run's to
// remove; the object's name ends with the run's own id, so two runs of
// one checkpoint never share one; and a create the budget cut off, which
// may have committed the object, is removed under that name.
func TestARefusedSecretCreateRemovesNothing(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "admin")
	_ = os.WriteFile(secretFile, []byte("s3cret"), 0o600)
	spec := RunSpec{Name: "pdr-lab-run-1", Image: "img@sha256:x", Network: "pdr-lab-int", Labels: map[string]string{LabelInstance: "lab"},
		Secrets: []SecretFile{{Name: "admin", Source: secretFile}}, UID: 1000, GID: 1000, Timeout: time.Second}
	rec := &recorder{answers: map[string]func([]string) ([]byte, error){"secret create ": func(args []string) ([]byte, error) {
		return nil, &CommandError{Args: args, Stderr: "Error: creating secret: name in use"}
	}}}
	p := &Podman{Exe: "podman", Exec: rec.exec}
	if _, err := p.Run(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "name in use") {
		t.Fatalf("refused create: %v", err)
	}
	for _, c := range rec.calls {
		if strings.HasPrefix(c, "secret rm ") {
			t.Fatalf("a refused create made nothing, yet the run removed a secret object: %s", c)
		}
	}
	// The name is the run's own: `pdrs-<instance>_<run>_<secret>_<run id>`,
	// a different id on every run.
	created := func(r *recorder) string {
		for _, c := range r.calls {
			if strings.HasPrefix(c, "secret create ") {
				return strings.Fields(c)[2]
			}
		}
		return ""
	}
	attach := func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, []byte, int, error) {
		return []byte(`{"contract":"podaro.dev/exec/v1","status":"pass"}`), nil, 0, nil
	}
	answers := map[string]func([]string) ([]byte, error){"create ": func([]string) ([]byte, error) { return []byte("c1d000000000001\n"), nil }}
	rec1, rec2 := &recorder{answers: answers}, &recorder{answers: answers}
	for _, r := range []*recorder{rec1, rec2} {
		if _, err := (&Podman{Exe: "podman", Exec: r.exec, Attach: attach}).Run(context.Background(), spec); err != nil {
			t.Fatal(err)
		}
	}
	n1, n2 := created(rec1), created(rec2)
	prefix := SecretPrefix("lab") + "run-1_admin_"
	if !strings.HasPrefix(n1, prefix) || !strings.HasPrefix(n2, prefix) || n1 == n2 || !regexp.MustCompile(`_[0-9a-f]{16}$`).MatchString(n1) {
		t.Fatalf("secret object names must be the run's own: %q %q", n1, n2)
	}
	if !rec1.has("secret rm "+n1) || !rec2.has("secret rm "+n2) {
		t.Fatalf("each run removes its own object: %v %v", rec1.calls, rec2.calls)
	}
	// A create the budget cut off: the object may exist, under a name no
	// other run can hold, and the cleanup takes it back.
	var calls []string
	var mu sync.Mutex
	p3 := &Podman{Exe: "podman", Exec: func(c context.Context, _ string, args ...string) ([]byte, error) {
		line := strings.Join(args, " ")
		mu.Lock()
		calls = append(calls, line)
		mu.Unlock()
		if strings.HasPrefix(line, "secret create ") {
			<-c.Done()
			return nil, &CommandError{Args: args, Err: c.Err(), Stderr: "killed"}
		}
		return nil, nil
	}, Attach: attach}
	spec3 := spec
	spec3.Timeout = 20 * time.Millisecond
	res, err := p3.Run(context.Background(), spec3)
	if err != nil || !res.TimedOut {
		t.Fatalf("cut-off create: %+v %v", res, err)
	}
	mu.Lock()
	defer mu.Unlock()
	name3, removed := "", false
	for _, c := range calls {
		if strings.HasPrefix(c, "secret create ") {
			name3 = strings.Fields(c)[2]
		}
		if name3 != "" && c == "secret rm "+name3 {
			removed = true
		}
	}
	if name3 == "" || !removed {
		t.Fatalf("a create the budget cut off is removed under the run's own name: %v", calls)
	}
}

// ImageUser: numeric USERs are read straight; a named USER is resolved in
// the image's own /etc/passwd, read out of a created — never started —
// container; one that cannot be resolved is reported so, never as root
// and never as a guess.
func TestImageUserResolution(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/sh\ncurl_user:x:100:101:curl user:/home/curl_user:/bin/sh\n"
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	_ = tw.WriteHeader(&tar.Header{Name: "passwd", Mode: 0o644, Size: int64(len(passwd)), Typeflag: tar.TypeReg})
	_, _ = io.WriteString(tw, passwd)
	_ = tw.Close()
	cases := []struct {
		user     string
		want     ImageUser
		resolves bool
	}{
		{"", ImageUser{Raw: ""}, false},
		{"0", ImageUser{Raw: "0", UID: 0, Resolved: true}, false},
		{"root", ImageUser{Raw: "root", UID: 0, GID: 0, Resolved: true}, true},
		{"1000", ImageUser{Raw: "1000", UID: 1000, Resolved: true}, false},
		{"1000:1000", ImageUser{Raw: "1000:1000", UID: 1000, GID: 1000, Resolved: true}, false},
		{"curl_user", ImageUser{Raw: "curl_user", UID: 100, GID: 101, Resolved: true}, true},
		{"curl_user:200", ImageUser{Raw: "curl_user:200", UID: 100, GID: 200, Resolved: true}, true},
		{"nobody", ImageUser{Raw: "nobody", Resolved: false}, true},
	}
	for _, c := range cases {
		rec := &recorder{answers: map[string]func([]string) ([]byte, error){
			"image inspect": func(args []string) ([]byte, error) {
				return []byte(fmt.Sprintf(`[{"Config":{"User":%q}}]`, c.user)), nil
			},
			"create --name pdr-inspect-":   func(args []string) ([]byte, error) { return []byte("00112233445566778899aabb\n"), nil },
			"cp 00112233445566778899aabb:": func(args []string) ([]byte, error) { return tarBuf.Bytes(), nil },
		}}
		p := &Podman{Exe: "podman", Exec: rec.exec}
		got, err := p.ImageUser(context.Background(), "img@sha256:x")
		if err != nil {
			t.Fatalf("%q: %v", c.user, err)
		}
		if got != c.want {
			t.Errorf("USER %q: got %+v, want %+v", c.user, got, c.want)
		}
		if c.resolves != rec.has("cp 00112233445566778899aabb:") {
			t.Errorf("USER %q: passwd lookup = %v, want %v (%v)", c.user, rec.has("cp 00112233445566778899aabb:"), c.resolves, rec.calls)
		}
		if rec.has("start") || rec.has("run ") {
			t.Errorf("USER %q: nothing of the image may run to find its user: %v", c.user, rec.calls)
		}
		if c.resolves && !rec.has("rm --force --ignore --volumes 00112233445566778899aabb") {
			t.Errorf("USER %q: the inspection container must be removed: %v", c.user, rec.calls)
		}
	}
	if !(ImageUser{Raw: ""}).Root() || !(ImageUser{Raw: "0", UID: 0, Resolved: true}).Root() || (ImageUser{Raw: "1000", UID: 1000, Resolved: true}).Root() || (ImageUser{Raw: "nobody"}).Root() {
		t.Fatal("Root(): no USER and uid 0 are root; a non-zero or unresolved user is not")
	}
}

func TestObjectsListsRunSecretsByPrefix(t *testing.T) {
	rec := &recorder{answers: map[string]func([]string) ([]byte, error){
		"ps":         func([]string) ([]byte, error) { return []byte(`[]`), nil },
		"network ls": func([]string) ([]byte, error) { return []byte(`[]`), nil },
		"volume ls":  func([]string) ([]byte, error) { return []byte(`[]`), nil },
		"secret ls": func([]string) ([]byte, error) {
			return []byte(fmt.Sprintf(`[{"ID":"1","Spec":{"Name":%q}},{"ID":"2","Spec":{"Name":%q}},{"ID":"3","Spec":{"Name":"user-secret"}}]`, SecretPrefix("lab")+"aaaa-admin", SecretPrefix("lab-2")+"bbbb-admin")), nil
		},
	}}
	p := &Podman{Exe: "podman", Exec: rec.exec}
	objs, err := p.Objects(context.Background(), "lab")
	if err != nil || len(objs.Secrets) != 1 || objs.Secrets[0] != SecretPrefix("lab")+"aaaa-admin" || objs.Empty() {
		t.Fatalf("objects: %+v %v", objs, err)
	}
	if err := p.RemoveSecret(context.Background(), "gone"); err != nil {
		t.Fatalf("removing a secret that is not there: %v", err)
	}
}

// --- the fake ------------------------------------------------------------

func newTestFake(t *testing.T) *Fake {
	t.Helper()
	t.Setenv(EnvFakeReadyDelay, "0s")
	f, err := NewFake(filepath.Join(t.TempDir(), "world.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	return f
}

func startFake(t *testing.T, f *Fake, spec ContainerSpec) *ContainerState {
	t.Helper()
	ctx := context.Background()
	_ = f.Pull(ctx, spec.Image)
	if _, err := f.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := f.Start(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
	st, err := f.Inspect(ctx, spec.Name)
	if err != nil || st == nil || !st.Running {
		t.Fatalf("inspect: %+v %v", st, err)
	}
	return st
}

func getJSON(t *testing.T, url string, out any) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil {
		_ = json.Unmarshal(raw, out)
	}
	return resp.StatusCode
}

func TestFakePrometheusPersonality(t *testing.T) {
	f := newTestFake(t)
	ctx := context.Background()
	labels := map[string]string{LabelInstance: "lab", LabelManaged: "true"}
	_ = f.EnsureNetwork(ctx, "pdr-lab", labels, false)
	_ = f.EnsureNetwork(ctx, "pdr-lab-int", labels, true)
	if !f.Internal("pdr-lab-int") || f.Internal("pdr-lab") {
		t.Fatal("internal flag")
	}
	prom := startFake(t, f, ContainerSpec{Name: "pdr-lab-prometheus", Image: "docker.io/prom/prometheus@sha256:" + strings.Repeat("1", 64), Network: "pdr-lab", Networks: []string{"pdr-lab-int"}, Alias: "prometheus", Labels: map[string]string{LabelInstance: "lab", LabelManaged: "true", LabelService: "prometheus"}, Publish: []int{9090}})
	base := fmt.Sprintf("http://127.0.0.1:%d", prom.Ports[9090])
	if getJSON(t, base+"/-/ready", nil) != 200 {
		t.Fatal("ready")
	}
	type resp struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Value []any `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	query := func(q string) (int, []string) {
		var r resp
		code := getJSON(t, base+"/api/v1/query?query="+strings.ReplaceAll(q, "\"", "%22"), &r)
		var values []string
		for _, s := range r.Data.Result {
			values = append(values, fmt.Sprint(s.Value[1]))
		}
		return code, values
	}
	if code, v := query(`up{job="prometheus"}`); code != 200 || len(v) != 1 || v[0] != "1" {
		t.Fatalf("self scrape: %d %v", code, v)
	}
	if _, v := query(`up{job="grafana"}`); len(v) != 0 {
		t.Fatalf("grafana not running yet: %v", v)
	}
	startFake(t, f, ContainerSpec{Name: "pdr-lab-grafana", Image: "docker.io/grafana/grafana@sha256:" + strings.Repeat("2", 64), Network: "pdr-lab", Networks: []string{"pdr-lab-int"}, Alias: "grafana", Labels: map[string]string{LabelInstance: "lab", LabelManaged: "true", LabelService: "grafana"}, Publish: []int{3000}})
	if _, v := query(`up{job="grafana"}`); len(v) != 1 || v[0] != "1" {
		t.Fatalf("a running sibling is scraped: %v", v)
	}
	// The counter reads the queries served before this one.
	_, v := query(`sum(prometheus_http_requests_total{handler="/api/v1/query"})`)
	if len(v) != 1 || v[0] != "3" {
		t.Fatalf("counter after three queries: %v", v)
	}
	if f.Queries("pdr-lab-prometheus") != 4 {
		t.Fatalf("queries served: %d", f.Queries("pdr-lab-prometheus"))
	}
}

func TestFakeGrafanaPersonality(t *testing.T) {
	f := newTestFake(t)
	ctx := context.Background()
	_ = f.EnsureNetwork(ctx, "pdr-lab", map[string]string{LabelInstance: "lab", LabelManaged: "true"}, false)
	envFile := filepath.Join(t.TempDir(), "grafana.env")
	_ = os.WriteFile(envFile, []byte("GF_SECURITY_ADMIN_PASSWORD=correct-horse\nGF_SECURITY_ALLOW_EMBEDDING=true\n"), 0o600)
	spec := ContainerSpec{Name: "pdr-lab-grafana", Image: "docker.io/grafana/grafana@sha256:" + strings.Repeat("2", 64), Network: "pdr-lab", Alias: "grafana", Labels: map[string]string{LabelInstance: "lab", LabelManaged: "true", LabelService: "grafana"}, Publish: []int{3000}, EnvFile: envFile,
		Files: []FileSpec{{Path: "/etc/grafana/provisioning/datasources/prometheus.yaml", Mode: 0o644, Content: []byte("apiVersion: 1\n")}}}
	st := startFake(t, f, spec)
	if files := f.Files("pdr-lab-grafana"); len(files) != 1 || files[0].Path != spec.Files[0].Path || files[0].Mode != 0o644 || files[0].Sum == "" {
		t.Fatalf("files recorded: %+v", files)
	}
	if raw, _ := os.ReadFile(f.path); bytes.Contains(raw, []byte("apiVersion: 1")) || bytes.Contains(raw, []byte("correct-horse")) {
		t.Fatal("the world file must carry neither file content nor secrets")
	}
	base := fmt.Sprintf("http://127.0.0.1:%d", st.Ports[3000])
	if getJSON(t, base+"/api/health", nil) != 200 {
		t.Fatal("health")
	}
	var list []map[string]any
	getJSON(t, base+"/api/search?query=Lab%20Overview", &list)
	if len(list) != 0 {
		t.Fatalf("no dashboards yet: %v", list)
	}
	post := func(user, pass string) int {
		req, _ := http.NewRequest(http.MethodPost, base+"/api/dashboards/db", strings.NewReader(`{"dashboard":{"title":"Lab Overview","panels":[]},"overwrite":false}`))
		req.Header.Set("Content-Type", "application/json")
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if post("", "") != 401 || post("admin", "wrong") != 401 {
		t.Fatal("dashboards need the admin password the env file carried")
	}
	if post("admin", "correct-horse") != 200 {
		t.Fatal("create dashboard")
	}
	getJSON(t, base+"/api/search?query=Lab%20Overview", &list)
	if len(list) != 1 || list[0]["title"] != "Lab Overview" {
		t.Fatalf("search: %v", list)
	}
	// A stop/start keeps the dashboard (the container's storage); a
	// replacement or removal loses it.
	_ = f.Stop(ctx, "pdr-lab-grafana", time.Second)
	_ = f.Start(ctx, "pdr-lab-grafana")
	st, _ = f.Inspect(ctx, "pdr-lab-grafana")
	base = fmt.Sprintf("http://127.0.0.1:%d", st.Ports[3000])
	getJSON(t, base+"/api/search?query=lab", &list)
	if len(list) != 1 {
		t.Fatalf("dashboards survive a restart: %v", list)
	}
	_ = f.Remove(ctx, "pdr-lab-grafana")
	st = startFake(t, f, spec)
	base = fmt.Sprintf("http://127.0.0.1:%d", st.Ports[3000])
	getJSON(t, base+"/api/search?query=lab", &list)
	if len(list) != 0 {
		t.Fatalf("dashboards go with the container: %v", list)
	}
}

func TestFakeRunEnforcesTheNetworkWall(t *testing.T) {
	f := newTestFake(t)
	ctx := context.Background()
	image := "docker.io/podaro/exec-conformance@sha256:" + strings.Repeat("e", 64)
	_ = f.Pull(ctx, image)
	labels := map[string]string{LabelInstance: "lab", LabelManaged: "true"}
	_ = f.EnsureNetwork(ctx, "pdr-lab", labels, false)
	if _, err := f.Run(ctx, RunSpec{Name: "r", Image: image, Network: "pdr-lab", Stdin: []byte(`{}`)}); err == nil || !strings.Contains(err.Error(), "internal network") {
		t.Fatalf("a run on the lab network must be refused: %v", err)
	}
	if _, err := f.Run(ctx, RunSpec{Name: "r", Image: image, Network: "pdr-nope", Stdin: []byte(`{}`)}); err == nil {
		t.Fatal("a run on an absent network must be refused")
	}
	if _, err := f.Run(ctx, RunSpec{Name: "r", Image: "docker.io/other/thing@sha256:" + strings.Repeat("f", 64), Network: "pdr-lab-int"}); err == nil {
		t.Fatal("an unpulled image must be refused")
	}
}

func TestFakeConformanceBehaviors(t *testing.T) {
	f := newTestFake(t)
	ctx := context.Background()
	image := "docker.io/podaro/exec-conformance@sha256:" + strings.Repeat("e", 64)
	_ = f.Pull(ctx, image)
	labels := map[string]string{LabelInstance: "lab", LabelManaged: "true"}
	_ = f.EnsureNetwork(ctx, "pdr-lab-int", labels, true)
	stdin := []byte(`{"contract":"podaro.dev/exec/v1","kind":"checkpoint","run_id":"run_1","instance":{"name":"lab","endpoints":[{"service":"web"}]},"secrets":{"granted":["tok"]},"checkpoint":{"id":"c","expect":{"lag":0}}}`)
	run := func(mode string, extra RunSpec) *RunResult {
		spec := RunSpec{Name: "pdr-lab-run-" + mode, Image: image, Network: "pdr-lab-int", Labels: labels, Command: []string{mode}, Stdin: stdin, Timeout: extra.Timeout, Secrets: extra.Secrets}
		res, err := f.Run(ctx, spec)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		return res
	}
	var verdict struct {
		Contract string          `json:"contract"`
		Status   string          `json:"status"`
		Observed json.RawMessage `json:"observed"`
		Message  string          `json:"message"`
		Evidence struct {
			Capture map[string]any `json:"capture"`
		} `json:"evidence"`
	}
	res := run("pass", RunSpec{})
	if res.ExitCode != 0 || json.Unmarshal(res.Stdout, &verdict) != nil || verdict.Status != "pass" || string(verdict.Observed) != `{"lag":0}` || verdict.Contract != "podaro.dev/exec/v1" {
		t.Fatalf("pass: %+v %s", res, res.Stdout)
	}
	if verdict.Evidence.Capture["endpoints"] != float64(1) || fmt.Sprint(verdict.Evidence.Capture["secrets"]) != "[tok]" || verdict.Evidence.Capture["run_id"] != "run_1" {
		t.Fatalf("capture: %v", verdict.Evidence.Capture)
	}
	res = run("fail", RunSpec{})
	_ = json.Unmarshal(res.Stdout, &verdict)
	if res.ExitCode != 0 || verdict.Status != "fail" || string(verdict.Observed) != `{"lag":3}` || !strings.Contains(string(res.Stderr), "chatter") {
		t.Fatalf("fail: %+v", res)
	}
	res = run("crash", RunSpec{})
	if res.ExitCode != 2 || len(res.Stdout) != 0 || !strings.Contains(string(res.Stderr), "crashing") {
		t.Fatalf("crash: %+v", res)
	}
	res = run("garbage", RunSpec{})
	if res.ExitCode != 0 || json.Unmarshal(res.Stdout, &verdict) == nil {
		t.Fatalf("garbage: %+v", res)
	}
	res = run("sleep", RunSpec{Timeout: 30 * time.Millisecond})
	if !res.TimedOut || res.ExitCode != -1 {
		t.Fatalf("sleep: %+v", res)
	}
	secretFile := filepath.Join(t.TempDir(), "tok")
	_ = os.WriteFile(secretFile, []byte("abcdef\n"), 0o600)
	res = run("secret", RunSpec{Secrets: []SecretFile{{Name: "tok", Source: secretFile}}})
	_ = json.Unmarshal(res.Stdout, &verdict)
	if verdict.Status != "pass" || string(verdict.Observed) != `{"secret_bytes":6}` {
		t.Fatalf("secret: %s", res.Stdout)
	}
	if bytes.Contains(res.Stdout, []byte("abcdef")) {
		t.Fatal("the secret value must never be echoed")
	}
	if objs, _ := f.Objects(ctx, "lab"); len(objs.Secrets) != 0 {
		t.Fatalf("run secrets are removed when the run ends: %+v", objs)
	}
	// A seed run reports what it sent.
	seedIn := []byte(`{"contract":"podaro.dev/exec/v1","kind":"seed","run_id":"run_2","instance":{"name":"lab","endpoints":[]},"secrets":{"granted":[]},"seed":{"name":"orders","count":42,"seed_value":"9f2c66d1a4e07b53"}}`)
	sres, err := f.Run(ctx, RunSpec{Name: "pdr-lab-run-seed", Image: image, Network: "pdr-lab-int", Labels: labels, Command: []string{"pass"}, Stdin: seedIn})
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Status string `json:"status"`
		Sent   struct {
			Events int `json:"events"`
		} `json:"sent"`
		Message string `json:"message"`
	}
	if json.Unmarshal(sres.Stdout, &report) != nil || report.Status != "ok" || report.Sent.Events != 42 || !strings.Contains(report.Message, "9f2c66d1a4e07b53") {
		t.Fatalf("seed report: %s", sres.Stdout)
	}
	// Leftover secret objects (a crash mid-run) are listed and removable.
	_ = f.AddSecret(SecretPrefix("lab")+"dead-tok", map[string]string{LabelInstance: "lab"})
	if objs, _ := f.Objects(ctx, "lab"); len(objs.Secrets) != 1 || objs.Empty() {
		t.Fatalf("leftover secret listed: %+v", objs)
	}
	_ = f.RemoveSecret(ctx, SecretPrefix("lab")+"dead-tok")
	if objs, _ := f.Objects(ctx, "lab"); len(objs.Secrets) != 0 {
		t.Fatalf("leftover secret removed: %+v", objs)
	}
}

func TestFakeInitProgramRunsAgainstProducts(t *testing.T) {
	f := newTestFake(t)
	ctx := context.Background()
	labels := map[string]string{LabelInstance: "lab", LabelManaged: "true"}
	_ = f.EnsureNetwork(ctx, "pdr-lab", labels, false)
	_ = f.EnsureNetwork(ctx, "pdr-lab-int", labels, true)
	startFake(t, f, ContainerSpec{Name: "pdr-lab-web", Image: "docker.io/library/nginx@sha256:" + strings.Repeat("3", 64), Network: "pdr-lab", Networks: []string{"pdr-lab-int"}, Alias: "web", Labels: map[string]string{LabelInstance: "lab", LabelManaged: "true", LabelService: "web"}, Publish: []int{80}})
	curl := "docker.io/curlimages/curl@sha256:" + strings.Repeat("4", 64)
	_ = f.Pull(ctx, curl)
	program := InitProgram{Requests: []InitRequest{
		{Method: "GET", URL: "http://web:80/", Until: 200, Attempts: 5, BackoffMillis: 10},
		{Method: "POST", URL: "http://web:80/api/thing", Headers: map[string]string{"x-requested-by": "podaro"}, Body: `{"a":1}`, Username: "admin", Password: "pw", Attempts: 1},
	}}
	raw, _ := json.Marshal(program)
	spec := RunSpec{Name: "pdr-lab-init-web", Image: curl, Network: "pdr-lab-int", Labels: labels, Command: []string{"-K", InitCurlConfigPath}, Files: []FileSpec{{Path: InitProgramPath, Mode: 0o600, Content: raw}, {Path: InitCurlConfigPath, Mode: 0o600, Content: []byte("url = ...\n")}}, Timeout: 5 * time.Second}
	res, err := f.Run(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || string(res.Stdout) != "200 GET http://web:80/\n200 POST http://web:80/api/thing\n" {
		t.Fatalf("init run: %+v\nstdout %s\nstderr %s", res, res.Stdout, res.Stderr)
	}
	// A request whose polled status never comes fails the sequence, and
	// nothing after it runs (curl --fail-early).
	program.Requests = append([]InitRequest{{Method: "GET", URL: "http://web:80/never", Until: 404, Attempts: 2, BackoffMillis: 1}}, program.Requests...)
	raw, _ = json.Marshal(program)
	spec.Files[0].Content = raw
	res, err = f.Run(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 22 || !strings.Contains(string(res.Stderr), "returned 200") || strings.Contains(string(res.Stdout), "POST") {
		t.Fatalf("failing init run: %+v\nstdout %s\nstderr %s", res, res.Stdout, res.Stderr)
	}
	// An unresolvable service is a connection failure (exit 7).
	program.Requests = []InitRequest{{Method: "GET", URL: "http://nowhere:80/", Attempts: 1}}
	raw, _ = json.Marshal(program)
	spec.Files[0].Content = raw
	res, _ = f.Run(ctx, spec)
	if res.ExitCode != 7 || !strings.Contains(string(res.Stderr), "could not resolve host") {
		t.Fatalf("unresolvable: %+v %s", res, res.Stderr)
	}
}

func TestFakeImageUser(t *testing.T) {
	f := newTestFake(t)
	ctx := context.Background()
	for image, want := range map[string]ImageUser{
		"docker.io/podaro/exec-conformance@sha256:" + strings.Repeat("a", 64):            {Raw: "1000", UID: 1000, GID: 1000, Resolved: true},
		"docker.io/podaro/exec-conformance-root@sha256:" + strings.Repeat("b", 64):       {Raw: "", Resolved: true},
		"docker.io/podaro/exec-conformance-unresolved@sha256:" + strings.Repeat("c", 64): {Raw: "svc", Resolved: false},
	} {
		if _, err := f.ImageUser(ctx, image); err == nil {
			t.Fatalf("%s: an unpulled image has no user to report", image)
		}
		_ = f.Pull(ctx, image)
		got, err := f.ImageUser(ctx, image)
		if err != nil || got != want {
			t.Fatalf("%s: %+v %v, want %+v", image, got, err, want)
		}
	}
	if errors.Is(nil, ErrNotFound) {
		t.Fatal("unreachable")
	}
}

// A podman error names the verb it ran and what podman said — never the
// argument values, which for a create hold rendered configuration (a
// service's command may carry a secret) and travel into journals and
// logs.
func TestCommandErrorNamesNoArgumentValues(t *testing.T) {
	err := &CommandError{Args: []string{"create", "--name", "pdr-x-web", "--entrypoint", "serve", "docker.io/library/nginx@sha256:aaaa", "--token", "s3cr3tvalue0000"}, Stderr: "Error: invalid argument\n"}
	if got := err.Error(); got != "podman create: Error: invalid argument" {
		t.Fatalf("Error() = %q", got)
	}
	err = &CommandError{Args: []string{"network", "create", "--internal", "pdr-x-int"}, Stderr: "Error: exists"}
	if got := err.Error(); got != "podman network create: Error: exists" {
		t.Fatalf("Error() = %q", got)
	}
	err = &CommandError{Args: []string{"image", "inspect", "--format", "json", "img"}, Stderr: "Error: no such image"}
	if got := err.Error(); got != "podman image inspect: Error: no such image" {
		t.Fatalf("Error() = %q", got)
	}
	if got := (&CommandError{Stderr: "boom"}).Error(); got != "podman (no command): boom" {
		t.Fatalf("Error() = %q", got)
	}
}

// A one-shot run whose cleanup fails is not a run that finished cleanly:
// a container podman could not remove may still be running past its
// budget, a secret object left behind outlives the run — so Run reports
// the failure instead of a normal result.
func TestRunFailsWhenCleanupFails(t *testing.T) {
	attach := func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, []byte, int, error) {
		return []byte(`{"contract":"podaro.dev/exec/v1","status":"pass"}`), nil, 0, nil
	}
	secretFile := filepath.Join(t.TempDir(), "tok")
	_ = os.WriteFile(secretFile, []byte("s3cret"), 0o600)
	spec := RunSpec{Name: "pdr-lab-run-9", Image: "img@sha256:x", Network: "pdr-lab-int", Labels: map[string]string{LabelInstance: "lab"}, Secrets: []SecretFile{{Name: "tok", Source: secretFile}}, UID: 1000, GID: 1000, Timeout: time.Second}
	// The container cannot be removed.
	rec := &recorder{answers: map[string]func([]string) ([]byte, error){"create ": func([]string) ([]byte, error) { return []byte("c1d000000000001\n"), nil }, "rm ": func(args []string) ([]byte, error) {
		return nil, &CommandError{Args: args, Stderr: "Error: cannot remove container: device or resource busy"}
	}}}
	p := &Podman{Exe: "podman", Exec: rec.exec, Attach: attach}
	res, err := p.Run(context.Background(), spec)
	if err == nil || res != nil || !strings.Contains(err.Error(), "cleanup failed") || !strings.Contains(err.Error(), "remove container pdr-lab-run-9") || !strings.Contains(err.Error(), "resource busy") {
		t.Fatalf("a failed removal must fail the run: res=%+v err=%v", res, err)
	}
	if !rec.has("secret rm " + SecretPrefix("lab")) {
		t.Fatalf("the secret objects are still removed after a failed container removal: %v", rec.calls)
	}
	// A secret object cannot be removed.
	rec2 := &recorder{answers: map[string]func([]string) ([]byte, error){"create ": func([]string) ([]byte, error) { return []byte("c1d000000000001\n"), nil }, "secret rm": func(args []string) ([]byte, error) {
		return nil, &CommandError{Args: args, Stderr: "Error: secret in use"}
	}}}
	p2 := &Podman{Exe: "podman", Exec: rec2.exec, Attach: attach}
	if res, err := p2.Run(context.Background(), spec); err == nil || res != nil || !strings.Contains(err.Error(), "remove secret object "+SecretPrefix("lab")) {
		t.Fatalf("a failed secret removal must fail the run: res=%+v err=%v", res, err)
	}
	// A refused create reports the refusal and a cleanup failure together.
	rec3 := &recorder{answers: map[string]func([]string) ([]byte, error){
		"create ": func(args []string) ([]byte, error) {
			return nil, &CommandError{Args: args, Stderr: "Error: no such network"}
		},
		"secret rm": func(args []string) ([]byte, error) {
			return nil, &CommandError{Args: args, Stderr: "Error: secret in use"}
		},
	}}
	p3 := &Podman{Exe: "podman", Exec: rec3.exec, Attach: attach}
	if _, err := p3.Run(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "no such network") || !strings.Contains(err.Error(), "remove secret object") {
		t.Fatalf("both the refusal and the cleanup failure are reported: %v", err)
	}
}

// copyIn refuses a container path that would leave its staging directory
// or land elsewhere than written (podman.go:370):
// nothing is staged, no `podman cp` runs, and a host file
// the path pointed at is untouched. A clean absolute path still copies.
func TestCopyInRejectsEscapingPaths(t *testing.T) {
	home := t.TempDir()
	victim := filepath.Join(home, ".config", "podaro", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(victim), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	p := &Podman{Exe: "podman", Exec: rec.exec}
	// Enough `..` to reach the root from any staging depth; Clean then
	// lands on the victim's absolute path.
	traversal := "/../../../../../../../../.." + victim
	for _, bad := range []string{traversal, "/etc/../etc/passwd", "/etc//nginx.conf", "/etc/nginx/", "etc/nginx.conf", "/", "/a/./b", ""} {
		err := p.copyIn(context.Background(), "pdr-x-web", []FileSpec{{Path: bad, Content: []byte("owned"), Mode: 0o644}})
		if err == nil {
			t.Fatalf("path %q accepted", bad)
		}
		if rec.has("cp ") {
			t.Fatalf("path %q: podman cp ran", bad)
		}
	}
	if got, _ := os.ReadFile(victim); string(got) != "mine" {
		t.Fatalf("the host file was overwritten: %q", got)
	}
	if err := p.copyIn(context.Background(), "pdr-x-web", []FileSpec{{Path: "/etc/nginx/nginx.conf", Content: []byte("ok")}}); err != nil {
		t.Fatal(err)
	}
	if !rec.has("cp ") {
		t.Fatal("a clean absolute path must be staged and copied")
	}
	// The fake applies the same wall — refusing the path itself, not the
	// spec for some other reason.
	f, err := NewFake(filepath.Join(t.TempDir(), "world.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Pull(context.Background(), "docker.io/library/nginx@sha256:aa"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Create(context.Background(), ContainerSpec{Name: "pdr-x-web", Image: "docker.io/library/nginx@sha256:aa", Files: []FileSpec{{Path: traversal, Content: []byte("owned")}}}); err == nil || !strings.Contains(err.Error(), "container paths are clean") {
		t.Fatalf("the fake must refuse the escaping path as such: %v", err)
	}
}

// An inspection container's removal runs under its own live context and a
// failed removal is reported, naming the container (podman.go:881):
// a caller's deadline that ended the copy no
// longer leaks a pdr-inspect-* container, silently.
func TestInspectionCleanupOutlivesTheCallerAndReportsFailure(t *testing.T) {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	passwd := "app:x:1234:1234::/:/bin/sh\n"
	if err := tw.WriteHeader(&tar.Header{Name: "passwd", Mode: 0o644, Size: int64(len(passwd)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write([]byte(passwd))
	_ = tw.Close()
	inspect := []byte(`[{"Config":{"User":"app"}}]`)

	// A: the caller's context ends during the copy; the removal still
	// runs, and under a context that is alive.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rmSeen, rmCtxErr := false, error(nil)
	p := &Podman{Exe: "podman", Exec: func(c context.Context, _ string, args ...string) ([]byte, error) {
		line := strings.Join(args, " ")
		switch {
		case strings.HasPrefix(line, "image inspect"):
			return inspect, nil
		case strings.HasPrefix(line, "create --name pdr-inspect-"):
			return []byte("00112233445566778899aabb\n"), nil
		case strings.HasPrefix(line, "cp 00112233445566778899aabb:"):
			cancel()
			return nil, c.Err()
		case strings.HasPrefix(line, "rm --force --ignore --volumes 00112233445566778899aabb"):
			rmSeen, rmCtxErr = true, c.Err()
			return nil, nil
		}
		return nil, nil
	}}
	if _, err := p.ImageUser(ctx, "img@sha256:aa"); err != nil {
		t.Fatalf("an ended read is an unresolved user, not an error: %v", err)
	}
	if !rmSeen || rmCtxErr != nil {
		t.Fatalf("the removal must run under a live context: seen=%v ctxErr=%v", rmSeen, rmCtxErr)
	}

	// B: the read succeeds but the removal fails — an error the operator
	// sees, naming the container that may remain.
	p2 := &Podman{Exe: "podman", Exec: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		line := strings.Join(args, " ")
		switch {
		case strings.HasPrefix(line, "image inspect"):
			return inspect, nil
		case strings.HasPrefix(line, "create --name pdr-inspect-"):
			return []byte("00112233445566778899aabb\n"), nil
		case strings.HasPrefix(line, "cp 00112233445566778899aabb:"):
			return tarBuf.Bytes(), nil
		case strings.HasPrefix(line, "rm --force --ignore --volumes 00112233445566778899aabb"):
			return nil, &CommandError{Args: args, Stderr: "Error: container is in use"}
		}
		return nil, nil
	}}
	_, err := p2.ImageUser(context.Background(), "img@sha256:aa")
	var ce *CleanupError
	if !errors.As(err, &ce) || !strings.HasPrefix(ce.Container, "pdr-inspect-") || !strings.Contains(err.Error(), "could not be removed") || !strings.Contains(err.Error(), "container is in use") {
		t.Fatalf("a failed removal must be reported, naming the container: %v", err)
	}
}

// An incomplete container is never adopted as complete (podman.go:342):
// a copy that fails because the caller's
// context ended removes the container under a live context and names it
// when the removal fails; a container of the same digest found created but
// never started gets its files copied again; one that has started is
// adopted as it is.
func TestCreateNeverAdoptsAnIncompleteContainer(t *testing.T) {
	spec := ContainerSpec{Name: "pdr-x-web", Image: "docker.io/library/nginx@sha256:abc",
		Labels: map[string]string{LabelManaged: "true", LabelInstance: "x", LabelService: "web"},
		Files:  []FileSpec{{Path: "/etc/nginx/nginx.conf", Content: []byte("ok")}}}
	digest, err := spec.Digest()
	if err != nil {
		t.Fatal(err)
	}
	inspectJSON := func(running bool, started string) []byte {
		return []byte(fmt.Sprintf(`[{"Id":"abc123","ImageName":%q,"Config":{"Labels":{"dev.podaro/managed":"true","dev.podaro/instance":"x","dev.podaro/service":"web","dev.podaro/spec":%q}},"State":{"Running":%v,"ExitCode":0,"StartedAt":%q},"NetworkSettings":{"Ports":{}}}]`, spec.Image, digest, running, started))
	}
	// A: no container yet; the copy fails as the caller's context ends.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rmSeen, rmCtxErr := false, error(nil)
	p := &Podman{Exe: "podman", Exec: func(c context.Context, _ string, args ...string) ([]byte, error) {
		line := strings.Join(args, " ")
		switch {
		case strings.HasPrefix(line, "container exists"):
			return nil, &fakeExit{code: 1}
		case strings.HasPrefix(line, "create "):
			return []byte("0123456789abcdef\n"), nil
		case strings.HasPrefix(line, "cp "):
			cancel()
			return nil, c.Err()
		case strings.HasPrefix(line, "rm --force --volumes 0123456789abcdef"):
			rmSeen, rmCtxErr = true, c.Err()
			return nil, &CommandError{Args: args, Stderr: "Error: container is in use"}
		}
		return nil, nil
	}}
	_, err = p.Create(ctx, spec)
	var ce *CleanupError
	if err == nil || !errors.As(err, &ce) || ce.Container != "pdr-x-web" || !strings.Contains(err.Error(), "container is in use") {
		t.Fatalf("a failed removal of the incomplete container must be named: %v", err)
	}
	if !rmSeen || rmCtxErr != nil {
		t.Fatalf("the removal must run under a live context: seen=%v ctxErr=%v", rmSeen, rmCtxErr)
	}
	// B: the same digest, created but never started → the files are copied
	// again, nothing is created anew.
	rec := &recorder{answers: map[string]func([]string) ([]byte, error){
		"inspect": func([]string) ([]byte, error) { return inspectJSON(false, "0001-01-01T00:00:00Z"), nil },
	}}
	id, err := (&Podman{Exe: "podman", Exec: rec.exec}).Create(context.Background(), spec)
	if err != nil || id != "abc123" || !rec.has("cp ") || rec.has("create ") {
		t.Fatalf("a never-started container must get its files again: id=%q err=%v calls=%v", id, err, rec.calls)
	}
	// C: the same digest, started before → adopted as it is.
	rec2 := &recorder{answers: map[string]func([]string) ([]byte, error){
		"inspect": func([]string) ([]byte, error) { return inspectJSON(true, "2026-09-03T10:00:00Z"), nil },
	}}
	id, err = (&Podman{Exe: "podman", Exec: rec2.exec}).Create(context.Background(), spec)
	if err != nil || id != "abc123" || rec2.has("cp ") || rec2.has("create ") {
		t.Fatalf("a started container is adopted as it is: id=%q err=%v calls=%v", id, err, rec2.calls)
	}
}

// Spec 0002 caps the contract stream and the diagnostics at 64 KiB each;
// the caps hold for the attach seam too (podman.go:677).
func TestRunCapsOutputAtTheContractLimit(t *testing.T) {
	if DefaultMaxStdout != 64<<10 || DefaultMaxStderr != 64<<10 {
		t.Fatalf("defaults: stdout %d stderr %d, want 64 KiB each", DefaultMaxStdout, DefaultMaxStderr)
	}
	rec := &recorder{answers: map[string]func([]string) ([]byte, error){"create ": func([]string) ([]byte, error) { return []byte("c1d000000000001\n"), nil }}}
	p := &Podman{Exe: "podman", Exec: rec.exec, Attach: func(context.Context, []byte, string, ...string) ([]byte, []byte, int, error) {
		return bytes.Repeat([]byte("o"), 100<<10), bytes.Repeat([]byte("e"), 100<<10), 0, nil
	}}
	res, err := p.Run(context.Background(), RunSpec{Name: "pdr-lab-run-cap", Image: "docker.io/library/busybox@sha256:aa", Stdin: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stdout) != 64<<10 || len(res.Stderr) != 64<<10 {
		t.Fatalf("outputs must be capped at 64 KiB: stdout %d stderr %d", len(res.Stdout), len(res.Stderr))
	}
}

// The run's budget bounds its setup as well as its process: a stalled
// create ends as the timeout result within the budget, after the cleanup
// (podman.go:815).
func TestRunBudgetBoundsTheSetup(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	var runID string
	p := &Podman{Exe: "podman", Exec: func(c context.Context, _ string, args ...string) ([]byte, error) {
		line := strings.Join(args, " ")
		mu.Lock()
		calls = append(calls, line)
		mu.Unlock()
		switch {
		case strings.HasPrefix(line, "create "):
			for _, a := range args {
				if strings.HasPrefix(a, LabelRunID+"=") {
					mu.Lock()
					runID = strings.TrimPrefix(a, LabelRunID+"=")
					mu.Unlock()
				}
			}
			<-c.Done() // a podman create that never answers
			return nil, c.Err()
		case strings.HasPrefix(line, "inspect --type container"):
			// The container did come to be under this run's own id, so
			// the cleanup removes it (round 42).
			mu.Lock()
			defer mu.Unlock()
			return []byte(fmt.Sprintf(`[{"Id":"abc","Config":{"Labels":{"dev.podaro/run-id":%q}},"State":{},"NetworkSettings":{"Ports":{}}}]`, runID)), nil
		}
		return nil, nil
	}}
	type outcome struct {
		res *RunResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := p.Run(context.Background(), RunSpec{Name: "pdr-lab-run-stall", Image: "docker.io/library/busybox@sha256:aa", Timeout: 100 * time.Millisecond, Stdin: []byte("{}")})
		done <- outcome{res, err}
	}()
	var out outcome
	select {
	case out = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run hung on a stalled create: the budget must bound the setup")
	}
	if out.err != nil || out.res == nil || !out.res.TimedOut || out.res.ExitCode != -1 {
		t.Fatalf("a setup that outlives the budget is the timeout result: %+v %v", out.res, out.err)
	}
	mu.Lock()
	defer mu.Unlock()
	cleaned := false
	for _, c := range calls {
		if strings.HasPrefix(c, "rm --force --ignore --volumes abc") { // the id the inspection saw (round 46)
			cleaned = true
		}
	}
	if !cleaned {
		t.Fatalf("the cleanup must run after a setup timeout: %v", calls)
	}
}

// A secret object whose creation the budget cut off is removed with the
// rest: its name is tracked before the command runs, and a removal of one
// that never came to be is no error (podman.go:829).
func TestRunCleanupRemovesASecretWhoseCreateWasCutOff(t *testing.T) {
	spec := RunSpec{Name: "pdr-lab-run-cut", Image: "docker.io/library/busybox@sha256:aa", Timeout: 100 * time.Millisecond, Stdin: []byte("{}"),
		Labels: map[string]string{LabelInstance: "lab"}, Secrets: []SecretFile{{Name: "tok", Source: "/state/instances/lab/secrets/tok"}}}
	want := SecretPrefix("lab") + "run-cut_tok_" // the run's own id ends the name (round 63)
	var mu sync.Mutex
	var calls []string
	p := &Podman{Exe: "podman", Exec: func(c context.Context, _ string, args ...string) ([]byte, error) {
		line := strings.Join(args, " ")
		mu.Lock()
		calls = append(calls, line)
		mu.Unlock()
		switch {
		case strings.HasPrefix(line, "secret create"):
			mu.Lock()
			want = args[2]
			mu.Unlock()
			<-c.Done() // the CLI is killed by the budget after committing the object
			return nil, c.Err()
		case strings.HasPrefix(line, "secret rm"):
			return nil, &CommandError{Args: args, Stderr: "Error: no such secret"} // never came to be: a no-op
		}
		return nil, nil
	}}
	res, err := p.Run(context.Background(), spec)
	if err != nil || res == nil || !res.TimedOut {
		t.Fatalf("a create the budget cut off is the timeout result, its cleanup clean: %+v %v", res, err)
	}
	mu.Lock()
	defer mu.Unlock()
	removed := false
	for _, c := range calls {
		if c == "secret rm "+want {
			removed = true
		}
	}
	if !removed {
		t.Fatalf("the cleanup must remove the secret object whose create was cut off (%s): %v", want, calls)
	}
}

// A stream the cap cut says so: the result carries the truncation, so a
// reader never takes the kept prefix for the whole (podman.go:116).
func TestRunReportsACutStream(t *testing.T) {
	rec := &recorder{answers: map[string]func([]string) ([]byte, error){"create ": func([]string) ([]byte, error) { return []byte("c1d000000000001\n"), nil }}}
	out, errs := bytes.Repeat([]byte("o"), 100<<10), []byte("short")
	p := &Podman{Exe: "podman", Exec: rec.exec, Attach: func(context.Context, []byte, string, ...string) ([]byte, []byte, int, error) {
		return out, errs, 0, nil
	}}
	spec := RunSpec{Name: "pdr-lab-run-cut", Image: "docker.io/library/busybox@sha256:aa", Stdin: []byte("{}")}
	res, err := p.Run(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !res.StdoutTruncated || res.StderrTruncated || len(res.Stdout) != DefaultMaxStdout || string(res.Stderr) != "short" {
		t.Fatalf("stdout cut, stderr whole: %v %v (%d, %q)", res.StdoutTruncated, res.StderrTruncated, len(res.Stdout), res.Stderr)
	}
	out = []byte("whole")
	if res, err = p.Run(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if res.StdoutTruncated || res.StderrTruncated {
		t.Fatalf("nothing cut: %v %v", res.StdoutTruncated, res.StderrTruncated)
	}
	// The buffer a real attach writes into reports the cut the same way.
	b := &cappedBuffer{max: 4}
	if n, _ := b.Write([]byte("123456")); n != 6 || b.buf.String() != "1234" || !b.truncated {
		t.Fatalf("cappedBuffer: %d %q %v", n, b.buf.String(), b.truncated)
	}
}

// Two admitted instance names whose hashes collided shared a run-secret
// prefix, so destroying one would have removed the other's secret objects
// (podman.go:699): the name now carries the
// instance whole, and each instance's listing holds its own objects only.
func TestObjectsOfCollidingInstancesStayApart(t *testing.T) {
	mine := RunSpec{Name: "pdr-lab-41265-run-0a1b2c3d4e5f", Labels: map[string]string{LabelInstance: "lab-41265"}}
	other := RunSpec{Name: "pdr-lab-150237-run-6a7b8c9d0e1f", Labels: map[string]string{LabelInstance: "lab-150237"}}
	mineTok, otherTok := runSecretName(mine, "0123456789abcdef", "tok"), runSecretName(other, "0123456789abcdef", "tok")
	if mineTok == otherTok {
		t.Fatal("two instances' run secrets share a name")
	}
	rec := &recorder{answers: map[string]func([]string) ([]byte, error){
		"ps":         func([]string) ([]byte, error) { return []byte(`[]`), nil },
		"network ls": func([]string) ([]byte, error) { return []byte(`[]`), nil },
		"volume ls":  func([]string) ([]byte, error) { return []byte(`[]`), nil },
		"secret ls": func([]string) ([]byte, error) {
			return []byte(fmt.Sprintf(`[{"ID":"1","Spec":{"Name":%q}},{"ID":"2","Spec":{"Name":%q}},{"ID":"3","Spec":{"Name":"user-secret"}}]`, mineTok, otherTok)), nil
		},
	}}
	p := &Podman{Exe: "podman", Exec: rec.exec}
	for _, c := range []struct{ instance, want string }{{"lab-41265", mineTok}, {"lab-150237", otherTok}} {
		objs, err := p.Objects(context.Background(), c.instance)
		if err != nil || len(objs.Secrets) != 1 || objs.Secrets[0] != c.want {
			t.Fatalf("%s: objects %+v %v, want its own run secret only", c.instance, objs, err)
		}
	}
	// Podman admits [a-zA-Z0-9][a-zA-Z0-9_.-]* up to 253 characters; the
	// longest name Podaro can form — a 24-character instance, a
	// 63-character secret — stays inside.
	long := RunSpec{Name: "pdr-" + strings.Repeat("z", 24) + "-run-" + strings.Repeat("f", 12), Labels: map[string]string{LabelInstance: strings.Repeat("z", 24)}}
	if name := runSecretName(long, "0123456789abcdef", strings.Repeat("s", 63)); !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`).MatchString(name) || len(name) > 253 {
		t.Fatalf("a run secret name podman would refuse: %d characters", len(name))
	}
}

// A create podman refused made nothing: the name it refused is held by a
// container this run never created — a helper another process won between
// the caller's ownership check and the create — and the cleanup leaves it
// standing, while the run's secret objects are still taken back. A
// container this run did create is removed as before (podman.go:795).
func TestRunRemovesOnlyTheContainerItCreated(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "tok")
	_ = os.WriteFile(secretFile, []byte("never-printed"), 0o600)
	spec := RunSpec{Name: "pdr-lab-init_web", Image: "img@sha256:x", Network: "pdr-lab_int", Labels: map[string]string{LabelInstance: "lab"}, Secrets: []SecretFile{{Name: "tok", Source: secretFile}}, UID: 1000, GID: 1000, Timeout: time.Second}
	rec := &recorder{answers: map[string]func([]string) ([]byte, error){"create ": func(args []string) ([]byte, error) {
		return nil, &CommandError{Args: args, Stderr: `Error: creating container storage: the container name "pdr-lab-init_web" is already in use`}
	}}}
	p := &Podman{Exe: "podman", Exec: rec.exec}
	if res, err := p.Run(context.Background(), spec); err == nil || res != nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("a refused create is the run's error: res=%+v err=%v", res, err)
	}
	if rec.has("rm ") {
		t.Fatalf("a container this run never created was removed: %v", rec.calls)
	}
	if !rec.has("secret rm " + SecretPrefix("lab") + "init_web_tok_") {
		t.Fatalf("the run's secret objects are still removed after a refused create: %v", rec.calls)
	}
	// Created, then failed at the copy-in: removed.
	rec2 := &recorder{answers: map[string]func([]string) ([]byte, error){"create ": func([]string) ([]byte, error) { return []byte("c1d000000000001\n"), nil }, "cp ": func(args []string) ([]byte, error) {
		return nil, &CommandError{Args: args, Stderr: "Error: copy failed"}
	}}}
	p2 := &Podman{Exe: "podman", Exec: rec2.exec}
	spec2 := spec
	spec2.Files = []FileSpec{{Path: "/run/podaro/init/run.sh", Content: []byte("#!/bin/sh\n"), Mode: 0o600}}
	if _, err := p2.Run(context.Background(), spec2); err == nil || !strings.Contains(err.Error(), "copy failed") {
		t.Fatalf("a failed copy-in is the run's error: %v", err)
	}
	if !rec2.has("rm --force --ignore --volumes c1d000000000001") || rec2.has("rm --force --ignore --volumes pdr-lab-init_web") {
		t.Fatalf("a container this run created is removed after a failed copy-in, by the id create answered: %v", rec2.calls)
	}
}

// A create the budget cut off — the CLI killed before it answered — may
// have committed this run's container, or another process may hold the
// name by now: the cleanup inspects what stands there under its own
// context and removes it only when it carries this run's id label; a
// stranger's container, or nothing, is left as found (podman.go:857).
func TestRunAfterACutOffCreateRemovesOnlyItsOwnContainer(t *testing.T) {
	run := func(t *testing.T, inspect func(runID string) []byte) (calls []string) {
		var mu sync.Mutex
		var runID string
		p := &Podman{Exe: "podman", Exec: func(c context.Context, _ string, args ...string) ([]byte, error) {
			line := strings.Join(args, " ")
			mu.Lock()
			calls = append(calls, line)
			mu.Unlock()
			switch {
			case strings.HasPrefix(line, "create "):
				for _, a := range args {
					if strings.HasPrefix(a, LabelRunID+"=") {
						mu.Lock()
						runID = strings.TrimPrefix(a, LabelRunID+"=")
						mu.Unlock()
					}
				}
				<-c.Done() // killed by the budget; whether the container came to be is unknown
				return nil, c.Err()
			case strings.HasPrefix(line, "container exists "):
				mu.Lock()
				id := runID
				mu.Unlock()
				if inspect(id) == nil {
					return nil, &fakeExit{code: 1} // absent
				}
				return nil, nil
			case strings.HasPrefix(line, "inspect --type container"):
				mu.Lock()
				id := runID
				mu.Unlock()
				return inspect(id), nil
			}
			return nil, nil
		}}
		res, err := p.Run(context.Background(), RunSpec{Name: "pdr-lab-init_web", Image: "img@sha256:x", Timeout: 100 * time.Millisecond, Stdin: []byte("{}"), Labels: map[string]string{LabelInstance: "lab"}})
		if err != nil || res == nil || !res.TimedOut {
			t.Fatalf("a cut-off create is the timeout result: %+v %v", res, err)
		}
		mu.Lock()
		defer mu.Unlock()
		if runID == "" {
			t.Fatalf("the create must carry the run's own id label: %v", calls)
		}
		return calls
	}
	removed := func(calls []string) bool {
		for _, c := range calls {
			if strings.HasPrefix(c, "rm --force --ignore --volumes abc") { // the id the inspection saw
				return true
			}
		}
		return false
	}
	doc := func(id string) []byte {
		return []byte(fmt.Sprintf(`[{"Id":"abc","ImageName":"img@sha256:x","Config":{"Labels":{"dev.podaro/instance":"lab","dev.podaro/run-id":%q}},"State":{"Running":false,"ExitCode":0,"StartedAt":"2026-09-06T00:00:00Z"},"NetworkSettings":{"Ports":{}}}]`, id))
	}
	// Another process's container holds the name: left standing.
	if calls := run(t, func(string) []byte { return doc("someone-else") }); removed(calls) {
		t.Fatalf("a stranger's container under the run's name was removed: %v", calls)
	}
	// Nothing under the name: nothing to remove.
	if calls := run(t, func(string) []byte { return nil }); removed(calls) {
		t.Fatalf("an absent container was removed: %v", calls)
	}
	// This run's own container came to be after all: removed.
	if calls := run(t, func(id string) []byte { return doc(id) }); !removed(calls) {
		t.Fatalf("the run's own container must be removed: %v", calls)
	}
}

// A run that cannot draw its own id does not start: the id is what the
// cleanup after a cut-off create trusts, so a run without one could
// remove another's container (round 42 re-read).
func TestRunFailsWhenItCannotMarkItself(t *testing.T) {
	old := randReader
	randReader = iotest.ErrReader(errors.New("no entropy"))
	defer func() { randReader = old }()
	rec := &recorder{}
	p := &Podman{Exe: "podman", Exec: rec.exec, Attach: func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, []byte, int, error) {
		return []byte(`{"contract":"podaro.dev/exec/v1","status":"pass"}`), nil, 0, nil
	}}
	res, err := p.Run(context.Background(), RunSpec{Name: "pdr-lab-run-1", Image: "img@sha256:x", Labels: map[string]string{LabelInstance: "lab"}, Timeout: time.Second})
	if err == nil || res != nil || !strings.Contains(err.Error(), "mark the run") {
		t.Fatalf("a run without an id must not start: res=%+v err=%v", res, err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("nothing may run before the run is marked: %v", rec.calls)
	}
}

// The container a run created is removed by the id podman create
// answered, never by its name: a container another process placed under
// the name after removing this one — while it copied, started or ran —
// is not this run's (podman.go:821).
func TestRunRemovesTheContainerItCreatedByItsID(t *testing.T) {
	rec := &recorder{answers: map[string]func([]string) ([]byte, error){"create ": func([]string) ([]byte, error) { return []byte("c0ffee0123456789\n"), nil }}}
	p := &Podman{Exe: "podman", Exec: rec.exec, Attach: func(context.Context, []byte, string, ...string) ([]byte, []byte, int, error) {
		return []byte(`{"contract":"podaro.dev/exec/v1","status":"pass"}`), nil, 0, nil
	}}
	if _, err := p.Run(context.Background(), RunSpec{Name: "pdr-lab-run-byid", Image: "img@sha256:x", Stdin: []byte("{}"), Labels: map[string]string{LabelInstance: "lab"}, Timeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	if !rec.has("rm --force --ignore --volumes c0ffee0123456789") || rec.has("rm --force --ignore --volumes pdr-lab-run-byid") {
		t.Fatalf("the run must remove the id create answered, never the name: %v", rec.calls)
	}
	// The id is the last word of create's stdout, a hex id: a stray line
	// before it is not the id, and stdout that carries no id at all falls
	// to the inspection, which removes only this run's own container by
	// the id it saw — never a word that matches nothing.
	for name, out := range map[string]string{"a warning first": "WARN: something\nc0ffee0123456789\n", "not an id": "created\n"} {
		var runID string
		rec := &recorder{}
		rec.answers = map[string]func([]string) ([]byte, error){
			"create ": func(args []string) ([]byte, error) {
				for _, a := range args {
					runID = strings.TrimPrefix(a, LabelRunID+"=")
					if a != runID {
						break
					}
				}
				return []byte(out), nil
			},
			"inspect --type container": func([]string) ([]byte, error) {
				return []byte(fmt.Sprintf(`[{"Id":"abc","Config":{"Labels":{"dev.podaro/run-id":%q}},"State":{},"NetworkSettings":{"Ports":{}}}]`, runID)), nil
			},
		}
		p := &Podman{Exe: "podman", Exec: rec.exec, Attach: func(context.Context, []byte, string, ...string) ([]byte, []byte, int, error) {
			return []byte(`{"contract":"podaro.dev/exec/v1","status":"pass"}`), nil, 0, nil
		}}
		if _, err := p.Run(context.Background(), RunSpec{Name: "pdr-lab-run-byid", Image: "img@sha256:x", Stdin: []byte("{}"), Labels: map[string]string{LabelInstance: "lab"}, Timeout: time.Second}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := "rm --force --ignore --volumes c0ffee0123456789"
		if name == "not an id" {
			want = "rm --force --ignore --volumes abc"
		}
		if !rec.has(want) || rec.has("rm --force --ignore --volumes pdr-lab-run-byid") || rec.has("rm --force --ignore --volumes created") || rec.has("rm --force --ignore --volumes WARN") {
			t.Fatalf("%s: want %q, never a name or a stray word: %v", name, want, rec.calls)
		}
	}
}

// After the create, the copy-in, the start and the cleanup address the
// container by the id create answered, never by the name another process
// may reuse after removing it: a replacement receives no rendered file
// and runs no verdict. Without an id from create, the container under the
// name is used only if it carries this run's own id — a stranger there
// stops the run before any copy or start, and is not removed (podman.go:904).
func TestRunAddressesItsContainerByIdAfterCreate(t *testing.T) {
	file := FileSpec{Path: "/run/podaro/init/run.sh", Content: []byte("#!/bin/sh\n"), Mode: 0o600}
	rec := &recorder{answers: map[string]func([]string) ([]byte, error){"create ": func([]string) ([]byte, error) { return []byte("c0ffee0123456789\n"), nil }}}
	p := &Podman{Exe: "podman", Exec: rec.exec, Attach: func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, []byte, int, error) {
		rec.calls = append(rec.calls, "ATTACH "+strings.Join(args, " "))
		return []byte(`{"contract":"podaro.dev/exec/v1","status":"pass"}`), nil, 0, nil
	}}
	if _, err := p.Run(context.Background(), RunSpec{Name: "pdr-lab-run-byid", Image: "img@sha256:x", Stdin: []byte("{}"), Files: []FileSpec{file}, Labels: map[string]string{LabelInstance: "lab"}, Timeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	for _, c := range rec.calls {
		switch {
		case strings.HasPrefix(c, "create "):
			continue // the create names the container; everything after it names the id
		case strings.Contains(c, "pdr-lab-run-byid"):
			t.Fatalf("a call after the create addressed the name, not the id: %s", c)
		}
	}
	if !rec.has("cp ") || !rec.has("ATTACH start --attach --interactive c0ffee0123456789") || !rec.has("rm --force --ignore --volumes c0ffee0123456789") {
		t.Fatalf("the copy-in, the start and the cleanup must address the id: %v", rec.calls)
	}
	for _, c := range rec.calls {
		if strings.HasPrefix(c, "cp ") && !strings.Contains(c, "c0ffee0123456789:") {
			t.Fatalf("a copy-in must target the id: %s", c)
		}
	}
	// No id from create: a stranger under the name stops the run before
	// any copy or start, and stands; this run's own container proceeds.
	for name, owner := range map[string]string{"a stranger": "someone-else", "this run": ""} {
		var runID string
		rec := &recorder{}
		rec.answers = map[string]func([]string) ([]byte, error){
			"create ": func(args []string) ([]byte, error) {
				for _, a := range args {
					if strings.HasPrefix(a, LabelRunID+"=") {
						runID = strings.TrimPrefix(a, LabelRunID+"=")
					}
				}
				return []byte("created\n"), nil
			},
			"inspect --type container": func([]string) ([]byte, error) {
				id := owner
				if id == "" {
					id = runID
				}
				return []byte(fmt.Sprintf(`[{"Id":"abc","Config":{"Labels":{"dev.podaro/run-id":%q}},"State":{},"NetworkSettings":{"Ports":{}}}]`, id)), nil
			},
		}
		p := &Podman{Exe: "podman", Exec: rec.exec, Attach: func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, []byte, int, error) {
			rec.calls = append(rec.calls, "ATTACH "+strings.Join(args, " "))
			return []byte(`{"contract":"podaro.dev/exec/v1","status":"pass"}`), nil, 0, nil
		}}
		_, err := p.Run(context.Background(), RunSpec{Name: "pdr-lab-run-byid", Image: "img@sha256:x", Stdin: []byte("{}"), Files: []FileSpec{file}, Labels: map[string]string{LabelInstance: "lab"}, Timeout: time.Second})
		if owner != "" {
			if err == nil || !strings.Contains(err.Error(), "not this run's") || rec.has("cp ") || rec.has("ATTACH ") || rec.has("rm --force") {
				t.Fatalf("%s: the run must stop before any copy, start or removal: err=%v calls=%v", name, err, rec.calls)
			}
			continue
		}
		if err != nil || !rec.has("ATTACH start --attach --interactive abc") || !rec.has("rm --force --ignore --volumes abc") {
			t.Fatalf("%s: the inspected own container is used by its id: err=%v calls=%v", name, err, rec.calls)
		}
	}
}

// A service container is addressed by its id from the create on: the
// files are copied into the id create answered — or the id an adoption
// inspected — and an incomplete container is removed by that id, never by
// the name another process may reuse after removing it (the service-container instance of the one-shot run's rule).
func TestCreateAddressesTheContainerByIdAfterCreate(t *testing.T) {
	spec := ContainerSpec{Name: "pdr-x-web", Image: "docker.io/library/nginx@sha256:aaaa", Labels: map[string]string{LabelInstance: "x", LabelService: "web", LabelManaged: "true"}, Files: []FileSpec{{Path: "/etc/nginx/nginx.conf", Content: []byte("events {}\n"), Mode: 0o644}}}
	rec := &recorder{answers: map[string]func([]string) ([]byte, error){
		"container exists": func([]string) ([]byte, error) { return nil, &fakeExit{code: 1} },
		"create ":          func([]string) ([]byte, error) { return []byte("0123456789abcdef\n"), nil },
	}}
	id, err := (&Podman{Exe: "podman", Exec: rec.exec}).Create(context.Background(), spec)
	if err != nil || id != "0123456789abcdef" {
		t.Fatalf("create: id=%q err=%v", id, err)
	}
	for _, c := range rec.calls {
		if strings.HasPrefix(c, "cp ") && !strings.Contains(c, " 0123456789abcdef:") {
			t.Fatalf("the copy-in must target the id create answered, never the name: %s", c)
		}
	}
	if !rec.has("cp ") {
		t.Fatalf("the files must be copied in: %v", rec.calls)
	}
	// A copy that fails removes the incomplete container by its id.
	rec2 := &recorder{answers: map[string]func([]string) ([]byte, error){
		"container exists": func([]string) ([]byte, error) { return nil, &fakeExit{code: 1} },
		"create ":          func([]string) ([]byte, error) { return []byte("0123456789abcdef\n"), nil },
		"cp ": func(args []string) ([]byte, error) {
			return nil, &CommandError{Args: args, Stderr: "Error: copy failed"}
		},
	}}
	if _, err := (&Podman{Exe: "podman", Exec: rec2.exec}).Create(context.Background(), spec); err == nil || !rec2.has("rm --force --volumes 0123456789abcdef") || rec2.has("rm --force --volumes pdr-x-web") {
		t.Fatalf("an incomplete container is removed by its id: err=%v calls=%v", err, rec2.calls)
	}
}

// A stale owned service — ours, created from a spec since changed — is
// replaced by removing the id its inspection saw, never the name a
// container another process placed there meanwhile would answer to (S6
// review, round 48, podman.go:355).
func TestCreateReplacesAStaleContainerByItsId(t *testing.T) {
	spec := ContainerSpec{Name: "pdr-x-web", Image: "docker.io/library/nginx@sha256:aaaa", Labels: map[string]string{LabelInstance: "x", LabelService: "web", LabelManaged: "true"}}
	stale := []byte(`[{"Id":"abc123","ImageName":"docker.io/library/nginx@sha256:aaaa","Config":{"Labels":{"dev.podaro/managed":"true","dev.podaro/instance":"x","dev.podaro/service":"web","dev.podaro/spec":"a-digest-since-changed"}},"State":{"Running":false,"ExitCode":0,"StartedAt":"0001-01-01T00:00:00Z"},"NetworkSettings":{"Ports":{}}}]`)
	rec := &recorder{answers: map[string]func([]string) ([]byte, error){
		"inspect": func([]string) ([]byte, error) { return stale, nil },
		"create ": func([]string) ([]byte, error) { return []byte("0123456789abcdef\n"), nil },
	}}
	id, err := (&Podman{Exe: "podman", Exec: rec.exec}).Create(context.Background(), spec)
	if err != nil || id != "0123456789abcdef" {
		t.Fatalf("create: id=%q err=%v calls=%v", id, err, rec.calls)
	}
	if !rec.has("rm --force --volumes abc123") || rec.has("rm --force --volumes pdr-x-web") {
		t.Fatalf("the stale container is removed by the id its inspection saw, never by name: %v", rec.calls)
	}
}

// The image-user inspection addresses its temporary container by the id
// create answered — the read of /etc/passwd and the removal — never by
// the name, which another process may reuse after removing it and whose
// /etc/passwd would then vouch for the image's user; without an id from
// create, the container under the name is used only if it carries the
// inspection's own tag (podman.go:1100). The removal
// takes the anonymous volumes with it.
func TestImageFileAddressesTheInspectionContainerByItsId(t *testing.T) {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	body := []byte("root:x:0:0:root:/root:/bin/sh\ncurl_user:x:100:101::/home/curl_user:/bin/sh\n")
	_ = tw.WriteHeader(&tar.Header{Name: "passwd", Mode: 0o644, Size: int64(len(body))})
	_, _ = tw.Write(body)
	_ = tw.Close()
	rec := &recorder{answers: map[string]func([]string) ([]byte, error){
		"image inspect": func([]string) ([]byte, error) { return []byte(`[{"Config":{"User":"curl_user"}}]`), nil },
		"create ":       func([]string) ([]byte, error) { return []byte("00112233445566778899aabb\n"), nil },
		"cp ":           func([]string) ([]byte, error) { return tarBuf.Bytes(), nil },
	}}
	got, err := (&Podman{Exe: "podman", Exec: rec.exec}).ImageUser(context.Background(), "img@sha256:x")
	if err != nil || got.UID != 100 || !got.Resolved {
		t.Fatalf("image user: %+v %v", got, err)
	}
	if !rec.has("cp 00112233445566778899aabb:/etc/passwd -") || !rec.has("rm --force --ignore --volumes 00112233445566778899aabb") {
		t.Fatalf("the read and the removal must address the id: %v", rec.calls)
	}
	for _, c := range rec.calls {
		if (strings.HasPrefix(c, "cp ") || strings.HasPrefix(c, "rm ")) && strings.Contains(c, "pdr-inspect-") {
			t.Fatalf("a call addressed the inspection container by name: %s", c)
		}
		if strings.HasPrefix(c, "create ") && !strings.Contains(c, "--label "+LabelRunID+"=") {
			t.Fatalf("the create must tag the container for the no-id case: %s", c)
		}
	}
	// No id from create: a stranger under the name is never read or removed.
	rec2 := &recorder{answers: map[string]func([]string) ([]byte, error){
		"image inspect": func([]string) ([]byte, error) { return []byte(`[{"Config":{"User":"curl_user"}}]`), nil },
		"create ":       func([]string) ([]byte, error) { return []byte("created\n"), nil },
		"inspect --type container": func([]string) ([]byte, error) {
			return []byte(`[{"Id":"abc","Config":{"Labels":{"dev.podaro/run-id":"someone-else"}},"State":{},"NetworkSettings":{"Ports":{}}}]`), nil
		},
	}}
	// An ended read is an unresolved user — which the engine refuses to
	// run — never a user read from the stranger.
	if got, err := (&Podman{Exe: "podman", Exec: rec2.exec}).ImageUser(context.Background(), "img@sha256:x"); err != nil || got.Resolved || rec2.has("cp ") || rec2.has("rm ") {
		t.Fatalf("a stranger under the inspection's name must stop the read, unresolved: got=%+v err=%v calls=%v", got, err, rec2.calls)
	}
}

// A one-shot run's cleanup takes the container's anonymous volumes with
// it: an init or extension image that declares a VOLUME would otherwise
// leave one per run, unlabelled, that the destroy sweep can never find
// (podman.go:845).
func TestRunCleanupRemovesAnonymousVolumes(t *testing.T) {
	rec := &recorder{answers: map[string]func([]string) ([]byte, error){"create ": func([]string) ([]byte, error) { return []byte("c0ffee0123456789\n"), nil }}}
	p := &Podman{Exe: "podman", Exec: rec.exec, Attach: func(context.Context, []byte, string, ...string) ([]byte, []byte, int, error) {
		return []byte(`{"contract":"podaro.dev/exec/v1","status":"pass"}`), nil, 0, nil
	}}
	if _, err := p.Run(context.Background(), RunSpec{Name: "pdr-lab-run-vol", Image: "img@sha256:x", Stdin: []byte("{}"), Labels: map[string]string{LabelInstance: "lab"}, Timeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	if !rec.has("rm --force --ignore --volumes c0ffee0123456789") {
		t.Fatalf("the cleanup must remove the anonymous volumes with the container: %v", rec.calls)
	}
}

// A create the caller's context cuts off may have committed the
// image-inspection container, which carries no instance label and so
// nothing else could ever find: under the cleanup's own context, what
// stands under the name is removed — with its anonymous volumes — only
// if it carries the inspection's tag, by the id the inspection saw; a
// stranger there stands (podman.go:1114).
func TestImageFileCleansUpACutOffCreate(t *testing.T) {
	for name, owner := range map[string]string{"its own": "", "a stranger": "someone-else"} {
		var mu sync.Mutex
		var tag string
		var calls []string
		rmCtxErr := error(nil)
		ctx, cancel := context.WithCancel(context.Background())
		p := &Podman{Exe: "podman", Exec: func(c context.Context, _ string, args ...string) ([]byte, error) {
			line := strings.Join(args, " ")
			mu.Lock()
			calls = append(calls, line)
			mu.Unlock()
			switch {
			case strings.HasPrefix(line, "image inspect"):
				return []byte(`[{"Config":{"User":"curl_user"}}]`), nil
			case strings.HasPrefix(line, "create "):
				for _, a := range args {
					if strings.HasPrefix(a, LabelRunID+"=") {
						mu.Lock()
						tag = strings.TrimPrefix(a, LabelRunID+"=")
						mu.Unlock()
					}
				}
				cancel() // the context ends after podman committed the container, before it answered
				return nil, c.Err()
			case strings.HasPrefix(line, "inspect --type container"):
				mu.Lock()
				id := owner
				if id == "" {
					id = tag
				}
				mu.Unlock()
				return []byte(fmt.Sprintf(`[{"Id":"abc","Config":{"Labels":{"dev.podaro/run-id":%q}},"State":{},"NetworkSettings":{"Ports":{}}}]`, id)), nil
			case strings.HasPrefix(line, "rm "):
				rmCtxErr = c.Err()
			}
			return nil, nil
		}}
		_, _ = p.ImageUser(ctx, "img@sha256:x")
		cancel()
		mu.Lock()
		removed := false
		for _, c := range calls {
			if strings.HasPrefix(c, "rm --force --ignore --volumes abc") {
				removed = true
			}
			if strings.HasPrefix(c, "rm ") && strings.Contains(c, "pdr-inspect-") {
				t.Fatalf("%s: a removal by name: %s", name, c)
			}
		}
		mu.Unlock()
		if owner == "" && (!removed || rmCtxErr != nil) {
			t.Fatalf("%s: the cut-off create's container must be removed by its id under a live context: removed=%v ctxErr=%v calls=%v", name, removed, rmCtxErr, calls)
		}
		if owner != "" && removed {
			t.Fatalf("%s: a stranger under the inspection's name must stand: %v", name, calls)
		}
	}
}

// When create succeeds but answers no id, the container is found under
// the inspection's name — under the cleanup's own context: the caller's
// may have ended while create ran, and an inspection that failed for that
// reason alone would leave the tagged container, which carries no
// instance label, behind for good (podman.go:1141).
func TestImageFileFallbackInspectsUnderItsOwnContext(t *testing.T) {
	var mu sync.Mutex
	var tag string
	var calls []string
	inspectCtxErr, rmCtxErr := error(nil), error(nil)
	inspected, removed := false, false
	ctx, cancel := context.WithCancel(context.Background())
	p := &Podman{Exe: "podman", Exec: func(c context.Context, _ string, args ...string) ([]byte, error) {
		line := strings.Join(args, " ")
		mu.Lock()
		calls = append(calls, line)
		mu.Unlock()
		if !strings.HasPrefix(line, "create ") && c.Err() != nil {
			return nil, c.Err() // a command under a context that ended never runs
		}
		switch {
		case strings.HasPrefix(line, "image inspect"):
			return []byte(`[{"Config":{"User":"curl_user"}}]`), nil
		case strings.HasPrefix(line, "create "):
			for _, a := range args {
				if strings.HasPrefix(a, LabelRunID+"=") {
					mu.Lock()
					tag = strings.TrimPrefix(a, LabelRunID+"=")
					mu.Unlock()
				}
			}
			cancel() // the caller's context ends as create answers — with a warning, no id
			return []byte("WARN[0000] a warning line and no id\n"), nil
		case strings.HasPrefix(line, "inspect --type container"):
			mu.Lock()
			inspected, inspectCtxErr = true, c.Err()
			id := tag
			mu.Unlock()
			return []byte(fmt.Sprintf(`[{"Id":"abc","Config":{"Labels":{"dev.podaro/run-id":%q}},"State":{},"NetworkSettings":{"Ports":{}}}]`, id)), nil
		case strings.HasPrefix(line, "rm --force --ignore --volumes abc"):
			mu.Lock()
			removed, rmCtxErr = true, c.Err()
			mu.Unlock()
		}
		return nil, nil
	}}
	got, _ := p.ImageUser(ctx, "img@sha256:x")
	cancel()
	mu.Lock()
	defer mu.Unlock()
	if !inspected || inspectCtxErr != nil {
		t.Fatalf("the fallback inspection must run under a live context: inspected=%v ctxErr=%v calls=%v", inspected, inspectCtxErr, calls)
	}
	if !removed || rmCtxErr != nil {
		t.Fatalf("the tagged container must be removed by its id under a live context: removed=%v ctxErr=%v calls=%v", removed, rmCtxErr, calls)
	}
	if got.Resolved {
		t.Fatalf("a read the context cut off resolves nothing: %+v", got)
	}
}

// An image inspection that cannot draw its tag does not start: two
// inspections under the same entropy failure would wear the same name and
// tag, each free to read or remove the other's container (podman.go:1103).
func TestImageInspectionRefusesWithoutAnIdentity(t *testing.T) {
	saved := randReader
	randReader = iotest.ErrReader(errors.New("no entropy"))
	defer func() { randReader = saved }()
	var mu sync.Mutex
	var calls []string
	p := &Podman{Exe: "podman", Exec: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		mu.Lock()
		calls = append(calls, strings.Join(args, " "))
		mu.Unlock()
		if strings.HasPrefix(args[0], "image") {
			return []byte(`[{"Config":{"User":"curl_user"}}]`), nil
		}
		return []byte("0123456789abcdef\n"), nil
	}}
	got, _ := p.ImageUser(context.Background(), "img@sha256:x")
	mu.Lock()
	defer mu.Unlock()
	for _, c := range calls {
		if strings.HasPrefix(c, "create ") || strings.HasPrefix(c, "cp ") || strings.HasPrefix(c, "rm ") {
			t.Fatalf("nothing is created, read or removed without an identity: %v", calls)
		}
	}
	if got.Resolved {
		t.Fatalf("an inspection that could not start resolves nothing: %+v", got)
	}
}

// An init target that is not there yet is a connection failure the
// rendered runner retries up to Attempts — curl's 000 — whether or not
// the request polls a status; the fake used to give up on the first
// unresolved name for a request without `until` (fake.go:993).
// A target that comes up during the backoff
// succeeds under the fake as it does under Podman.
func TestFakeInitRetriesUntilTheTargetResolves(t *testing.T) {
	f := newTestFake(t)
	ctx := context.Background()
	labels := map[string]string{LabelInstance: "lab", LabelManaged: "true"}
	_ = f.EnsureNetwork(ctx, "pdr-lab", labels, false)
	_ = f.EnsureNetwork(ctx, "pdr-lab-int", labels, true)
	curl := "docker.io/curlimages/curl@sha256:" + strings.Repeat("4", 64)
	_ = f.Pull(ctx, curl)
	program := InitProgram{Requests: []InitRequest{{Method: "GET", URL: "http://late:80/", Attempts: 40, BackoffMillis: 20}}}
	raw, _ := json.Marshal(program)
	spec := RunSpec{Name: "pdr-lab-init-late", Image: curl, Network: "pdr-lab-int", Labels: labels, Command: []string{"-K", InitCurlConfigPath}, Files: []FileSpec{{Path: InitProgramPath, Mode: 0o600, Content: raw}, {Path: InitCurlConfigPath, Mode: 0o600, Content: []byte("url = ...\n")}}, Timeout: 10 * time.Second}
	done := make(chan *RunResult, 1)
	go func() {
		res, err := f.Run(ctx, spec)
		if err != nil {
			t.Error(err)
		}
		done <- res
	}()
	time.Sleep(100 * time.Millisecond) // a few attempts fail to resolve first
	startFake(t, f, ContainerSpec{Name: "pdr-lab-late", Image: "docker.io/library/nginx@sha256:" + strings.Repeat("3", 64), Network: "pdr-lab", Networks: []string{"pdr-lab-int"}, Alias: "late", Labels: map[string]string{LabelInstance: "lab", LabelManaged: "true", LabelService: "late"}, Publish: []int{80}})
	res := <-done
	if res == nil || res.ExitCode != 0 || string(res.Stdout) != "200 GET http://late:80/\n" {
		t.Fatalf("the request succeeds once the target resolves: %+v\nstderr %s", res, res.Stderr)
	}
}
