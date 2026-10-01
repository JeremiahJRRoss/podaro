// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Fake is a runtime whose world lives in one JSON file and whose running
// containers are loopback HTTP listeners: a readiness probe against a fake
// container is a real HTTP request that answers 503 until the container's
// simulated start delay has elapsed, then 200. Because the world file
// outlives the process, killing the engine mid-job and restarting it
// exercises the same resumption path Podman would — with one honest
// difference: the listeners die with the process and are re-spawned on
// load, whereas Podman's containers keep running. A "reboot" is simulated
// by Reboot, which stops every container the way a host restart would.
//
// Plan S6 gives fake containers product personalities keyed by image
// (Prometheus, Grafana) so the small template's checkpoints have a real
// API to query, and one-shot runs: an init helper's request program is
// executed against those products, and the exec-conformance fixture
// image behaves per its first argument (pass · fail · crash · garbage ·
// sleep · seed · secret). What the fake cannot prove — the five walls
// themselves — it refuses to fake: a run on anything but an existing
// internal network is an error.
type Fake struct {
	path       string
	readyAfter time.Duration
	// now is the fake's clock: a container starts at now() and answers
	// 503 until readyAfter has passed on the same clock. A test may set
	// it, so the readiness delay is judged on a clock it controls rather
	// than on the wall — a loaded runner made the wall-clock version pass
	// the delay before the "still starting" request went out (CI on the).
	now func() time.Time

	mu      sync.Mutex
	world   fakeWorld
	servers map[string]*fakeServer
}

type fakeWorld struct {
	Images     map[string]bool              `json:"images"`
	Networks   map[string]map[string]string `json:"networks"`
	Internal   map[string]bool              `json:"internal,omitempty"`
	Containers map[string]*fakeContainer    `json:"containers"`
	// Secrets are the secret objects one-shot runs make (Objects lists
	// them; RemoveSecret removes them), name → labels.
	Secrets map[string]map[string]string `json:"secrets,omitempty"`
	// Dashboards are what a fake Grafana holds, by container: they live in
	// the container's storage — a stop/start keeps them, a removal or a
	// replacement loses them, exactly as the product's own database would.
	Dashboards map[string][]fakeDashboard `json:"dashboards,omitempty"`
	// Sinks are what a fake `example/ndjson-sink` holds, by container —
	// the vendor-neutral destination of fake_sink.go — kept here for the
	// same reason the dashboards are: the fake's restart contract is that
	// a container keeps what it holds.
	Sinks map[string]*sinkState `json:"sinks,omitempty"`
}

type fakeContainer struct {
	ID        string        `json:"id"`
	Spec      ContainerSpec `json:"spec"`
	Running   bool          `json:"running"`
	StartedAt time.Time     `json:"started_at"`
	Ports     map[int]int   `json:"ports"`
	// Files records what was copied in — path, mode, content hash — never
	// the content (it may carry rendered secrets).
	Files []fileDigest `json:"files,omitempty"`
}

type fakeDashboard struct {
	ID    int    `json:"id"`
	UID   string `json:"uid"`
	Title string `json:"title"`
}

type fakeServer struct {
	listeners []net.Listener
	servers   []*http.Server
	// queries counts /api/v1/query requests a fake Prometheus served —
	// its prometheus_http_requests_total{handler="/api/v1/query"}.
	queries atomic.Int64
	// adminPassword is what a fake Grafana read from its env file
	// (GF_SECURITY_ADMIN_PASSWORD): the rendered secret reached the
	// container's configuration.
	adminPassword string
}

// EnvFakeReadyDelay sets the fake's start-to-healthy delay (a Go duration).
const EnvFakeReadyDelay = "PODARO_FAKE_READY_DELAY"

// NewFake opens (or creates) the world file at path.
func NewFake(path string) (*Fake, error) {
	f := &Fake{path: path, readyAfter: 500 * time.Millisecond, servers: map[string]*fakeServer{}, now: time.Now}
	if d, err := time.ParseDuration(os.Getenv(EnvFakeReadyDelay)); err == nil {
		f.readyAfter = d
	}
	if err := f.load(); err != nil {
		return nil, err
	}
	// Re-spawn listeners for containers the world says are running.
	for name, c := range f.world.Containers {
		if c.Running {
			if err := f.spawn(name, c); err != nil {
				return nil, err
			}
		}
	}
	if err := f.save(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *Fake) load() error {
	f.world = fakeWorld{Images: map[string]bool{}, Networks: map[string]map[string]string{}, Internal: map[string]bool{}, Containers: map[string]*fakeContainer{}, Secrets: map[string]map[string]string{}, Dashboards: map[string][]fakeDashboard{}, Sinks: map[string]*sinkState{}}
	raw, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &f.world); err != nil {
		return err
	}
	if f.world.Internal == nil {
		f.world.Internal = map[string]bool{}
	}
	if f.world.Secrets == nil {
		f.world.Secrets = map[string]map[string]string{}
	}
	if f.world.Dashboards == nil {
		f.world.Dashboards = map[string][]fakeDashboard{}
	}
	if f.world.Sinks == nil {
		f.world.Sinks = map[string]*sinkState{}
	}
	return nil
}

// save writes the world atomically (rename) so a kill between writes
// leaves the previous consistent state.
func (f *Fake) save() error {
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(f.world, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

// Info reports the fake as a rootless runtime.
func (f *Fake) Info(ctx context.Context) (Info, error) {
	return Info{Name: "fake", Version: "0", Rootless: true}, nil
}

// Pull records the image; digest refs only, like Podman.
func (f *Fake) Pull(ctx context.Context, image string) error {
	if !containsDigest(image) {
		return fmt.Errorf("refusing to pull %q: images are digest-pinned (repository@sha256:…)", image)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.world.Images[image] = true
	return f.save()
}

func containsDigest(image string) bool {
	for i := 0; i+8 <= len(image); i++ {
		if image[i:i+8] == "@sha256:" {
			return true
		}
	}
	return false
}

// EnsureNetwork records the network once.
func (f *Fake) EnsureNetwork(ctx context.Context, name string, labels map[string]string, internal bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, ok := f.world.Networks[name]; ok {
		return OwnedNetwork(name, existing, labels)
	}
	copied := map[string]string{}
	for k, v := range labels {
		copied[k] = v
	}
	f.world.Networks[name] = copied
	if internal {
		f.world.Internal[name] = true
	} else {
		delete(f.world.Internal, name)
	}
	return f.save()
}

// InspectNetwork reports a network's labels.
func (f *Fake) InspectNetwork(ctx context.Context, name string) (map[string]string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	labels, ok := f.world.Networks[name]
	if !ok {
		return nil, false, nil
	}
	out := map[string]string{}
	for k, v := range labels {
		out[k] = v
	}
	return out, true, nil
}

// Internal reports whether a network was created internal (tests).
func (f *Fake) Internal(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.world.Internal[name]
}

// RemoveNetwork forgets the network; already gone is success.
func (f *Fake) RemoveNetwork(ctx context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// As `podman network rm` without --force: a network still used by a
	// container is refused, whoever owns the container.
	for cname, c := range f.world.Containers {
		if c.Spec.Network == name || contains(c.Spec.Networks, name) {
			return fmt.Errorf("network %s is being used by container %s", name, cname)
		}
	}
	delete(f.world.Networks, name)
	delete(f.world.Internal, name)
	return f.save()
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Create records a stopped container unless the name exists.
func (f *Fake) Create(ctx context.Context, spec ContainerSpec) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	digest, err := spec.Digest()
	if err != nil {
		return "", err
	}
	if c, ok := f.world.Containers[spec.Name]; ok {
		if err := Owned(c.Spec.Labels, spec); err != nil {
			return "", err
		}
		if c.Spec.Labels[LabelSpec] == digest {
			return c.ID, nil
		}
		// Ours, but stale: replace it — its storage goes with it, the
		// dashboards a fake Grafana holds and what a sink received alike.
		// Both are the container's, so a replacement must drop both;
		// hanging the second on Remove alone left a redeployed
		// destination holding the previous container's events.
		f.stopServers(spec.Name)
		delete(f.world.Containers, spec.Name)
		delete(f.world.Dashboards, spec.Name)
		delete(f.world.Sinks, spec.Name)
	}
	spec = withSpecLabel(spec, digest)
	if !f.world.Images[spec.Image] {
		return "", fmt.Errorf("image %s not pulled", spec.Image)
	}
	for _, n := range append([]string{spec.Network}, spec.Networks...) {
		if n == "" {
			continue
		}
		if _, ok := f.world.Networks[n]; !ok {
			return "", fmt.Errorf("network %s does not exist", n)
		}
	}
	for _, file := range spec.Files {
		if err := ValidateFilePath(file.Path); err != nil {
			return "", err // the same wall Podman's copy-in applies
		}
	}
	files := FileDigests(spec.Files)
	spec.Files = nil // content never reaches the world file
	var b [12]byte
	_, _ = rand.Read(b[:])
	c := &fakeContainer{ID: hex.EncodeToString(b[:]), Spec: spec, Ports: map[int]int{}, Files: files}
	f.world.Containers[spec.Name] = c
	return c.ID, f.save()
}

// Start marks the container running and spawns its listeners.
func (f *Fake) Start(ctx context.Context, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	name, c := f.resolve(ref) // a name or an id, as podman start takes either
	if c == nil {
		return fmt.Errorf("container %s: %w", ref, ErrNotFound)
	}
	if c.Running {
		return nil
	}
	c.Running = true
	c.StartedAt = f.now()
	if err := f.spawn(name, c); err != nil {
		c.Running = false
		return err
	}
	return f.save()
}

// spawn binds one loopback listener per published port, reusing the
// recorded host port when it is still free (a restarted engine finds the
// same address), and serves the readiness contract in front of the
// container's product personality.
func (f *Fake) spawn(name string, c *fakeContainer) error {
	f.stopServers(name)
	fs := &fakeServer{}
	if c.Ports == nil {
		c.Ports = map[int]int{}
	}
	if c.Spec.EnvFile != "" {
		fs.adminPassword = envFileValue(c.Spec.EnvFile, "GF_SECURITY_ADMIN_PASSWORD")
	}
	ports := append([]int(nil), c.Spec.Publish...)
	sort.Ints(ports)
	product := f.personality(name, c, fs)
	for _, cport := range ports {
		addr := "127.0.0.1:0"
		if hp, ok := c.Ports[cport]; ok && hp > 0 {
			addr = "127.0.0.1:" + strconv.Itoa(hp)
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			l, err = net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				fs.close()
				return err
			}
		}
		c.Ports[cport] = l.Addr().(*net.TCPAddr).Port
		started := c.StartedAt
		ready := f.readyAfter
		clock := f.now
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if clock().Sub(started) < ready {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprintln(w, "starting")
				return
			}
			product.ServeHTTP(w, r)
		})}
		listener := l
		// A port a module declares as https answers a real handshake: a
		// checkpoint that names https must not be proved against a
		// product speaking plain HTTP (plan S8).
		if tp, ok := product.(tlsProduct); ok && tp.servesTLS(cport) {
			cert, err := fakeCertificate()
			if err != nil {
				fs.close()
				return err
			}
			listener = tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{*cert}})
		}
		go func() { _ = srv.Serve(listener) }()
		fs.listeners = append(fs.listeners, l)
		fs.servers = append(fs.servers, srv)
	}
	f.servers[name] = fs
	return nil
}

// envFileValue reads one KEY=VALUE from an env file (the fake product's
// way of proving the rendered configuration reached it).
func envFileValue(path, key string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok && k == key {
			return v
		}
	}
	return ""
}

// personality picks the product behavior for a container by its image.
func (f *Fake) personality(name string, c *fakeContainer, fs *fakeServer) http.Handler {
	switch {
	case strings.Contains(c.Spec.Image, "prom/prometheus"):
		return &fakePrometheus{f: f, name: name, fs: fs}
	case strings.Contains(c.Spec.Image, "grafana/grafana"):
		return &fakeGrafana{f: f, name: name, fs: fs}
	case strings.Contains(c.Spec.Image, "example/ndjson-sink"):
		// The vendor-neutral destination (fake_sink.go): what a seed
		// delivers, kept and read back, with no product in the picture.
		return &fakeSink{f: f, name: name}
	case strings.Contains(c.Spec.Image, "example/tls-echo"):
		// The vendor-neutral https personality (fake_tls.go): every port
		// answers a real handshake.
		return &fakeTLSEcho{name: name}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fakeProductResponse(w, r, name) })
}

// fakeProductResponse behaves like a lab product UI behind the gateway
// (plan S5): it forbids framing the way many product UIs do — headers
// the gateway must rewrite on product vhosts — echoes the forwarded
// facts so a test can see what the proxy sent, and answers a WebSocket
// upgrade with a raw byte echo so the upgrade path is provable.
func fakeProductResponse(w http.ResponseWriter, r *http.Request, name string) {
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Fake-Upgrade: %s\r\n\r\n", name)
		_ = rw.Flush()
		buf := make([]byte, 1024)
		for {
			n, err := rw.Read(buf)
			if n > 0 {
				_, _ = rw.Write(buf[:n])
				_ = rw.Flush()
			}
			if err != nil {
				return
			}
		}
	}
	h := w.Header()
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	h.Set("X-Fake-Host", r.Host)
	h.Set("X-Fake-Forwarded-Proto", r.Header.Get("X-Forwarded-Proto"))
	h.Set("X-Fake-Forwarded-For", r.Header.Get("X-Forwarded-For"))
	h.Set("X-Fake-Cookie", r.Header.Get("Cookie"))
	h.Set("X-Fake-Authorization", r.Header.Get("Authorization"))
	if r.Header.Get("X-Fake-Set-Cookie") != "" {
		// A hostile product trying to set the gateway's own cookie, beside
		// one of its own (the gateway must drop the first and pass the second).
		h.Add("Set-Cookie", "podaro_session=evil; Path=/")
		h.Add("Set-Cookie", "app=1; Path=/")
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "<!doctype html><title>fake %s</title><p>fake %s ok · path %s\n", name, name, r.URL.Path)
}

// --- Prometheus ---------------------------------------------------------

var upJob = regexp.MustCompile(`^up\{job="([^"]+)"\}$`)

// fakePrometheus answers the endpoints the small template's checkpoints
// and seed touch: readiness, and /api/v1/query for `up{job=…}` (1 when the
// named job is this server or a running sibling on its network) and the
// `prometheus_http_requests_total{handler="/api/v1/query"}` counter — the
// queries it has served, so 200 seeded requests read ≥ 200 afterwards.
type fakePrometheus struct {
	f    *Fake
	name string
	fs   *fakeServer
}

func (p *fakePrometheus) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/-/ready":
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Prometheus Server is Ready.")
	case r.URL.Path == "/-/healthy":
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Prometheus Server is Healthy.")
	case r.URL.Path == "/api/v1/query":
		served := p.fs.queries.Add(1) - 1 // what the counter read before this request
		query := strings.TrimSpace(r.URL.Query().Get("query"))
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		type sample struct {
			Metric map[string]string `json:"metric"`
			Value  []any             `json:"value"`
		}
		var result []sample
		switch {
		case upJob.MatchString(query):
			job := upJob.FindStringSubmatch(query)[1]
			if job == "prometheus" || p.f.siblingRunning(p.name, job) {
				result = append(result, sample{Metric: map[string]string{"__name__": "up", "job": job}, Value: []any{ts, "1"}})
			}
		case query == "up":
			result = append(result, sample{Metric: map[string]string{"__name__": "up", "job": "prometheus"}, Value: []any{ts, "1"}})
		case strings.Contains(query, "prometheus_http_requests_total"):
			result = append(result, sample{Metric: map[string]string{}, Value: []any{ts, strconv.FormatInt(served, 10)}})
		}
		if result == nil {
			result = []sample{}
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": result}})
	case r.URL.Path == "/" || r.URL.Path == "/graph" || r.URL.Path == "/query":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><title>Prometheus</title><p>fake %s\n", p.name)
	default:
		writeFakeJSON(w, http.StatusNotFound, map[string]any{"status": "error", "error": "no such endpoint"})
	}
}

// siblingRunning reports whether a running container with the given
// alias shares a network with the named container.
func (f *Fake) siblingRunning(name, alias string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	self, ok := f.world.Containers[name]
	if !ok {
		return false
	}
	mine := append([]string{self.Spec.Network}, self.Spec.Networks...)
	for _, c := range f.world.Containers {
		if !c.Running || c.Spec.Alias != alias {
			continue
		}
		for _, n := range append([]string{c.Spec.Network}, c.Spec.Networks...) {
			if n != "" && contains(mine, n) {
				return true
			}
		}
	}
	return false
}

// --- Grafana ------------------------------------------------------------

// fakeGrafana answers /api/health, dashboard search, and dashboard
// creation under the admin password the rendered env file carried — the
// learner's "build a dashboard" act, done by hand against the API.
type fakeGrafana struct {
	f    *Fake
	name string
	fs   *fakeServer
}

func (g *fakeGrafana) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/health":
		writeFakeJSON(w, http.StatusOK, map[string]any{"database": "ok", "version": "fake"})
	case r.URL.Path == "/api/search" && r.Method == http.MethodGet:
		q := strings.ToLower(r.URL.Query().Get("query"))
		list := []fakeDashboard{}
		for _, d := range g.f.dashboards(g.name) {
			if q == "" || strings.Contains(strings.ToLower(d.Title), q) {
				list = append(list, d)
			}
		}
		out := make([]map[string]any, 0, len(list))
		for _, d := range list {
			out = append(out, map[string]any{"id": d.ID, "uid": d.UID, "title": d.Title, "type": "dash-db", "url": "/d/" + d.UID})
		}
		writeFakeJSON(w, http.StatusOK, out)
	case r.URL.Path == "/api/dashboards/db" && r.Method == http.MethodPost:
		if !g.authorized(r) {
			writeFakeJSON(w, http.StatusUnauthorized, map[string]any{"message": "invalid username or password"})
			return
		}
		var body struct {
			Dashboard struct {
				Title string `json:"title"`
			} `json:"dashboard"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || strings.TrimSpace(body.Dashboard.Title) == "" {
			writeFakeJSON(w, http.StatusBadRequest, map[string]any{"message": "dashboard title required"})
			return
		}
		d := g.f.addDashboard(g.name, body.Dashboard.Title)
		writeFakeJSON(w, http.StatusOK, map[string]any{"id": d.ID, "uid": d.UID, "status": "success", "url": "/d/" + d.UID})
	case strings.HasPrefix(r.URL.Path, "/api/dashboards/uid/") && r.Method == http.MethodDelete:
		if !g.authorized(r) {
			writeFakeJSON(w, http.StatusUnauthorized, map[string]any{"message": "invalid username or password"})
			return
		}
		uid := strings.TrimPrefix(r.URL.Path, "/api/dashboards/uid/")
		if !g.f.removeDashboard(g.name, uid) {
			writeFakeJSON(w, http.StatusNotFound, map[string]any{"message": "dashboard not found"})
			return
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{"message": "dashboard deleted"})
	case r.URL.Path == "/" || r.URL.Path == "/login":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><title>Grafana</title><p>fake %s\n", g.name)
	default:
		writeFakeJSON(w, http.StatusNotFound, map[string]any{"message": "not found"})
	}
}

func (g *fakeGrafana) authorized(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	return ok && user == "admin" && g.fs.adminPassword != "" && pass == g.fs.adminPassword
}

func (f *Fake) dashboards(container string) []fakeDashboard {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeDashboard(nil), f.world.Dashboards[container]...)
}

func (f *Fake) addDashboard(container, title string) fakeDashboard {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b [6]byte
	_, _ = rand.Read(b[:])
	d := fakeDashboard{ID: len(f.world.Dashboards[container]) + 1, UID: hex.EncodeToString(b[:]), Title: title}
	f.world.Dashboards[container] = append(f.world.Dashboards[container], d)
	_ = f.save()
	return d
}

func (f *Fake) removeDashboard(container, uid string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := f.world.Dashboards[container]
	for i, d := range list {
		if d.UID == uid {
			f.world.Dashboards[container] = append(list[:i:i], list[i+1:]...)
			_ = f.save()
			return true
		}
	}
	return false
}

func writeFakeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (fs *fakeServer) close() {
	for _, s := range fs.servers {
		_ = s.Close()
	}
	for _, l := range fs.listeners {
		_ = l.Close()
	}
}

func (f *Fake) stopServers(name string) {
	fs, ok := f.servers[name]
	if !ok {
		return
	}
	fs.close()
	delete(f.servers, name)
}

// Stop marks the container stopped and closes its listeners.
func (f *Fake) Stop(ctx context.Context, ref string, timeout time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	name, c := f.resolve(ref) // a name or an id, as podman stop takes either
	if c == nil {
		return fmt.Errorf("container %s: %w", name, ErrNotFound)
	}
	c.Running = false
	f.stopServers(name)
	return f.save()
}

// Remove forgets the container; already gone is success. Its storage —
// a fake Grafana's dashboards, what a sink received — goes with it, as a
// product's own data does on a host with no volume under it, so a reset
// that removes a container starts its destination empty again.
func (f *Fake) Remove(ctx context.Context, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	name, c := f.resolve(ref)
	if c == nil {
		return nil // already gone
	}
	f.stopServers(name)
	delete(f.world.Containers, name)
	delete(f.world.Dashboards, name)
	delete(f.world.Sinks, name)
	return f.save()
}

// resolve finds a container by its name or, as podman does, by its id;
// a removal by the id an inspection saw never takes a container that
// took the name meanwhile.
func (f *Fake) resolve(ref string) (string, *fakeContainer) {
	if c, ok := f.world.Containers[ref]; ok {
		return ref, c
	}
	for name, c := range f.world.Containers {
		if c.ID == ref {
			return name, c
		}
	}
	return "", nil
}

// Inspect returns nil, nil for an absent container; a name or an id.
func (f *Fake) Inspect(ctx context.Context, ref string) (*ContainerState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, c := f.resolve(ref)
	if c == nil {
		return nil, nil
	}
	st := &ContainerState{ID: c.ID, Running: c.Running, StartedAt: c.StartedAt, Ports: map[int]int{}, Labels: map[string]string{}, Image: c.Spec.Image}
	for k, v := range c.Ports {
		st.Ports[k] = v
	}
	for k, v := range c.Spec.Labels {
		st.Labels[k] = v
	}
	return st, nil
}

// Objects lists everything labeled with the instance.
func (f *Fake) Objects(ctx context.Context, instance string) (Objects, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var o Objects
	for name, c := range f.world.Containers {
		if c.Spec.Labels[LabelInstance] == instance {
			o.Containers = append(o.Containers, name)
		}
	}
	for name, labels := range f.world.Networks {
		if labels[LabelInstance] == instance {
			o.Networks = append(o.Networks, name)
		}
	}
	for name, labels := range f.world.Secrets {
		if labels[LabelInstance] == instance {
			o.Secrets = append(o.Secrets, name)
		}
	}
	sort.Strings(o.Containers)
	sort.Strings(o.Networks)
	sort.Strings(o.Secrets)
	return o, nil
}

// AddSecret records a secret object as a crashed run would leave it
// (tests of the destroy sweep).
func (f *Fake) AddSecret(name string, labels map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.world.Secrets[name] = labels
	return f.save()
}

// RemoveSecret forgets a secret object; already gone is success.
func (f *Fake) RemoveSecret(ctx context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.world.Secrets, name)
	return f.save()
}

// ImageUser reports the user a fake image runs as: images whose name
// carries "-root" run as root, "-unresolved" declare a user the image
// cannot resolve, everything else runs as 1000.
func (f *Fake) ImageUser(ctx context.Context, image string) (ImageUser, error) {
	f.mu.Lock()
	pulled := f.world.Images[image]
	f.mu.Unlock()
	if !pulled {
		return ImageUser{}, fmt.Errorf("image %s not pulled", image)
	}
	switch {
	case strings.Contains(image, "-root@"):
		return ImageUser{Raw: "", Resolved: true}, nil
	case strings.Contains(image, "-unresolved@"):
		return ImageUser{Raw: "svc", Resolved: false}, nil
	}
	return ImageUser{Raw: "1000", UID: 1000, GID: 1000, Resolved: true}, nil
}

// ReadFake opens the fake's world for reading alone: nothing is spawned
// and nothing is written, so a second process — `system upgrade`'s
// preflight, beside a running engine — can see what the world holds
// without starting a listener or saving over the engine's file.
func ReadFake(path string) (ContainerReader, error) {
	f := &Fake{path: path, servers: map[string]*fakeServer{}}
	if err := f.load(); err != nil {
		return nil, err
	}
	return f, nil
}

// Reboot simulates a host restart: every container is stopped, as a
// reboot leaves them; the engine's reconcile must bring them back.
func Reboot(path string) error {
	f := &Fake{path: path, servers: map[string]*fakeServer{}}
	if err := f.load(); err != nil {
		return err
	}
	for _, c := range f.world.Containers {
		c.Running = false
	}
	return f.save()
}

// Spec returns a container's recorded spec (tests), or nil.
func (f *Fake) Spec(name string) *ContainerSpec {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.world.Containers[name]
	if !ok {
		return nil
	}
	spec := c.Spec
	return &spec
}

// Files returns what was copied into a container (tests): paths, modes,
// content hashes.
func (f *Fake) Files(name string) []fileDigest {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.world.Containers[name]
	if !ok {
		return nil
	}
	return append([]fileDigest(nil), c.Files...)
}

// Queries reports how many /api/v1/query requests a fake Prometheus has
// served (tests).
func (f *Fake) Queries(name string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if fs, ok := f.servers[name]; ok {
		return fs.queries.Load()
	}
	return 0
}

// Close releases every listener.
func (f *Fake) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for name := range f.servers {
		f.stopServers(name)
	}
}

// --- one-shot runs --------------------------------------------------------

// Run executes a one-shot container in-process. The network wall is the
// one wall the fake can observe, so it is enforced: the run must name an
// existing internal network. Secrets become objects for the run's
// duration, as with Podman. What runs is decided by the image and files:
// an init helper (the request program at InitProgramPath) executes its
// requests against the products on the run's network; the exec-conformance
// fixture image behaves per its first argument; anything else cannot run
// here and is an error.
func (f *Fake) Run(ctx context.Context, spec RunSpec) (*RunResult, error) {
	f.mu.Lock()
	if !f.world.Images[spec.Image] {
		f.mu.Unlock()
		return nil, fmt.Errorf("image %s not pulled", spec.Image)
	}
	if _, ok := f.world.Networks[spec.Network]; !ok || !f.world.Internal[spec.Network] {
		f.mu.Unlock()
		return nil, fmt.Errorf("run %s: network %q is not an internal network of this world — one-shot runs join the instance's internal network only", spec.Name, spec.Network)
	}
	// A name in use is refused, as podman create refuses it: a leftover
	// under the run's name is the caller's to remove first.
	if _, exists := f.world.Containers[spec.Name]; exists {
		f.mu.Unlock()
		return nil, fmt.Errorf("run %s: the container name is already in use", spec.Name)
	}
	var created []string
	var rb [8]byte
	_, _ = rand.Read(rb[:])
	runID := hex.EncodeToString(rb[:])
	for _, s := range spec.Secrets {
		name := runSecretName(spec, runID, s.Name)
		f.world.Secrets[name] = map[string]string{LabelInstance: spec.Labels[LabelInstance], LabelRun: spec.Name}
		created = append(created, name)
	}
	_ = f.save()
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		for _, n := range created {
			delete(f.world.Secrets, n)
		}
		_ = f.save()
		f.mu.Unlock()
	}()

	rctx := ctx
	if spec.Timeout > 0 {
		var cancel context.CancelFunc
		rctx, cancel = context.WithTimeout(ctx, spec.Timeout)
		defer cancel()
	}
	res := &RunResult{Started: time.Now().UTC()}
	maxOut, maxErr := spec.MaxStdout, spec.MaxStderr
	if maxOut <= 0 {
		maxOut = DefaultMaxStdout
	}
	if maxErr <= 0 {
		maxErr = DefaultMaxStderr
	}
	var program *InitProgram
	for _, file := range spec.Files {
		if file.Path == InitProgramPath {
			var p InitProgram
			if err := json.Unmarshal(file.Content, &p); err != nil {
				return nil, fmt.Errorf("init program: %w", err)
			}
			program = &p
		}
	}
	switch {
	case program != nil:
		stdout, stderr, code := f.runInitProgram(rctx, spec.Network, program)
		res.Stdout, res.StdoutTruncated = cut(stdout, maxOut)
		res.Stderr, res.StderrTruncated = cut(stderr, maxErr)
		res.ExitCode = code
	case strings.Contains(spec.Image, "exec-conformance"):
		stdout, stderr, code := f.runConformance(rctx, spec)
		res.Stdout, res.StdoutTruncated = cut(stdout, maxOut)
		res.Stderr, res.StderrTruncated = cut(stderr, maxErr)
		res.ExitCode = code
	default:
		return nil, fmt.Errorf("the fake runtime cannot run %s: only init helpers and the exec-conformance fixture run here", spec.Image)
	}
	res.Finished = time.Now().UTC()
	if errors.Is(rctx.Err(), context.DeadlineExceeded) {
		// A deadline is a timeout wherever it came from: the run's own
		// budget or the caller's (a checkpoint's timeout bounds both, and
		// they expire together). A cancellation is not.
		res.TimedOut = true
		res.ExitCode = -1
	}
	return res, nil
}

// resolveService maps a service alias on a network to its loopback
// address for one container port.
func (f *Fake) resolveService(network, alias string, port int) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.world.Containers {
		if !c.Running || c.Spec.Alias != alias {
			continue
		}
		if c.Spec.Network != network && !contains(c.Spec.Networks, network) {
			continue
		}
		if hp := c.Ports[port]; hp > 0 {
			return "127.0.0.1:" + strconv.Itoa(hp), true
		}
		return "", false
	}
	return "", false
}

// runInitProgram performs the request sequence as the curl helper would:
// in order, polling each `until` request within its attempts, stopping at
// the first request that fails (curl's --fail-early), printing one line
// per request the way write-out does.
func (f *Fake) runInitProgram(ctx context.Context, network string, p *InitProgram) (stdout, stderr []byte, code int) {
	var out, errOut bytes.Buffer
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}} //nolint:gosec // lab self-signed certificates
	for i, req := range p.Requests {
		u, err := url.Parse(req.URL)
		if err != nil {
			fmt.Fprintf(&errOut, "request %d: %v\n", i+1, err)
			return out.Bytes(), errOut.Bytes(), 3
		}
		port, _ := strconv.Atoi(u.Port())
		if port == 0 {
			port = 80
			if u.Scheme == "https" {
				port = 443
			}
		}
		attempts := req.Attempts
		if attempts < 1 {
			attempts = 1
		}
		backoff := time.Duration(req.BackoffMillis) * time.Millisecond
		status := 0
		var lastErr error
		for attempt := 0; attempt < attempts; attempt++ {
			if attempt > 0 {
				select {
				case <-ctx.Done():
					fmt.Fprintf(&errOut, "request %d: %v\n", i+1, ctx.Err())
					return out.Bytes(), errOut.Bytes(), 28
				case <-time.After(backoff):
				}
			}
			addr, ok := f.resolveService(network, u.Hostname(), port)
			if !ok {
				// A target not there yet is a connection failure — curl's
				// 000, which the rendered runner retries up to Attempts
				// whether or not the request polls a status — so the fake
				// retries it the same.
				lastErr = fmt.Errorf("could not resolve host: %s", u.Hostname())
				status = 0
				continue
			}
			target := *u
			target.Host = addr
			var body io.Reader
			if req.BodyDeclared() {
				body = strings.NewReader(req.Body)
			}
			hreq, err := http.NewRequestWithContext(ctx, req.Method, target.String(), body)
			if err != nil {
				lastErr = err
				break
			}
			hreq.Host = u.Host
			for k, v := range req.Headers {
				// the wire Host is the request's own field, as curl sends an
				// authored Host header
				if strings.EqualFold(k, "Host") {
					hreq.Host = v
					continue
				}
				hreq.Header.Set(k, v)
			}
			if req.BodyDeclared() && hreq.Header.Get("Content-Type") == "" {
				hreq.Header.Set("Content-Type", "application/json")
			}
			if req.Username != "" || req.Password != "" {
				hreq.SetBasicAuth(req.Username, req.Password)
			}
			resp, err := client.Do(hreq)
			if err != nil {
				lastErr = err
				status = 0
				if req.Until == 0 && !isTransient(err) {
					break
				}
				continue
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			status = resp.StatusCode
			lastErr = nil
			if req.Until != 0 {
				if status == req.Until {
					break
				}
				continue
			}
			if status < 400 || attempt == attempts-1 || status < 500 {
				break
			}
		}
		fmt.Fprintf(&out, "%d %s %s\n", status, req.Method, req.URL)
		failed := lastErr != nil || (req.Until != 0 && status != req.Until) || (req.Until == 0 && status >= 400)
		if failed {
			if lastErr != nil {
				fmt.Fprintf(&errOut, "curl: (7) request %d %s %s: %v\n", i+1, req.Method, req.URL, lastErr)
				return out.Bytes(), errOut.Bytes(), 7
			}
			fmt.Fprintf(&errOut, "curl: (22) request %d %s %s returned %d\n", i+1, req.Method, req.URL, status)
			return out.Bytes(), errOut.Bytes(), 22
		}
	}
	return out.Bytes(), errOut.Bytes(), 0
}

func isTransient(err error) bool {
	return err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

// execInput is the Spec 0002 §3 stdin the conformance behaviors read.
type execInput struct {
	Contract string `json:"contract"`
	Kind     string `json:"kind"`
	RunID    string `json:"run_id"`
	Instance struct {
		Name      string `json:"name"`
		Endpoints []any  `json:"endpoints"`
	} `json:"instance"`
	Secrets struct {
		Granted []string `json:"granted"`
	} `json:"secrets"`
	Checkpoint struct {
		ID     string          `json:"id"`
		Expect json.RawMessage `json:"expect"`
	} `json:"checkpoint"`
	Seed struct {
		Name      string `json:"name"`
		Count     int    `json:"count"`
		SeedValue string `json:"seed_value"`
	} `json:"seed"`
}

// runConformance is the exec-conformance fixture's behavior table, shared
// with hack/fixtures/exec-conformance (the real image) so both prove the
// same Spec 0002 §6 mappings.
func (f *Fake) runConformance(ctx context.Context, spec RunSpec) (stdout, stderr []byte, code int) {
	mode := "pass"
	if len(spec.Command) > 0 {
		mode = spec.Command[0]
	}
	var in execInput
	if err := json.Unmarshal(spec.Stdin, &in); err != nil {
		return nil, []byte("conformance: stdin is not contract JSON: " + err.Error() + "\n"), 3
	}
	capture := map[string]any{"run_id": in.RunID, "endpoints": len(in.Instance.Endpoints), "secrets": in.Secrets.Granted}
	verdict := func(status string, observed any, message string) []byte {
		raw, _ := json.Marshal(map[string]any{"contract": "podaro.dev/exec/v1", "status": status, "observed": observed, "message": message, "evidence": map[string]any{"capture": capture}})
		return append(raw, '\n')
	}
	switch mode {
	case "crash":
		return nil, []byte("conformance: crashing on purpose (exit 2)\n"), 2
	case "garbage":
		return []byte("this is not contract json\n"), nil, 0
	case "sleep":
		<-ctx.Done()
		return nil, []byte("conformance: killed while sleeping\n"), 137
	case "secret":
		// A granted secret is read from its file, never echoed: only its
		// length is observed.
		n := 0
		for _, s := range spec.Secrets {
			if raw, err := os.ReadFile(s.Source); err == nil {
				n = len(bytes.TrimSpace(raw))
				break
			}
		}
		return verdict("pass", map[string]any{"secret_bytes": n}, "read the granted secret as a file"), nil, 0
	case "claim":
		// A misbehaving adapter of the other kind: it writes the engine's
		// own capture keys, claiming a different image and a different
		// grant set than the run used. The engine's reserved keys are
		// what keep evidence honest.
		capture["image"] = "docker.io/attacker/other@sha256:" + strings.Repeat("0", 64)
		capture["secrets"] = []any{"never-granted"}
		return verdict("pass", map[string]any{"ok": true}, "claimed the engine's keys"), nil, 0
	case "leak":
		// A misbehaving adapter: it echoes the granted secret into every
		// place a verdict can carry a value — nested, in arrays, in the
		// message, in the capture, in a seed's sent counts. The engine's
		// redaction filter is what keeps it out of evidence.
		v := "no-secret-granted"
		for _, s := range spec.Secrets {
			if raw, err := os.ReadFile(s.Source); err == nil {
				v = string(bytes.TrimSpace(raw))
				break
			}
		}
		capture["leaked"] = map[string]any{"token": v, "list": []any{v, map[string]any{"deep": v}}}
		if in.Kind == "seed" {
			raw, _ := json.Marshal(map[string]any{"contract": "podaro.dev/exec/v1", "status": "ok", "sent": map[string]any{"events": 1, "echo": v, "nested": []any{map[string]any{"deep": v}}}, "message": "leaked " + v})
			return append(raw, '\n'), []byte("leak: " + v + "\n"), 0
		}
		return verdict("pass", map[string]any{"echo": v, "nested": map[string]any{"deep": []any{v}}}, "leaked "+v), []byte("leak: " + v + "\n"), 0
	}
	if in.Kind == "seed" {
		raw, _ := json.Marshal(map[string]any{"contract": "podaro.dev/exec/v1", "status": "ok", "sent": map[string]any{"events": in.Seed.Count}, "message": fmt.Sprintf("%d events, seeded rng %s", in.Seed.Count, in.Seed.SeedValue)})
		return append(raw, '\n'), nil, 0
	}
	if mode == "fail" {
		return verdict("fail", map[string]any{"lag": 3}, "conformance fail: lag 3 above 0"), []byte("diagnostic chatter on stderr\n"), 0
	}
	var observed any = map[string]any{"ran": true}
	if len(in.Checkpoint.Expect) > 0 {
		observed = in.Checkpoint.Expect
	}
	return verdict("pass", observed, "conformance pass"), nil, 0
}
