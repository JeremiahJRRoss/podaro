// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Podman drives rootless Podman through its CLI with JSON output. Commands
// are built here and executed through Exec so tests pin the exact command
// lines and parse recorded output without a Podman on the host.
type Podman struct {
	// Exe is the podman executable (default "podman").
	Exe string
	// Exec runs a command and returns stdout; nil uses os/exec.
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
	// Attach runs a command with stdin and returns stdout, stderr and the
	// exit code separately (Run's `podman start --attach`); nil uses
	// os/exec. A non-nil error means the command could not be run at all.
	Attach func(ctx context.Context, stdin []byte, name string, args ...string) (stdout, stderr []byte, exitCode int, err error)
}

// NewPodman returns the CLI-backed runtime.
func NewPodman() *Podman {
	return &Podman{Exe: "podman"}
}

func (p *Podman) run(ctx context.Context, args ...string) ([]byte, error) {
	if p.Exec != nil {
		return p.Exec(ctx, p.Exe, args...)
	}
	cmd := exec.CommandContext(ctx, p.Exe, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.Bytes(), &CommandError{Args: args, Err: err, Stderr: msg}
	}
	return stdout.Bytes(), nil
}

// attached is what an attach returns: both streams, whether the cap cut
// either, and the exit code.
type attached struct {
	stdout, stderr []byte
	outCut, errCut bool
	code           int
}

// attach runs podman with stdin attached, separating the streams.
func (p *Podman) attach(ctx context.Context, stdin []byte, maxOut, maxErr int, args ...string) (attached, error) {
	if p.Attach != nil {
		// The seam's output meets the same caps as a real attach.
		so, se, code, err := p.Attach(ctx, stdin, p.Exe, args...)
		var a attached
		a.stdout, a.outCut = cut(so, maxOut)
		a.stderr, a.errCut = cut(se, maxErr)
		a.code = code
		return a, err
	}
	cmd := exec.CommandContext(ctx, p.Exe, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	stdout := &cappedBuffer{max: maxOut}
	stderr := &cappedBuffer{max: maxErr}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// The container's stdin is closed once the input is written: podman
	// start --interactive forwards EOF, so an extension reading stdin to
	// the end sees it.
	err := cmd.Run()
	a := attached{stdout: stdout.Bytes(), stderr: stderr.Bytes(), outCut: stdout.truncated, errCut: stderr.truncated}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			a.code = ee.ExitCode()
			return a, nil
		}
		a.code = -1
		return a, err
	}
	return a, nil
}

// cappedBuffer keeps the first max bytes written and drops the rest,
// noting that it did (Spec 0002 §2: stderr capped).
type cappedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.max <= 0 {
		return c.buf.Write(p)
	}
	room := c.max - c.buf.Len()
	if room <= 0 {
		c.truncated = true
		return len(p), nil
	}
	if len(p) > room {
		c.truncated = true
		_, _ = c.buf.Write(p[:room])
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *cappedBuffer) Bytes() []byte { return c.buf.Bytes() }

// CommandError carries the failing podman invocation (arguments only —
// environment travels in files, never on the command line).
type CommandError struct {
	Args   []string
	Err    error
	Stderr string
}

// Error names the podman verb and carries podman's stderr — never the
// argument values: a create's arguments hold rendered configuration
// (a service's command and args may carry a secret), and an error's text
// travels into the job journal, the job record, and the log.
func (e *CommandError) Error() string {
	return fmt.Sprintf("podman %s: %s", commandVerb(e.Args), strings.TrimSpace(e.Stderr))
}

// commandVerb is the sub-command an argument list invokes: `create`,
// `network create`, `image inspect` — the words before the first flag or
// operand, at most two.
func commandVerb(args []string) string {
	var verb []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") || len(verb) == 2 {
			break
		}
		verb = append(verb, a)
	}
	if len(verb) == 0 {
		return "(no command)"
	}
	return strings.Join(verb, " ")
}

func (e *CommandError) Unwrap() error { return e.Err }

// ExitCode reports the process exit status behind a run error (-1 when
// the command did not run to an exit status).
func ExitCode(err error) int {
	var coder interface{ ExitCode() int }
	if errors.As(err, &coder) {
		return coder.ExitCode()
	}
	return -1
}

// exists runs `podman <kind> exists <name>`: exit 0 is present, exit 1
// absent, anything else (125: storage or daemon trouble) is an error —
// never mistaken for absence (podman-container-exists(1)).
func (p *Podman) exists(ctx context.Context, kind, name string) (bool, error) {
	_, err := p.run(ctx, kind, "exists", name)
	if err == nil {
		return true, nil
	}
	if ExitCode(err) == 1 {
		return false, nil
	}
	return false, err
}

// Info runs `podman info --format json`.
func (p *Podman) Info(ctx context.Context) (Info, error) {
	out, err := p.run(ctx, "info", "--format", "json")
	if err != nil {
		return Info{}, err
	}
	var doc struct {
		Version struct {
			Version string `json:"Version"`
		} `json:"version"`
		Host struct {
			Security struct {
				Rootless bool `json:"rootless"`
			} `json:"security"`
		} `json:"host"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return Info{}, fmt.Errorf("podman info: %w", err)
	}
	return Info{Name: "podman", Version: doc.Version.Version, Rootless: doc.Host.Security.Rootless}, nil
}

// Pull pulls a digest-pinned image; a tag reference is refused here too,
// so no code path can ever pull a floating tag (extraction §7).
func (p *Podman) Pull(ctx context.Context, image string) error {
	if !strings.Contains(image, "@sha256:") {
		return fmt.Errorf("refusing to pull %q: images are digest-pinned (repository@sha256:…)", image)
	}
	_, err := p.run(ctx, "pull", "--quiet", image)
	return err
}

// NetworkCreateArgs renders `podman network create` for a network: labels
// sorted, --internal for a network with no route out (Spec 0002 §2).
func NetworkCreateArgs(name string, labels map[string]string, internal bool) []string {
	args := []string{"network", "create"}
	if internal {
		args = append(args, "--internal")
	}
	for _, k := range sortedLabelKeys(labels) {
		args = append(args, "--label", k+"="+labels[k])
	}
	return append(args, name)
}

// EnsureNetwork creates the per-instance network once.
func (p *Podman) EnsureNetwork(ctx context.Context, name string, labels map[string]string, internal bool) error {
	if existing, exists, err := p.InspectNetwork(ctx, name); err != nil {
		return err
	} else if exists {
		return OwnedNetwork(name, existing, labels)
	}
	_, err := p.run(ctx, NetworkCreateArgs(name, labels, internal)...)
	return err
}

// InspectNetwork reports a network's labels.
func (p *Podman) InspectNetwork(ctx context.Context, name string) (map[string]string, bool, error) {
	if ok, err := p.exists(ctx, "network", name); err != nil {
		return nil, false, err
	} else if !ok {
		return nil, false, nil
	}
	out, err := p.run(ctx, "network", "inspect", "--format", "json", name)
	if err != nil {
		return nil, true, err
	}
	labels, err := ParseNetworkLabels(out)
	if err != nil {
		return nil, true, err
	}
	if labels == nil {
		labels = map[string]string{}
	}
	return labels, true, nil
}

// RemoveNetwork removes the network; already gone is success.
func (p *Podman) RemoveNetwork(ctx context.Context, name string) error {
	if ok, err := p.exists(ctx, "network", name); err != nil {
		return err
	} else if !ok {
		return nil
	}
	// Never --force: it would remove any container still attached, ours or
	// not. The instance's own containers are gone by now; anything else
	// attached is foreign and must make the removal fail, named.
	_, err := p.run(ctx, "network", "rm", name)
	return err
}

// CreateArgs renders the `podman create` argument list for a spec — the
// container posture is fixed here: no new privileges, all capabilities
// dropped, published ports bound to loopback only (threat model B4/B5).
func CreateArgs(spec ContainerSpec) []string {
	args := []string{"create", "--name", spec.Name}
	if spec.Network != "" {
		args = append(args, "--network", spec.Network)
	}
	networks := append([]string(nil), spec.Networks...)
	sort.Strings(networks)
	for _, n := range networks {
		args = append(args, "--network", n)
	}
	if spec.Alias != "" {
		args = append(args, "--network-alias", spec.Alias)
	}
	if spec.Hostname != "" {
		args = append(args, "--hostname", spec.Hostname)
	}
	for _, k := range sortedLabelKeys(spec.Labels) {
		args = append(args, "--label", k+"="+spec.Labels[k])
	}
	if spec.EnvFile != "" {
		args = append(args, "--env-file", spec.EnvFile)
	}
	if len(spec.Entrypoint) > 0 {
		ep, _ := json.Marshal(spec.Entrypoint)
		args = append(args, "--entrypoint", string(ep))
	}
	ports := append([]int(nil), spec.Publish...)
	sort.Ints(ports)
	for _, port := range ports {
		args = append(args, "--publish", fmt.Sprintf("127.0.0.1::%d", port))
	}
	if spec.CPU != "" {
		args = append(args, "--cpus", cpuValue(spec.CPU))
	}
	if spec.Memory != "" {
		args = append(args, "--memory", memoryValue(spec.Memory))
	}
	args = append(args, "--security-opt", "no-new-privileges", "--cap-drop", "ALL")
	args = append(args, spec.Image)
	args = append(args, spec.Command...)
	return args
}

// Create creates the container unless one of that name exists, and copies
// the spec's files into it before it is ever started.
func (p *Podman) Create(ctx context.Context, spec ContainerSpec) (string, error) {
	digest, err := spec.Digest()
	if err != nil {
		return "", err
	}
	st, err := p.Inspect(ctx, spec.Name)
	if err != nil {
		return "", err
	}
	if st != nil {
		if err := Owned(st.Labels, spec); err != nil {
			return "", err
		}
		if st.Labels[LabelSpec] == digest {
			if st.Running || !st.StartedAt.IsZero() {
				return st.ID, nil
			}
			// Created but never started: it may stand from an attempt that
			// ended between create and copy (a crash, an expired context).
			// The files are copied again — idempotent, and the digest
			// vouches for their content — so an incomplete container is
			// never adopted as complete.
			if err := p.copyIn(ctx, st.ID, spec.Files); err != nil {
				return "", errors.Join(err, p.removeIncomplete(st.ID, spec.Name))
			}
			return st.ID, nil
		}
		// Ours, but created from a different spec (the author changed env,
		// command, ports…): replace it rather than resume the stale one —
		// by the id the inspection saw, never by the name (a container that took the name meanwhile stands).
		if err := p.Remove(ctx, st.ID); err != nil {
			return "", err
		}
	}
	spec = withSpecLabel(spec, digest)
	out, err := p.run(ctx, CreateArgs(spec)...)
	if err != nil {
		return "", err
	}
	// From the create on, the container is addressed by the id create
	// answered — the copy-in, the removal of an incomplete one, and the
	// engine's start by the id it records — never by the name, which
	// another process may reuse after removing this container: a
	// replacement would otherwise receive the rendered files.
	// Without an id from create, the container under the name
	// is used only if it is this very spec's.
	id := createdID(out)
	if id == "" {
		st, ierr := p.Inspect(ctx, spec.Name)
		switch {
		case ierr != nil:
			return "", ierr
		case st == nil || Owned(st.Labels, spec) != nil || st.Labels[LabelSpec] != digest:
			return "", fmt.Errorf("create %s: podman answered no id and the container under the name is not this spec's", spec.Name)
		}
		id = st.ID
	}
	if err := p.copyIn(ctx, id, spec.Files); err != nil {
		// The files are part of the digest: a container standing without
		// them must not be adopted as complete by the next attempt. It goes
		// with the failure — removed under its own context, or named if
		// the removal fails; the retry creates it again (or copies again).
		return "", errors.Join(err, p.removeIncomplete(id, spec.Name))
	}
	return id, nil
}

// removeIncomplete removes a container whose files did not all arrive,
// under its own bounded context — the caller's may be what ended the copy.
// A failure is a CleanupError naming what
// remains; a remaining container is still never adopted as complete
// (Create copies the files again into one it finds never started).
func (p *Podman) removeIncomplete(id, name string) error {
	rctx, cancel := context.WithTimeout(context.Background(), cleanupBudget)
	defer cancel()
	// By the id, never the name (round 47); the error names the container
	// for the operator.
	if _, err := p.run(rctx, "rm", "--force", "--volumes", id); err != nil {
		return &CleanupError{Container: name, Err: err}
	}
	return nil
}

// copyIn places files into a created container's own storage with
// `podman cp` (threat model B4: no host bind mounts — the file lives and
// dies with the container). Each file is staged under a private
// directory with its mode, then copied to its path; when the path's
// parent does not exist in the image, the copy moves one level up and
// copies the directory (podman creates a destination directory that does
// not exist, and `/.` copies a directory's contents rather than the
// directory itself into one that does) until an ancestor exists — `/`
// always does.
func (p *Podman) copyIn(ctx context.Context, container string, files []FileSpec) error {
	if len(files) == 0 {
		return nil
	}
	stage, err := os.MkdirTemp("", "podaro-files-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for _, f := range files {
		if err := ValidateFilePath(f.Path); err != nil {
			return err
		}
		local := filepath.Join(stage, filepath.FromSlash(f.Path))
		// Belt and braces: the joined path stays beneath the staging
		// directory, or nothing is written.
		if !strings.HasPrefix(local, stage+string(filepath.Separator)) {
			return fmt.Errorf("file %q: staging path %s escapes %s", f.Path, local, stage)
		}
		if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
			return err
		}
		mode := f.Mode
		if mode == 0 {
			mode = 0o644
		}
		if err := os.WriteFile(local, f.Content, mode); err != nil {
			return err
		}
		if err := os.Chmod(local, mode); err != nil {
			return err
		}
	}
	// Directories staged for the walk up get a sane mode: they may become
	// the container's when the copy creates them.
	_ = filepath.WalkDir(stage, func(pth string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() && pth != stage {
			_ = os.Chmod(pth, 0o755)
		}
		return nil
	})
	for _, f := range files {
		target := path.Clean(f.Path)
		for {
			src := filepath.Join(stage, filepath.FromSlash(target))
			if target != f.Path {
				src += string(filepath.Separator) + "."
			}
			_, err := p.run(ctx, "cp", src, container+":"+target)
			if err == nil {
				break
			}
			parent := path.Dir(target)
			if parent == target || !destinationMissing(err) {
				return fmt.Errorf("copy %s into %s: %w", f.Path, container, err)
			}
			target = parent
		}
	}
	return nil
}

// destinationMissing recognizes podman cp's refusal of a destination
// whose parent does not exist in the container.
func destinationMissing(err error) bool {
	var ce *CommandError
	if !errors.As(err, &ce) {
		return false
	}
	msg := strings.ToLower(ce.Stderr)
	return strings.Contains(msg, "no such file or directory") || strings.Contains(msg, "could not be found") || strings.Contains(msg, "does not exist")
}

// Start starts a created container; already running is success.
func (p *Podman) Start(ctx context.Context, name string) error {
	_, err := p.run(ctx, "start", name)
	return err
}

// Stop stops a running container within timeout.
func (p *Podman) Stop(ctx context.Context, name string, timeout time.Duration) error {
	secs := int(timeout / time.Second)
	if secs < 1 {
		secs = 1
	}
	_, err := p.run(ctx, "stop", "--time", strconv.Itoa(secs), name)
	return err
}

// Remove force-removes a container; already gone is success.
func (p *Podman) Remove(ctx context.Context, name string) error {
	// An uncertain inspection (storage or daemon trouble, exit 125) never
	// becomes a forced removal: only an affirmative absence is success,
	// only an affirmative presence is removed.
	st, err := p.Inspect(ctx, name)
	if err != nil {
		return err
	}
	if st == nil {
		return nil
	}
	// --volumes: an image's own anonymous volumes (a VOLUME in its
	// Containerfile) carry no instance label, so the destroy sweep could
	// never find them; they leave with the container that made them.
	return p.rm(ctx, name)
}

// rm is `podman rm --force --volumes`, retried once when podman could not
// signal its own rootless network helper: Podman 5.7 with pasta refused
// with "kill network process: permission denied" on a first destroy and
// removed the container on the next (acceptance log 0002, deviation 2).
// One retry after a moment; the second answer is the one reported, and
// any other failure is reported at once.
func (p *Podman) rm(ctx context.Context, name string) error {
	_, err := p.run(ctx, "rm", "--force", "--volumes", name)
	if err == nil || !netnsKillDenied(err) {
		return err
	}
	select {
	case <-ctx.Done():
		return err
	case <-time.After(time.Second):
	}
	_, err = p.run(ctx, "rm", "--force", "--volumes", name)
	return err
}

// netnsKillDenied recognises podman's rootless network cleanup refusing
// to signal its helper — the one removal failure a retry is known to clear.
func netnsKillDenied(err error) bool {
	var ce *CommandError
	return errors.As(err, &ce) && strings.Contains(ce.Stderr, "kill network process") && strings.Contains(ce.Stderr, "permission denied")
}

// podmanInspect is the subset of `podman inspect --format json` we read.
type podmanInspect struct {
	ID        string `json:"Id"`
	ImageName string `json:"ImageName"`
	Config    struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Running   bool   `json:"Running"`
		ExitCode  int    `json:"ExitCode"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

// withSpecLabel returns a copy of spec carrying the digest label.
func withSpecLabel(spec ContainerSpec, digest string) ContainerSpec {
	labels := map[string]string{}
	for k, v := range spec.Labels {
		labels[k] = v
	}
	labels[LabelSpec] = digest
	spec.Labels = labels
	return spec
}

// ParseNetworkLabels reads `podman network inspect --format json`.
func ParseNetworkLabels(out []byte) (map[string]string, error) {
	var docs []struct {
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(out, &docs); err != nil {
		return nil, fmt.Errorf("podman network inspect: %w", err)
	}
	if len(docs) == 0 {
		return nil, nil
	}
	return docs[0].Labels, nil
}

// Inspect returns nil, nil for an absent container.
func (p *Podman) Inspect(ctx context.Context, name string) (*ContainerState, error) {
	if ok, err := p.exists(ctx, "container", name); err != nil {
		return nil, err
	} else if !ok {
		return nil, nil
	}
	out, err := p.run(ctx, "inspect", "--type", "container", "--format", "json", name)
	if err != nil {
		return nil, err
	}
	return ParseInspect(out)
}

// ParseInspect parses `podman inspect --format json` output for one
// container.
func ParseInspect(out []byte) (*ContainerState, error) {
	var docs []podmanInspect
	if err := json.Unmarshal(out, &docs); err != nil {
		return nil, fmt.Errorf("podman inspect: %w", err)
	}
	if len(docs) == 0 {
		return nil, nil
	}
	d := docs[0]
	st := &ContainerState{ID: d.ID, Running: d.State.Running, ExitCode: d.State.ExitCode, Ports: map[int]int{}, Labels: d.Config.Labels, Image: d.ImageName}
	if t, err := time.Parse(time.RFC3339Nano, d.State.StartedAt); err == nil {
		st.StartedAt = t
	}
	for key, bindings := range d.NetworkSettings.Ports {
		portStr, _, _ := strings.Cut(key, "/")
		cport, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		for _, b := range bindings {
			if hp, err := strconv.Atoi(b.HostPort); err == nil {
				st.Ports[cport] = hp
				break
			}
		}
	}
	return st, nil
}

// Objects lists containers, networks, volumes, and run secrets labeled or
// named for the instance — the destroy checklist and the "leaves nothing"
// proof.
func (p *Podman) Objects(ctx context.Context, instance string) (Objects, error) {
	filter := "label=" + LabelInstance + "=" + instance
	var o Objects
	out, err := p.run(ctx, "ps", "--all", "--filter", filter, "--format", "json")
	if err != nil {
		return o, err
	}
	var containers []struct {
		Names []string `json:"Names"`
	}
	if err := json.Unmarshal(out, &containers); err != nil {
		return o, fmt.Errorf("podman ps: %w", err)
	}
	for _, c := range containers {
		o.Containers = append(o.Containers, c.Names...)
	}
	out, err = p.run(ctx, "network", "ls", "--filter", filter, "--format", "json")
	if err != nil {
		return o, err
	}
	var networks []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(out, &networks); err != nil {
		return o, fmt.Errorf("podman network ls: %w", err)
	}
	for _, n := range networks {
		o.Networks = append(o.Networks, n.Name)
	}
	out, err = p.run(ctx, "volume", "ls", "--filter", filter, "--format", "json")
	if err != nil {
		return o, err
	}
	var volumes []struct {
		Name string `json:"Name"`
	}
	if err := json.Unmarshal(out, &volumes); err != nil {
		return o, fmt.Errorf("podman volume ls: %w", err)
	}
	for _, v := range volumes {
		o.Volumes = append(o.Volumes, v.Name)
	}
	// Secret objects carry no filterable label on every Podman this
	// release supports (Manual §3: ≥ 4.4), so they are named for the
	// instance instead — the instance name whole, ended by an underscore
	// no instance name carries, so no other instance's prefix matches,
	// hyphenated names included — and listed whole.
	out, err = p.run(ctx, "secret", "ls", "--format", "json")
	if err != nil {
		return o, err
	}
	names, err := ParseSecretNames(out)
	if err != nil {
		return o, err
	}
	prefix := SecretPrefix(instance)
	for _, n := range names {
		if strings.HasPrefix(n, prefix) {
			o.Secrets = append(o.Secrets, n)
		}
	}
	sort.Strings(o.Containers)
	sort.Strings(o.Networks)
	sort.Strings(o.Volumes)
	sort.Strings(o.Secrets)
	return o, nil
}

// ParseSecretNames reads `podman secret ls --format json`.
func ParseSecretNames(out []byte) ([]string, error) {
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil
	}
	var docs []struct {
		Name string `json:"Name"`
		Spec struct {
			Name string `json:"Name"`
		} `json:"Spec"`
	}
	if err := json.Unmarshal(out, &docs); err != nil {
		return nil, fmt.Errorf("podman secret ls: %w", err)
	}
	var names []string
	for _, d := range docs {
		n := d.Name
		if n == "" {
			n = d.Spec.Name
		}
		if n != "" {
			names = append(names, n)
		}
	}
	return names, nil
}

// SecretPrefix is the name prefix of every run secret of an instance:
// `pdrs-<instance>_`. The instance name is carried whole — a hash of it
// can collide, and a 32-bit one did for two admitted names
// — and the underscore that ends it, which no
// instance name can carry, keeps `lab` apart from `lab-2`: a prefix
// match is exact per instance.
func SecretPrefix(instance string) string {
	return "pdrs-" + instance + "_"
}

// RemoveSecret removes a run secret object; already gone is success.
func (p *Podman) RemoveSecret(ctx context.Context, name string) error {
	_, err := p.run(ctx, "secret", "rm", name)
	if err != nil && IsNotFound(err) {
		return nil
	}
	return err
}

// Defaults of the resource wall (Spec 0002 §2) as podman values.
const (
	defaultRunCPU   = "500m"
	defaultRunMem   = "256MiB"
	defaultRunPids  = 128
	defaultRunTmpfs = "64m"
	// DefaultMaxStdout and DefaultMaxStderr are Spec 0002's caps on the
	// contract stream and the diagnostics: 64 KiB each (the implemented wall equals the documented one).
	DefaultMaxStdout = 64 << 10
	DefaultMaxStderr = 64 << 10
)

// RunCreateArgs renders `podman create` for a one-shot run — the five
// walls as flags: the given (internal) network only; read-only rootfs with
// a bounded /tmp tmpfs; all capabilities dropped and no new privileges;
// pids, cpu, and memory capped; granted secrets mounted as 0400 files
// owned by the container's user; stdin kept open for the contract input.
// secretNames maps each granted secret's name to the podman secret object
// holding its value.
func RunCreateArgs(spec RunSpec, secretNames map[string]string) []string {
	args := []string{"create", "--name", spec.Name, "--interactive"}
	if spec.Network != "" {
		args = append(args, "--network", spec.Network)
	}
	for _, k := range sortedLabelKeys(spec.Labels) {
		args = append(args, "--label", k+"="+spec.Labels[k])
	}
	if spec.EnvFile != "" {
		args = append(args, "--env-file", spec.EnvFile)
	}
	if len(spec.Entrypoint) > 0 {
		ep, _ := json.Marshal(spec.Entrypoint)
		args = append(args, "--entrypoint", string(ep))
	}
	tmpfs := spec.TmpfsSize
	if tmpfs == "" {
		tmpfs = defaultRunTmpfs
	}
	args = append(args, "--read-only", "--tmpfs", "/tmp:rw,size="+tmpfs+",mode=1777")
	args = append(args, "--security-opt", "no-new-privileges", "--cap-drop", "ALL")
	pids := spec.Pids
	if pids <= 0 {
		pids = defaultRunPids
	}
	args = append(args, "--pids-limit", strconv.Itoa(pids))
	cpu := spec.CPU
	if cpu == "" {
		cpu = defaultRunCPU
	}
	mem := spec.Memory
	if mem == "" {
		mem = defaultRunMem
	}
	args = append(args, "--cpus", cpuValue(cpu), "--memory", memoryValue(mem))
	secrets := append([]SecretFile(nil), spec.Secrets...)
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].Name < secrets[j].Name })
	for _, s := range secrets {
		args = append(args, "--secret", fmt.Sprintf("source=%s,type=mount,target=%s/%s,mode=0400,uid=%d,gid=%d", secretNames[s.Name], SecretsMount, s.Name, spec.UID, spec.GID))
	}
	args = append(args, spec.Image)
	args = append(args, spec.Command...)
	return args
}

// Run executes a one-shot container: secrets become podman secret objects
// for the run's duration, the container is created with the walls, files
// are copied in, it is started attached with the input on stdin, and it is
// removed whatever happened — on a timeout, killed first.
func (p *Podman) Run(ctx context.Context, spec RunSpec) (*RunResult, error) {
	if spec.Name == "" {
		return nil, errors.New("run: a container name is required")
	}
	secretNames := map[string]string{}
	var created []string
	// containerCreated: the container under spec.Name is this run's to
	// remove. A create podman refused — the name in use first of all —
	// made nothing, and what stands under the name then is another's:
	// a helper another process won between the caller's ownership check
	// and this create is left standing.
	// createCutOff: the CLI was killed before it answered, so the
	// container may or may not exist and may or may not be this run's —
	// the cleanup inspects it and removes it only under this run's own
	// id, stamped as a label on the create.
	containerCreated, createCutOff := false, false
	// containerID: the id podman create answers, the one the cleanup
	// removes — never the name, which another process may have reused
	// after removing this container while it ran.
	containerID := ""
	var b [8]byte
	if _, err := io.ReadFull(randReader, b[:]); err != nil {
		// Without an id of its own the cleanup could trust nothing: a
		// run that cannot draw one does not start.
		return nil, fmt.Errorf("run %s: mark the run: %w", spec.Name, err)
	}
	runID := hex.EncodeToString(b[:])
	labels := make(map[string]string, len(spec.Labels)+1)
	for k, v := range spec.Labels {
		labels[k] = v
	}
	labels[LabelRunID] = runID
	spec.Labels = labels
	// cleanup removes the container and the run's secret objects; a
	// removal that fails is reported, never swallowed — a run whose
	// container or secrets may remain is not a run that finished cleanly
	// (Spec 0002 §3: fresh per run, secrets for the run's duration).
	cleanup := func() error {
		rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var errs []error
		remove := func(ref string) {
			// --volumes: an image's anonymous volumes (a VOLUME in its
			// Containerfile) carry no label the destroy sweep could find;
			// they leave with the container.
			if _, err := p.run(rctx, "rm", "--force", "--ignore", "--volumes", ref); err != nil {
				errs = append(errs, fmt.Errorf("remove container %s: %w", spec.Name, err))
			}
		}
		switch {
		case containerCreated && containerID != "":
			// By the id podman create answered, never by the name.
			remove(containerID)
		case containerCreated || createCutOff:
			// No id in hand — the create's answer was cut off, or it
			// printed none: under the cleanup's own context, since the
			// run's has ended, what stands under the name is removed only
			// if it is this run's — its id label says so — and by the id
			// the inspection saw; nothing there, or another's container,
			// is left as found.
			st, err := p.Inspect(rctx, spec.Name)
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("inspect container %s before its removal: %w", spec.Name, err))
			case st != nil && st.Labels[LabelRunID] == runID:
				remove(st.ID)
			}
		}
		for _, n := range created {
			// Idempotent: a name tracked for a create the budget cut off may
			// never have come to be; already gone is success.
			if err := p.RemoveSecret(rctx, n); err != nil {
				errs = append(errs, fmt.Errorf("remove secret object %s: %w", n, err))
			}
		}
		return errors.Join(errs...)
	}
	// The run's budget bounds everything from here — the secret objects,
	// the create, the copy-in, and the attached process — so a stalled
	// setup step is a timeout too, never an open-ended hang.
	// A caller's deadline bounds it as well.
	rctx := ctx
	var cancel context.CancelFunc
	if spec.Timeout > 0 {
		rctx, cancel = context.WithTimeout(ctx, spec.Timeout)
		defer cancel()
	}
	res := &RunResult{Started: time.Now().UTC()}
	// setupFailed turns a setup step's failure into the run's outcome
	// after the cleanup: the budget's deadline is the timeout result
	// (PDR-E503 at the engine); anything else is the error.
	setupFailed := func(err error) (*RunResult, error) {
		cerr := cleanup()
		if errors.Is(rctx.Err(), context.DeadlineExceeded) {
			res.Finished = time.Now().UTC()
			res.TimedOut, res.ExitCode = true, -1
			if cerr != nil {
				return nil, fmt.Errorf("one-shot run %s timed out during its setup and its cleanup failed — the container or its secret objects may remain: %w", spec.Name, cerr)
			}
			return res, nil
		}
		return nil, errors.Join(err, cerr)
	}
	for _, s := range spec.Secrets {
		name := runSecretName(spec, runID, s.Name)
		if _, err := p.run(rctx, "secret", "create", name, s.Source); err != nil {
			// A create Podman answered with an error made nothing — the
			// name in use first of all — and nothing under that name is
			// this run's to remove; a create the budget cut off may have
			// committed the object before the CLI was killed, and the name
			// is the run's own (its id ends it), so the cleanup takes it
			// back.
			if rctx.Err() != nil {
				created = append(created, name)
			}
			return setupFailed(err)
		}
		created = append(created, name)
		secretNames[s.Name] = name
	}
	out, err := p.run(rctx, RunCreateArgs(spec, secretNames)...)
	if err != nil {
		// A create the budget cut off may have committed the container
		// before the CLI was killed — or another process may hold the
		// name by now: the cleanup inspects before it removes (round 42).
		createCutOff = rctx.Err() != nil
		return setupFailed(err)
	}
	containerCreated, containerID = true, createdID(out)
	// Everything after the create addresses the container by its id —
	// the copy-in, the start, the cleanup — never by the name, which
	// another process may reuse after removing this container: a
	// replacement would otherwise receive the rendered files and run as
	// the verdict. Without an id from
	// create, the container under the name is used only if it carries
	// this run's own id.
	if containerID == "" {
		st, ierr := p.Inspect(rctx, spec.Name)
		switch {
		case ierr != nil:
			return setupFailed(fmt.Errorf("inspect %s after its create: %w", spec.Name, ierr))
		case st == nil || st.Labels[LabelRunID] != runID:
			return setupFailed(fmt.Errorf("run %s: create answered no id and the container under the run's name is not this run's", spec.Name))
		}
		containerID = st.ID
	}
	if err := p.copyIn(rctx, containerID, spec.Files); err != nil {
		return setupFailed(err)
	}
	maxOut, maxErr := spec.MaxStdout, spec.MaxStderr
	if maxOut <= 0 {
		maxOut = DefaultMaxStdout
	}
	if maxErr <= 0 {
		maxErr = DefaultMaxStderr
	}
	a, err := p.attach(rctx, spec.Stdin, maxOut, maxErr, "start", "--attach", "--interactive", containerID)
	res.Finished = time.Now().UTC()
	res.Stdout, res.Stderr, res.ExitCode = a.stdout, a.stderr, a.code
	res.StdoutTruncated, res.StderrTruncated = a.outCut, a.errCut
	if errors.Is(rctx.Err(), context.DeadlineExceeded) {
		// A deadline is a timeout wherever it came from: the run's own
		// budget or the caller's (a checkpoint's timeout bounds both, and
		// they expire together). A cancellation is not.
		res.TimedOut = true
		res.ExitCode = -1
	}
	if cerr := cleanup(); cerr != nil {
		return nil, fmt.Errorf("one-shot run %s finished but its cleanup failed — the container or its secret objects may remain: %w", spec.Name, cerr)
	}
	if err != nil && !res.TimedOut {
		return nil, err
	}
	return res, nil
}

// createdID reads the id `podman create` prints: the last word of its
// stdout, a hex id of at least twelve characters. Anything else is no
// id in hand — the cleanup then inspects the name and removes only this
// run's own container by the id the inspection saw — so a stray line on
// stdout never hands `rm --ignore` a name that matches nothing and
// leaves the real container behind.
func createdID(out []byte) string {
	words := strings.Fields(string(out))
	if len(words) == 0 {
		return ""
	}
	id := words[len(words)-1]
	if len(id) < 12 {
		return ""
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return ""
		}
	}
	return id
}

// runSecretName names the podman secret object holding one granted
// secret for one run: `pdrs-<instance>_<run>_<secret>_<run id>` — the
// instance prefix, the run's container name less the instance's own
// prefix (`run-<id>` for an exec run), the secret's name, and the run's
// own id. Every field is carried whole and ended by an underscore no
// instance or secret name can carry, so no instance's prefix covers
// another's; the run id ends the name so
// no two runs' objects share one even under the same instance and
// checkpoint — a create the budget cut off is then removed under a name
// no other run can hold. Podman admits
// `[a-zA-Z0-9][a-zA-Z0-9_.-]*` up to 253 characters; the longest name
// Podaro can form stays well inside.
func runSecretName(spec RunSpec, runID, secret string) string {
	instance := spec.Labels[LabelInstance]
	return SecretPrefix(instance) + strings.TrimPrefix(spec.Name, "pdr-"+instance+"-") + "_" + secret + "_" + runID
}

// ImageUser reports the user a pulled image runs as: `podman image
// inspect`'s Config.User, resolved to numeric ids — through the image's
// own /etc/passwd when USER names a user, read out of a created (never
// started) container with `podman cp`, so nothing of the image runs to
// find out.
func (p *Podman) ImageUser(ctx context.Context, image string) (ImageUser, error) {
	out, err := p.run(ctx, "image", "inspect", "--format", "json", image)
	if err != nil {
		return ImageUser{}, err
	}
	raw, err := ParseImageUser(out)
	if err != nil {
		return ImageUser{}, err
	}
	u := ImageUser{Raw: raw}
	if raw == "" {
		return u, nil
	}
	user, group, _ := strings.Cut(raw, ":")
	uid, uidNumeric := atoiOK(user)
	gid, gidNumeric := atoiOK(group)
	if uidNumeric {
		u.UID, u.Resolved = uid, true
		if gidNumeric {
			u.GID = gid
		}
		return u, nil
	}
	passwd, err := p.imageFile(ctx, image, "/etc/passwd")
	if err != nil {
		var ce *CleanupError
		if errors.As(err, &ce) {
			// Whatever the read did, a container remains: that is an
			// error the operator sees, not an unresolved user.
			return ImageUser{}, err
		}
		return u, nil // unresolved: the caller refuses rather than guesses
	}
	ruid, rgid, ok := lookupPasswd(passwd, user)
	if !ok {
		return u, nil
	}
	u.UID, u.GID, u.Resolved = ruid, rgid, true
	if gidNumeric {
		u.GID = gid
	}
	return u, nil
}

// ParseImageUser reads Config.User from `podman image inspect`.
func ParseImageUser(out []byte) (string, error) {
	var docs []struct {
		Config struct {
			User string `json:"User"`
		} `json:"Config"`
	}
	if err := json.Unmarshal(out, &docs); err != nil {
		return "", fmt.Errorf("podman image inspect: %w", err)
	}
	if len(docs) == 0 {
		return "", errors.New("podman image inspect: no image")
	}
	return strings.TrimSpace(docs[0].Config.User), nil
}

// cleanupBudget bounds the removal of a container the runtime made and
// must take back on its own — an inspection container, one whose files
// did not all arrive. The removal runs under its own context: a caller's
// deadline that ended the work must not also end the cleanup and leave the
// container behind.
const cleanupBudget = 30 * time.Second

// CleanupError reports a container that did its work but could not be
// removed: what may remain, named, for the operator.
type CleanupError struct {
	Container string
	Err       error
}

func (e *CleanupError) Error() string {
	return fmt.Sprintf("container %s finished its work but could not be removed — it may remain: %v", e.Container, e.Err)
}

func (e *CleanupError) Unwrap() error { return e.Err }

// imageFile reads one file out of an image without running it: a
// container is created, the file streamed out as a tar, and the container
// removed. A removal that fails is reported (CleanupError), joined with
// any read failure.
func (p *Podman) imageFile(ctx context.Context, image, file string) (content []byte, err error) {
	var b [6]byte
	if _, rerr := io.ReadFull(randReader, b[:]); rerr != nil {
		// Without an identity of its own the inspection could trust
		// nothing — two inspections under the same failure would wear the
		// same name and tag, each free to read or remove the other's
		// container — so one that cannot draw its tag does not start, as
		// a run that cannot draw its id does not.
		return nil, fmt.Errorf("inspect image %s: mark the inspection: %w", image, rerr)
	}
	tag := hex.EncodeToString(b[:])
	name := "pdr-inspect-" + tag
	// The container is addressed by the id create answered — the read and
	// the removal — never by the name, which another process may reuse
	// after removing it: a replacement's /etc/passwd would otherwise
	// vouch for the image's user. Without an id from
	// create, the container under the name is used only if it carries
	// this inspection's own tag.
	created, cerr := p.run(ctx, "create", "--name", name, "--label", LabelRunID+"="+tag, image)
	if cerr != nil {
		if ctx.Err() != nil {
			// A create the context cut off may have committed the
			// container before the CLI was killed, and nothing else could
			// ever find it — it carries no instance label. Under the
			// cleanup's own context, what stands under the name is removed
			// only if it carries this inspection's tag, by the id the
			// inspection saw (the one-shot run's cut-off rule, here too).
			rctx, cancel := context.WithTimeout(context.Background(), cleanupBudget)
			defer cancel()
			st, ierr := p.Inspect(rctx, name)
			switch {
			case ierr != nil:
				return nil, errors.Join(cerr, &CleanupError{Container: name, Err: ierr})
			case st != nil && st.Labels[LabelRunID] == tag:
				if _, rerr := p.run(rctx, "rm", "--force", "--ignore", "--volumes", st.ID); rerr != nil {
					return nil, errors.Join(cerr, &CleanupError{Container: name, Err: rerr})
				}
			}
		}
		return nil, cerr
	}
	ref := createdID(created)
	if ref == "" {
		// Create answered no id: the container is found under the name —
		// under the cleanup's own context, since the caller's may have
		// ended while create ran, and an inspection that failed for that
		// reason alone would leave the tagged container, which nothing
		// else can find, behind for good — and used
		// only if it carries this inspection's tag.
		ictx, icancel := context.WithTimeout(context.Background(), cleanupBudget)
		st, ierr := p.Inspect(ictx, name)
		icancel()
		switch {
		case ierr != nil:
			return nil, errors.Join(fmt.Errorf("inspect image %s: create answered no id and the container under the inspection's name could not be inspected", image), &CleanupError{Container: name, Err: ierr})
		case st == nil || st.Labels[LabelRunID] != tag:
			return nil, fmt.Errorf("inspect image %s: create answered no id and the container under the inspection's name is not its own", image)
		}
		ref = st.ID
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.Background(), cleanupBudget)
		defer cancel()
		if _, rerr := p.run(rctx, "rm", "--force", "--ignore", "--volumes", ref); rerr != nil {
			err = errors.Join(err, &CleanupError{Container: name, Err: rerr})
		}
	}()
	out, err := p.run(ctx, "cp", ref+":"+file, "-")
	if err != nil {
		return nil, err
	}
	return ExtractTarFile(out, path.Base(file))
}

// ExtractTarFile returns the content of the first regular file named base
// in a tar stream (`podman cp <ctr>:<file> -` writes one).
func ExtractTarFile(stream []byte, base string) ([]byte, error) {
	tr := tar.NewReader(bytes.NewReader(stream))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("%s not in the archive", base)
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeReg && path.Base(hdr.Name) == base {
			return io.ReadAll(io.LimitReader(tr, 1<<20))
		}
	}
}

// lookupPasswd finds a user's uid and gid in passwd(5) content.
func lookupPasswd(passwd []byte, user string) (uid, gid int, ok bool) {
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 4 || fields[0] != user {
			continue
		}
		u, err1 := strconv.Atoi(fields[2])
		g, err2 := strconv.Atoi(fields[3])
		if err1 != nil || err2 != nil {
			return 0, 0, false
		}
		return u, g, true
	}
	return 0, 0, false
}

func atoiOK(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// randReader is the entropy source of temporary names (a seam for tests).
var randReader io.Reader = cryptoRand{}

// IsNotFound reports whether a podman error names a missing object.
func IsNotFound(err error) bool {
	var ce *CommandError
	if errors.As(err, &ce) {
		return strings.Contains(ce.Stderr, "no such") || strings.Contains(ce.Stderr, "not found")
	}
	return errors.Is(err, ErrNotFound)
}

func sortedLabelKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// cpuValue converts module envelopes ("2", "500m") to podman --cpus.
func cpuValue(v string) string {
	if strings.HasSuffix(v, "m") {
		if n, err := strconv.Atoi(strings.TrimSuffix(v, "m")); err == nil {
			return strconv.FormatFloat(float64(n)/1000, 'f', -1, 64)
		}
	}
	return v
}

// memoryValue converts "4GiB"/"512MiB" to podman's "4g"/"512m".
func memoryValue(v string) string {
	switch {
	case strings.HasSuffix(v, "GiB"):
		return strings.TrimSuffix(v, "GiB") + "g"
	case strings.HasSuffix(v, "MiB"):
		return strings.TrimSuffix(v, "MiB") + "m"
	}
	return v
}
