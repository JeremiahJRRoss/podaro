// SPDX-License-Identifier: AGPL-3.0-only

// Package runtime is the engine's container runtime seam (plan S4): the
// operations `up`, reconcile, and `destroy` need, behind one interface
// with two implementations — rootless Podman driven at arm's length
// through its CLI (roadmap §9 Engine row; the licensing rule: GPL-family tools are
// subprocesses, never imports), and a fake whose world persists on disk
// and whose "containers" answer real HTTP on loopback, so the job engine's
// resumption and reconcile logic is exercised end to end where Podman is
// absent. Plan S6 adds the one-shot runs the create path and the exec
// extension contract need (init helpers, adapters, generators).
package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// Labels the engine stamps on every object it creates: everything is
// namespaced by instance (invariant 5), so destroy can find all of it and
// nothing is ever a fixed name.
const (
	LabelInstance = "dev.podaro/instance"
	LabelService  = "dev.podaro/service"
	LabelTemplate = "dev.podaro/template"
	LabelManaged  = "dev.podaro/managed"
	// LabelSpec carries the digest of the effective spec a container was
	// created from, so an idempotent Create can tell "already as asked"
	// from "ours, but stale" (recreate) — see ContainerSpec.Digest.
	LabelSpec = "dev.podaro/spec"
	// LabelRun marks a one-shot container or the secret objects made for
	// it (Run): destroy sweeps whatever a crash left under it.
	LabelRun = "dev.podaro/run"
	// LabelRunID is one Run invocation's own mark on the container it
	// creates: a cleanup after a create the budget cut off removes what
	// stands under the run's name only if it carries this id, so a
	// container another process placed there meanwhile stands.
	LabelRunID = "dev.podaro/run-id"
)

// ErrNotFound reports an object the runtime does not hold.
var ErrNotFound = errors.New("not found")

// Info is what doctor and /system report about the runtime.
type Info struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Rootless bool   `json:"rootless"`
}

// FileSpec is one file placed into a container's own storage before it
// starts (plan S6: rendered module `config.files`, an init helper's
// request program). It is copied in — never bind-mounted from the host
// (threat model B4: no host bind mounts) — so it lives and dies with the
// container. Content may carry rendered secrets: it is hashed into the
// spec digest, never logged.
type FileSpec struct {
	Path    string
	Mode    fs.FileMode
	Content []byte
}

// ContainerSpec is one container to create. Image is always
// repository@sha256:… (digest-only pulls). Publish lists container ports to
// publish on 127.0.0.1 at ephemeral host ports — the only way a host
// process reaches a rootless instance network without joining it (threat
// model B4/B5: the engine stays off instance networks). EnvFile carries
// environment as a 0600 file so no value ever appears on a command line.
type ContainerSpec struct {
	Name    string
	Image   string
	Network string
	// Networks are further networks the container joins beside Network —
	// the instance's internal network, where extension and init containers
	// reach lab services and nothing else (Spec 0002 §2, the network wall).
	Networks []string
	Alias    string // in-network DNS name: the service name
	Labels   map[string]string
	EnvFile  string
	// Entrypoint replaces the image entrypoint; Command the image command
	// (spec 0003: module config.command / config.args; an inline service's
	// command is Command).
	Entrypoint []string
	Command    []string
	Publish    []int
	CPU        string
	Memory     string
	Hostname   string
	// Files are copied into the created container before it starts.
	Files []FileSpec
}

// ContainerState is what Inspect reports.
type ContainerState struct {
	ID        string
	Running   bool
	ExitCode  int
	StartedAt time.Time
	// Ports maps container port → host port on 127.0.0.1.
	Ports map[int]int
	// Labels and Image are the ownership facts: a container found under a
	// predictable name is adopted only when they match the spec (Owned).
	Labels map[string]string
	Image  string
}

// Owned reports whether an existing object may be treated as this
// instance's: it must carry the managed label and the same instance and
// service labels. Anything else under Podaro's name is someone else's —
// never started, never removed. Names are predictable
// (pdr-<instance>-<service>), so this check is what keeps idempotent
// Create and destroy honest. Whether an owned container still matches
// the requested spec is a separate question (Digest).
func Owned(labels map[string]string, spec ContainerSpec) error {
	if labels[LabelManaged] != "true" {
		return fmt.Errorf("%s exists but is not managed by podaro (no %s label): refusing to adopt it", spec.Name, LabelManaged)
	}
	for _, key := range []string{LabelInstance, LabelService} {
		if want := spec.Labels[key]; want != "" && labels[key] != want {
			return fmt.Errorf("%s exists but belongs to %s=%q, not %q: refusing to adopt it", spec.Name, key, labels[key], want)
		}
	}
	return nil
}

// fileDigest is what a file contributes to the spec digest: its path,
// mode, and the hash of its content — never the content itself.
type fileDigest struct {
	Path string
	Mode uint32
	Sum  string
}

// FileDigests canonicalizes a file set for hashing (sorted by path).
// ValidateFilePath accepts the container path of a file to copy in: an
// absolute, clean POSIX path (no `.` or `..` elements, no doubled or
// trailing slashes) below the root. Anything else is refused before a byte
// is staged, so the staging directory the path is joined to is never
// escaped and the copy lands where the manifest says (`/../../home/…` cleaned to a host path).
func ValidateFilePath(p string) error {
	switch {
	case p == "":
		return errors.New("file path is empty")
	case strings.ContainsRune(p, 0):
		return fmt.Errorf("file %q: contains a NUL byte", p)
	case !path.IsAbs(p):
		return fmt.Errorf("file %q: container paths are absolute", p)
	case path.Clean(p) != p:
		return fmt.Errorf("file %q: container paths are clean — no . or .. elements, no doubled or trailing slashes", p)
	case p == "/":
		return fmt.Errorf("file %q: a file path, not the root", p)
	}
	return nil
}

func FileDigests(files []FileSpec) []fileDigest {
	out := make([]fileDigest, 0, len(files))
	for _, f := range files {
		sum := sha256.Sum256(f.Content)
		out = append(out, fileDigest{Path: f.Path, Mode: uint32(f.Mode), Sum: hex.EncodeToString(sum[:])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Digest hashes everything that shapes the container — image, network
// identity, entrypoint and command, published ports, resources, the
// user labels, the env file's *content*, and the files copied in (path,
// mode, content hash) — so a retried create after the author changed any
// of it replaces the container instead of reusing a stale one. The spec
// label itself is excluded.
func (s ContainerSpec) Digest() (string, error) {
	labels := map[string]string{}
	for k, v := range s.Labels {
		if k != LabelSpec {
			labels[k] = v
		}
	}
	env := ""
	if s.EnvFile != "" {
		raw, err := os.ReadFile(s.EnvFile)
		if err != nil {
			return "", fmt.Errorf("env file for %s: %w", s.Name, err)
		}
		env = string(raw)
	}
	ports := append([]int(nil), s.Publish...)
	sort.Ints(ports)
	networks := append([]string(nil), s.Networks...)
	sort.Strings(networks)
	canon := struct {
		Image, Network, Alias, Hostname, CPU, Memory, Env string
		Networks, Entrypoint, Command                     []string
		Publish                                           []int
		Labels                                            map[string]string
		Files                                             []fileDigest `json:",omitempty"`
	}{s.Image, s.Network, s.Alias, s.Hostname, s.CPU, s.Memory, env, networks, s.Entrypoint, s.Command, ports, labels, FileDigests(s.Files)}
	raw, err := json.Marshal(canon)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// OwnedNetwork is Owned for networks: managed, and this instance's.
func OwnedNetwork(name string, labels, want map[string]string) error {
	if labels[LabelManaged] != "true" {
		return fmt.Errorf("network %s exists but is not managed by podaro: refusing to adopt it", name)
	}
	if w := want[LabelInstance]; w != "" && labels[LabelInstance] != w {
		return fmt.Errorf("network %s exists but belongs to instance %q, not %q: refusing to adopt it", name, labels[LabelInstance], w)
	}
	return nil
}

// Objects lists everything labeled with one instance.
type Objects struct {
	Containers []string `json:"containers"`
	Networks   []string `json:"networks"`
	Volumes    []string `json:"volumes"`
	// Secrets are the runtime's secret objects made for one-shot runs
	// (Run mounts granted secrets through them); a crash mid-run may leave
	// one, and destroy removes it.
	Secrets []string `json:"secrets,omitempty"`
}

// Empty reports whether nothing remains.
func (o Objects) Empty() bool {
	return len(o.Containers) == 0 && len(o.Networks) == 0 && len(o.Volumes) == 0 && len(o.Secrets) == 0
}

// SecretFile is one granted secret a one-shot run receives as a file
// (Spec 0002 §2, the secrets wall): mounted at Mount/<Name>, 0400, on a
// tmpfs — never on stdin, argv, or env. Source is the engine's 0600 file
// holding the value; the runtime reads it into its own secret object and
// removes that object when the run ends.
type SecretFile struct {
	Name   string
	Source string
}

// SecretsMount is where granted secrets appear inside an extension
// container (Spec 0002 §2).
const SecretsMount = "/run/podaro/secrets"

// RunSpec is a one-shot container (Spec 0002 §2: "every run is a fresh
// podman run --rm"): an extension adapter or generator, or a module's
// init helper. The five walls are fixed here and rendered by each runtime:
// the instance's internal network only (no egress); non-root (judged by
// the caller through ImageUser before the run), read-only rootfs, all
// capabilities dropped, /tmp a bounded tmpfs; CPU, memory, and pids
// capped; wall-clock bounded by Timeout; stdout and stderr captured
// separately (stdout is contract, stderr diagnostics).
type RunSpec struct {
	Name    string
	Image   string
	Network string
	Labels  map[string]string
	// Entrypoint replaces the image entrypoint when set; Command is the
	// argument list (the image's command when Entrypoint is empty).
	Entrypoint []string
	Command    []string
	// EnvFile carries the extension's declared env as a 0600 file.
	EnvFile string
	// Files are copied in before start (an init helper's request program).
	Files []FileSpec
	// Secrets are mounted at SecretsMount/<Name>, mode 0400, owned by the
	// container's user (UID/GID).
	Secrets  []SecretFile
	UID, GID int
	// Stdin is written to the container's stdin, then closed. The engine
	// never logs it (Spec 0002 §2, the honesty wall).
	Stdin []byte
	// Timeout bounds the run; on expiry the container is removed and the
	// result reports TimedOut.
	Timeout time.Duration
	// Resources: CPU as a module envelope ("500m", "2"), Memory as
	// "256MiB"/"1GiB", Pids a count, TmpfsSize podman's size ("64m").
	CPU       string
	Memory    string
	Pids      int
	TmpfsSize string
	// Limits on the captured streams; zero means the runtime default.
	MaxStdout, MaxStderr int
}

// RunResult is what a one-shot run produced. ExitCode is the container
// process's; a run the runtime could not even start is an error from Run,
// never a result.
type RunResult struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
	Started  time.Time
	Finished time.Time
	TimedOut bool
	// StdoutTruncated and StderrTruncated report a stream the cap cut
	// (Spec 0002 §2): what follows the cap is unknown, so a verdict read
	// from a cut stdout is no verdict.
	StdoutTruncated bool
	StderrTruncated bool
}

// cut keeps the first max bytes of a stream and reports whether anything
// was dropped; max <= 0 keeps everything.
func cut(b []byte, max int) ([]byte, bool) {
	if max > 0 && len(b) > max {
		return b[:max], true
	}
	return b, false
}

// ImageUser is the user an image runs as: the USER instruction as written
// (Raw; "" when absent) resolved to numeric ids. Resolved is false when a
// named user could not be looked up in the image — the caller refuses such
// an image rather than guess (Spec 0002 §2, the identity wall).
type ImageUser struct {
	Raw      string
	UID      int
	GID      int
	Resolved bool
}

// Root reports whether the image would run as uid 0: no USER, or one
// that resolves to 0.
func (u ImageUser) Root() bool { return u.Raw == "" || (u.Resolved && u.UID == 0) }

// Runtime is the operation set. Every call is idempotent where the verb
// allows: EnsureNetwork and Create return success when the object already
// exists as asked; Remove* succeed when the object is already gone. That
// is what makes a journaled job safe to resume from any step.
type Runtime interface {
	Info(ctx context.Context) (Info, error)
	Pull(ctx context.Context, image string) error
	// EnsureNetwork creates a bridge network once; internal networks have
	// no route out (Spec 0002 §2: extension containers reach lab services
	// and nothing else).
	EnsureNetwork(ctx context.Context, name string, labels map[string]string, internal bool) error
	// InspectNetwork reports a network's labels; exists=false when absent.
	InspectNetwork(ctx context.Context, name string) (labels map[string]string, exists bool, err error)
	RemoveNetwork(ctx context.Context, name string) error
	Create(ctx context.Context, spec ContainerSpec) (id string, err error)
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string, timeout time.Duration) error
	// Remove takes a name or an id, as podman does; already gone is
	// success. The engine removes a container it inspected by its id,
	// so a replacement under the same name is never removed.
	Remove(ctx context.Context, name string) error
	Inspect(ctx context.Context, name string) (*ContainerState, error)
	Objects(ctx context.Context, instance string) (Objects, error)
	// Run executes a one-shot container to completion (RunSpec) and
	// removes it; a timeout kills it and reports TimedOut.
	Run(ctx context.Context, spec RunSpec) (*RunResult, error)
	// ImageUser reports the user a pulled image runs as.
	ImageUser(ctx context.Context, image string) (ImageUser, error)
	// RemoveSecret removes a runtime secret object; already gone is
	// success (destroy's sweep of what a crashed Run left).
	RemoveSecret(ctx context.Context, name string) error
	// Logs opens a container's combined stdout and stderr (API §7). The
	// caller closes the reader; with Follow it stays open until the
	// context ends or the container stops. The engine filters what comes
	// back before any of it leaves — a product prints what it was
	// configured with, and it was configured with this lab's secrets.
	Logs(ctx context.Context, name string, opts LogOptions) (io.ReadCloser, error)
}

// ContainerReader is the read a process other than the engine may make of
// the runtime: which containers carry an instance's label and what state
// each is in — never a change to one. `system upgrade`'s preflight
// counts an unsupported instance's running containers through it before
// anything is replaced (INSTALL §6; the reconciliation plan's R3).
// Podman is one as it is; the fake is read through ReadFake.
type ContainerReader interface {
	Inspect(ctx context.Context, name string) (*ContainerState, error)
	Objects(ctx context.Context, instance string) (Objects, error)
}

// LogOptions narrow a log read (API §7's query parameters).
type LogOptions struct {
	// Since bounds how far back to read; zero means the whole log.
	Since time.Duration
	// Tail is the last N lines, applied after Since; zero means no limit.
	Tail int
	// Follow keeps the stream open as new lines arrive.
	Follow bool
}
