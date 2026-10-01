// SPDX-License-Identifier: AGPL-3.0-only

package lab

import "gopkg.in/yaml.v3"

// Typed views of the v1alpha2 manifests — and of v1alpha1's, whose shape
// is the same (the reconciliation plan's D-R2) — decoded only after the
// schema has accepted the shape (spec 0003 §2–§9, spec 0001 §2–§6). Field names
// mirror the YAML keys; the JSON tags serve `lab plan --json`.

// Metadata is the shared metadata block of templates and modules.
type Metadata struct {
	Name        string `yaml:"name" json:"name"`
	Version     string `yaml:"version" json:"version,omitempty"`
	Title       string `yaml:"title" json:"title,omitempty"`
	Description string `yaml:"description" json:"description,omitempty"`
}

// Template is kind: Template (spec 0003 §2).
type Template struct {
	APIVersion  string             `yaml:"apiVersion"`
	Kind        string             `yaml:"kind"`
	Metadata    Metadata           `yaml:"metadata"`
	Services    map[string]Service `yaml:"services"`
	Seeds       map[string]Seed    `yaml:"seeds"`
	Checkpoints []Checkpoint       `yaml:"checkpoints"`
	Secrets     map[string]Secret  `yaml:"secrets"`
	Licenses    []string           `yaml:"licenses"`
	Profiles    map[string]Profile `yaml:"profiles"`
}

// Service is one entry of services: — module use or inline image (§3).
type Service struct {
	Use       string            `yaml:"use"`
	Config    map[string]any    `yaml:"config"`
	Image     string            `yaml:"image"`
	Env       map[string]string `yaml:"env"`
	Command   []string          `yaml:"command"`
	Endpoints []Endpoint        `yaml:"endpoints"`
	Embed     string            `yaml:"embed"`
	Readiness *Readiness        `yaml:"readiness"`
	Resources *Resources        `yaml:"resources"`
	EULA      *EULA             `yaml:"eula"`
}

// Seed is one named deterministic data injection (§4).
type Seed struct {
	Generator Generator      `yaml:"generator"`
	Count     int            `yaml:"count"`
	Params    map[string]any `yaml:"params"`
}

// Generator is either a name (built-in or module alias) or an exec form.
type Generator struct {
	Name string
	Exec *ExecSpec
}

// UnmarshalYAML accepts the scalar and the {exec: …} forms.
func (g *Generator) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		g.Name = n.Value
		return nil
	}
	var form struct {
		Exec *ExecSpec `yaml:"exec"`
	}
	if err := n.Decode(&form); err != nil {
		return err
	}
	g.Exec = form.Exec
	return nil
}

// ExecSpec is a Spec 0002 extension container: digest-pinned image plus
// declared secret grants (template schema $defs/execSpec).
type ExecSpec struct {
	Image   string            `yaml:"image" json:"image"`
	Args    []string          `yaml:"args" json:"args,omitempty"`
	Env     map[string]string `yaml:"env" json:"env,omitempty"`
	Secrets []string          `yaml:"secrets" json:"secrets,omitempty"`
	Limits  map[string]string `yaml:"limits" json:"limits,omitempty"`
}

// Checkpoint is spec 0001 §2, plus the playbook-side {ref: id} form.
type Checkpoint struct {
	Ref      string         `yaml:"ref"`
	ID       string         `yaml:"id"`
	Class    string         `yaml:"class"`
	Adapter  string         `yaml:"adapter"`
	Params   map[string]any `yaml:"params"`
	Expect   map[string]any `yaml:"expect"`
	Timeout  string         `yaml:"timeout"`
	Retries  *Retries       `yaml:"retries"`
	Severity string         `yaml:"severity"`
	Hint     string         `yaml:"hint"`
	Evidence *Evidence      `yaml:"evidence"`
}

// Retries is the {attempts, backoff} pair.
type Retries struct {
	Attempts int    `yaml:"attempts"`
	Backoff  string `yaml:"backoff"`
}

// Evidence names what a result records.
type Evidence struct {
	Capture []string `yaml:"capture"`
}

// Secret declares a per-instance generated secret: name and kind, never a
// value (§6).
type Secret struct {
	Kind        string `yaml:"kind"`
	Description string `yaml:"description"`
}

// Profile is a named resource sizing (§8).
type Profile struct {
	Description string               `yaml:"description"`
	Resources   map[string]Resources `yaml:"resources"`
}

// Resources is a cpu/memory envelope.
type Resources struct {
	CPU    string `yaml:"cpu" json:"cpu,omitempty"`
	Memory string `yaml:"memory" json:"memory,omitempty"`
}

// Endpoint is one port a service exposes on the instance network.
type Endpoint struct {
	Purpose string `yaml:"purpose" json:"purpose"`
	Port    int    `yaml:"port" json:"port"`
	Scheme  string `yaml:"scheme" json:"scheme,omitempty"`
	Path    string `yaml:"path" json:"path,omitempty"`
}

// Readiness is honest timing (§9.2): a liveness probe, the typical time
// the ladder narrates, and the budget that bounds it.
type Readiness struct {
	Probe    Probe  `yaml:"probe"`
	Typical  string `yaml:"typical"`
	Budget   string `yaml:"budget"`
	Interval string `yaml:"interval"`
}

// Probe is the liveness probe.
type Probe struct {
	Scheme       string `yaml:"scheme"`
	Port         int    `yaml:"port"`
	Path         string `yaml:"path"`
	ExpectStatus int    `yaml:"expect_status"`
}

// EULA is a license declaration (§7); env is injected only after recorded
// acceptance.
type EULA struct {
	ID   string            `yaml:"id" json:"id"`
	Name string            `yaml:"name" json:"name,omitempty"`
	URL  string            `yaml:"url" json:"url"`
	Env  map[string]string `yaml:"env" json:"-"`
}

// Image is a digest-pinned OCI reference (§9: the digest is the pin).
type Image struct {
	Repository string `yaml:"repository" json:"repository"`
	Tag        string `yaml:"tag" json:"tag"`
	Digest     string `yaml:"digest" json:"digest"`
}

// Ref is what the engine pulls: repository@digest.
func (i Image) Ref() string { return i.Repository + "@" + i.Digest }

// Module is kind: Module (§9).
type Module struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   Metadata          `yaml:"metadata"`
	Image      Image             `yaml:"image"`
	License    *License          `yaml:"license"`
	Secrets    map[string]Secret `yaml:"secrets"`
	Config     *ModuleConfig     `yaml:"config"`
	Init       *Init             `yaml:"init"`
	Readiness  *Readiness        `yaml:"readiness"`
	Endpoints  []Endpoint        `yaml:"endpoints"`
	Embed      string            `yaml:"embed"`
	Resources  *Resources        `yaml:"resources"`
	Requires   *Requires         `yaml:"requires"`
	Adapters   []Alias           `yaml:"adapters"`
	Generators []Alias           `yaml:"generators"`
}

// License is the product's license: SPDX for open source, EULA otherwise.
type License struct {
	SPDX string `yaml:"spdx"`
	EULA *EULA  `yaml:"eula"`
}

// ModuleConfig is rendered engine-side at create.
type ModuleConfig struct {
	Env     map[string]string `yaml:"env"`
	Command []string          `yaml:"command"`
	Args    []string          `yaml:"args"`
	Files   []File            `yaml:"files"`
}

// File is one rendered config file.
type File struct {
	Path string `yaml:"path"`
	Mode string `yaml:"mode"`
	// Content is the file's text. Source names a template asset to read
	// it from instead — `scenarios/<name>/assets/…`, resolved at validate
	// against the template's own directory, so the plan and the delivery
	// snapshot carry the content and not a path (spec 0003 §9, plan S8).
	Content string `yaml:"content"`
	Source  string `yaml:"source"`
}

// Init is the one-shot init job (§9.1): request metadata, never scripts.
type Init struct {
	Image    Image         `yaml:"image"`
	WaitsFor string        `yaml:"waits_for"`
	Requests []InitRequest `yaml:"requests"`
}

// InitRequest is one ordered HTTP request of an init job.
type InitRequest struct {
	Service string            `yaml:"service"`
	Method  string            `yaml:"method"`
	Scheme  string            `yaml:"scheme"`
	Port    int               `yaml:"port"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
	Body    any               `yaml:"body"`
	Auth    *Auth             `yaml:"auth"`
	Until   *Until            `yaml:"until"`
	Retries *Retries          `yaml:"retries"`
}

// Auth names the secret an init request authenticates with.
type Auth struct {
	Secret   string `yaml:"secret"`
	Username string `yaml:"username"`
}

// Until is the poll target of an init request.
type Until struct {
	Status int `yaml:"status"`
}

// Requires lists host facts doctor can check per template.
type Requires struct {
	Sysctls map[string]any `yaml:"sysctls"`
}

// Alias is a module-shipped adapter or generator name resolving to an
// exec judge (§10).
type Alias struct {
	Name string   `yaml:"name"`
	Exec ExecSpec `yaml:"exec"`
}

// Playbook is kind: Playbook (spec 0001 §5).
type Playbook struct {
	APIVersion string       `yaml:"apiVersion"`
	Kind       string       `yaml:"kind"`
	Metadata   PlaybookMeta `yaml:"metadata"`
	Steps      []Step       `yaml:"steps"`
}

// PlaybookMeta is the playbook metadata block.
type PlaybookMeta struct {
	Name        string   `yaml:"name"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Modes       []string `yaml:"modes"`
	Gating      string   `yaml:"gating"`
}

// Step is spec 0001 §6.
type Step struct {
	ID         string      `yaml:"id"`
	Title      string      `yaml:"title"`
	Context    string      `yaml:"context"`
	Duration   string      `yaml:"duration"`
	Auto       bool        `yaml:"auto"`
	Body       string      `yaml:"body"`
	Notes      string      `yaml:"notes"`
	Actions    []Action    `yaml:"actions"`
	Checkpoint *Checkpoint `yaml:"checkpoint"`
	Solution   string      `yaml:"solution"`
}

// Action is a seed or reveal button.
type Action struct {
	Seed   string `yaml:"seed"`
	Reveal string `yaml:"reveal"`
}

// Built-in registries (spec 0001 §3; spec 0003 §4). Alias names may not
// shadow them (spec 0003 §11 rule 6). The golden lab's six adapters and
// two generators left with it on 2026-09-23 (the reconciliation plan's
// R2); a name no registry holds is refused as unknown. A module alias's
// params, like every adapter's, are open input and are never interpreted
// as nested adapters.
var (
	builtinAdapters = map[string]bool{
		"http": true, "container": true, "attest": true, "exec": true,
	}
	builtinGenerators = map[string]bool{
		"http-requests": true, "web-logs": true,
	}
)
