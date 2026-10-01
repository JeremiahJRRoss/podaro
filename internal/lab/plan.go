// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// Plan is the human-reviewable plan of what create would do (API §6,
// roadmap P0 exit gate). It is deterministic: every list is sorted by
// name except checkpoints and steps, which keep their authored order.
// Secrets appear by name and kind only — values do not exist yet, and
// never appear here.
type Plan struct {
	Template    PlanTemplate    `json:"template"`
	Profile     *PlanProfile    `json:"profile,omitempty"`
	Services    []PlanService   `json:"services"`
	Network     PlanNetwork     `json:"network"`
	Volumes     []PlanVolume    `json:"volumes"`
	Secrets     []PlanSecret    `json:"secrets"`
	Seeds       []PlanSeed      `json:"seeds"`
	Checkpoints PlanCheckpoints `json:"checkpoints"`
	Playbooks   []PlanPlaybook  `json:"playbooks"`
	Licenses    []PlanLicense   `json:"licenses"`
	Exec        []PlanExec      `json:"exec"`
	Warnings    []Finding       `json:"warnings"`
}

// PlanTemplate identifies the template.
type PlanTemplate struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Title   string `json:"title,omitempty"`
	Path    string `json:"path"`
}

// PlanProfile is the selected sizing.
type PlanProfile struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// PlanService is one container the engine will create.
type PlanService struct {
	Name      string         `json:"name"`
	Module    string         `json:"module,omitempty"`
	Image     Image          `json:"image"`
	Endpoints []Endpoint     `json:"endpoints,omitempty"`
	Embed     string         `json:"embed,omitempty"`
	Resources Resources      `json:"resources"`
	Readiness *PlanReadiness `json:"readiness,omitempty"`
	Init      *PlanInit      `json:"init,omitempty"`
	Env       []string       `json:"env,omitempty"`
	Files     []string       `json:"files,omitempty"`
	Sysctls   map[string]any `json:"sysctls,omitempty"`
	EULA      string         `json:"eula,omitempty"`
}

// PlanReadiness is the honest timing the ladder will narrate.
type PlanReadiness struct {
	Typical string `json:"typical,omitempty"`
	Budget  string `json:"budget,omitempty"`
}

// PlanInit summarizes a one-shot init job.
type PlanInit struct {
	Image    Image `json:"image"`
	Requests int   `json:"requests"`
}

// PlanNetwork describes the per-instance network.
type PlanNetwork struct {
	Scope    string   `json:"scope"`
	Isolated bool     `json:"isolated"`
	Aliases  []string `json:"aliases"`
}

// PlanVolume is a persistent volume — none in v1alpha2, as in v1alpha1 (see Plan.Volumes).
type PlanVolume struct {
	Service string `json:"service"`
	Name    string `json:"name"`
}

// PlanSecret is a secret the engine will generate: name and kind only.
type PlanSecret struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	DeclaredBy []string `json:"declared_by"`
}

// PlanSeed is one named injection.
type PlanSeed struct {
	Name      string         `json:"name"`
	Generator string         `json:"generator"`
	Kind      string         `json:"kind"` // built-in · alias · exec
	Image     string         `json:"image,omitempty"`
	Count     int            `json:"count,omitempty"`
	Params    map[string]any `json:"params,omitempty"`
}

// PlanCheckpoints splits checkpoints by class (never summed, spec 0001 §1).
type PlanCheckpoints struct {
	Baseline  []PlanCheckpoint `json:"baseline"`
	Objective []PlanCheckpoint `json:"objective"`
}

// PlanCheckpoint is one checkpoint with where it is declared.
type PlanCheckpoint struct {
	ID       string `json:"id"`
	Adapter  string `json:"adapter"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
}

// PlanPlaybook summarizes a playbook.
type PlanPlaybook struct {
	Name       string   `json:"name"`
	Title      string   `json:"title"`
	Steps      int      `json:"steps"`
	Objectives int      `json:"objectives"`
	Modes      []string `json:"modes"`
}

// PlanLicense is an EULA create will gate on (API §6.2).
type PlanLicense struct {
	ID         string   `json:"id"`
	Name       string   `json:"name,omitempty"`
	URL        string   `json:"url"`
	RequiredBy []string `json:"required_by"`
}

// PlanExec is one extension image with its secret grants — the list the
// first-contact review (threat model D5) reads.
type PlanExec struct {
	Where   string   `json:"where"`
	Image   string   `json:"image"`
	Secrets []string `json:"secrets"`
}

// PlanOptions select the profile.
type PlanOptions struct {
	Options
	// Profile names a template profile; "" picks `standard` when the
	// template declares it, otherwise no profile (module envelopes).
	Profile string
}

// MakePlan validates and, when valid, builds the plan.
func MakePlan(opts PlanOptions) (*Plan, *Result, error) {
	res, err := Validate(opts.Options)
	if err != nil {
		return nil, nil, err
	}
	if !res.Valid() {
		return nil, res, res.Error()
	}
	p, err := BuildPlan(res, opts.Profile)
	if err != nil {
		return nil, res, err
	}
	return p, res, nil
}

// BuildPlan derives the plan from a valid Result.
func BuildPlan(res *Result, profile string) (*Plan, error) {
	t := res.Template
	c := res.Composition
	p := &Plan{
		Template: PlanTemplate{Name: t.Metadata.Name, Version: t.Metadata.Version, Title: t.Metadata.Title, Path: res.Path},
		Network:  PlanNetwork{Scope: "instance", Isolated: true, Aliases: sortedKeys(t.Services)},
		Volumes:  []PlanVolume{},
		Warnings: append([]Finding{}, res.Warnings...),
	}

	var prof *Profile
	switch {
	case profile != "":
		pr, ok := t.Profiles[profile]
		if !ok {
			e := pdr.New(pdr.CodeLabReference, "profile %q is not declared by %s (profiles: %s)", profile, t.Metadata.Name, joinOrNone(sortedKeys(t.Profiles)))
			e.Next = "pick a declared profile with --profile, or omit it"
			return nil, e
		}
		prof = &pr
		p.Profile = &PlanProfile{Name: profile, Description: pr.Description}
	default:
		if pr, ok := t.Profiles["standard"]; ok {
			prof = &pr
			p.Profile = &PlanProfile{Name: "standard", Description: pr.Description}
		}
	}

	for _, name := range sortedKeys(c.Services) {
		cs := c.Services[name]
		ps := PlanService{Name: name}
		if cs.Module != nil {
			m := cs.Module
			ps.Module = cs.Use
			ps.Image = m.Image
			ps.Endpoints = withDefaultScheme(m.Endpoints)
			ps.Embed = m.Embed
			if m.Resources != nil {
				ps.Resources = *m.Resources
			}
			if m.Readiness != nil {
				ps.Readiness = &PlanReadiness{Typical: m.Readiness.Typical, Budget: m.Readiness.Budget}
			}
			if m.Init != nil {
				ps.Init = &PlanInit{Image: m.Init.Image, Requests: len(m.Init.Requests)}
			}
			if m.Config != nil {
				ps.Env = sortedKeys(m.Config.Env)
				for _, f := range m.Config.Files {
					ps.Files = append(ps.Files, f.Path)
				}
				sort.Strings(ps.Files)
			}
			if m.Requires != nil && len(m.Requires.Sysctls) > 0 {
				ps.Sysctls = m.Requires.Sysctls
			}
			if e := moduleEULA(m); e != nil {
				ps.EULA = e.ID
			}
		} else {
			svc := cs.Svc
			ps.Image = splitImageRef(svc.Image)
			ps.Endpoints = withDefaultScheme(svc.Endpoints)
			ps.Embed = svc.Embed
			if svc.Resources != nil {
				ps.Resources = *svc.Resources
			}
			if svc.Readiness != nil {
				ps.Readiness = &PlanReadiness{Typical: svc.Readiness.Typical, Budget: svc.Readiness.Budget}
			}
			ps.Env = sortedKeys(svc.Env)
			if svc.EULA != nil {
				ps.EULA = svc.EULA.ID
			}
		}
		if prof != nil {
			if r, ok := prof.Resources[name]; ok {
				if r.CPU != "" {
					ps.Resources.CPU = r.CPU
				}
				if r.Memory != "" {
					ps.Resources.Memory = r.Memory
				}
			}
		}
		p.Services = append(p.Services, ps)
	}

	for _, name := range sortedKeys(c.Secrets) {
		p.Secrets = append(p.Secrets, PlanSecret{Name: name, Kind: c.Kinds[name], DeclaredBy: c.Secrets[name]})
	}

	for _, name := range sortedKeys(t.Seeds) {
		s := t.Seeds[name]
		ps := PlanSeed{Name: name, Count: s.Count, Params: s.Params}
		switch {
		case s.Generator.Exec != nil:
			ps.Generator, ps.Kind, ps.Image = "exec", "exec", s.Generator.Exec.Image
			p.Exec = append(p.Exec, PlanExec{Where: "seed " + name, Image: s.Generator.Exec.Image, Secrets: sortedCopy(s.Generator.Exec.Secrets)})
		case builtinGenerators[s.Generator.Name]:
			ps.Generator, ps.Kind = s.Generator.Name, "built-in"
		default:
			owner := c.Generators[s.Generator.Name]
			ps.Generator, ps.Kind, ps.Image = s.Generator.Name, "alias", owner.Exec.Image
			p.Exec = append(p.Exec, PlanExec{Where: fmt.Sprintf("seed %s (alias %s from modules/%s)", name, s.Generator.Name, owner.Module), Image: owner.Exec.Image, Secrets: sortedCopy(owner.Exec.Secrets)})
		}
		p.Seeds = append(p.Seeds, ps)
	}

	p.Checkpoints = PlanCheckpoints{Baseline: []PlanCheckpoint{}, Objective: []PlanCheckpoint{}}
	// addExec records an extension container a checkpoint (or one of its
	// nested query adapters) would run: an explicit exec, or an alias.
	addExec := func(where, adapter string, params map[string]any) {
		switch {
		case adapter == "exec":
			img, _ := params["image"].(string)
			var grants []string
			if gs, ok := params["secrets"].([]any); ok {
				for _, g := range gs {
					grants = append(grants, fmt.Sprint(g))
				}
			}
			p.Exec = append(p.Exec, PlanExec{Where: where, Image: img, Secrets: sortedCopy(grants)})
		default:
			if owner, ok := c.Adapters[adapter]; ok {
				p.Exec = append(p.Exec, PlanExec{Where: fmt.Sprintf("%s (alias %s from modules/%s)", where, adapter, owner.Module), Image: owner.Exec.Image, Secrets: sortedCopy(owner.Exec.Secrets)})
			}
		}
	}
	addCP := func(cp Checkpoint, defaultClass, source string) {
		class := cp.Class
		if class == "" {
			class = defaultClass
		}
		sev := cp.Severity
		if sev == "" {
			sev = "gate"
		}
		pc := PlanCheckpoint{ID: cp.ID, Adapter: cp.Adapter, Severity: sev, Source: source}
		if class == "baseline" {
			p.Checkpoints.Baseline = append(p.Checkpoints.Baseline, pc)
		} else {
			p.Checkpoints.Objective = append(p.Checkpoints.Objective, pc)
		}
		addExec("checkpoint "+cp.ID, cp.Adapter, cp.Params)
	}
	for _, cp := range t.Checkpoints {
		addCP(cp, "baseline", "template")
	}
	pbs := append([]*LoadedPlaybook(nil), res.Playbooks...)
	sort.Slice(pbs, func(i, j int) bool { return pbs[i].Playbook.Metadata.Name < pbs[j].Playbook.Metadata.Name })
	templateObjectives := map[string]bool{}
	for _, cp := range t.Checkpoints {
		if cp.Class == "objective" {
			templateObjectives[cp.ID] = true
		}
	}
	for _, lp := range pbs {
		pb := lp.Playbook
		objectives := 0
		for _, st := range pb.Steps {
			if st.Checkpoint == nil {
				continue
			}
			if st.Checkpoint.Ref != "" {
				if templateObjectives[st.Checkpoint.Ref] {
					objectives++
				}
				continue
			}
			class := st.Checkpoint.Class
			if class == "" {
				class = "objective"
			}
			if class == "objective" {
				objectives++
			}
			addCP(*st.Checkpoint, "objective", fmt.Sprintf("playbook %s · step %s", pb.Metadata.Name, st.ID))
		}
		modes := pb.Metadata.Modes
		if len(modes) == 0 {
			modes = []string{"guided", "presenter", "repro"}
		}
		p.Playbooks = append(p.Playbooks, PlanPlaybook{Name: pb.Metadata.Name, Title: pb.Metadata.Title, Steps: len(pb.Steps), Objectives: objectives, Modes: modes})
	}

	for _, id := range c.eulaIDs() {
		d := c.EULAs[id]
		p.Licenses = append(p.Licenses, PlanLicense{ID: id, Name: d.EULA.Name, URL: d.EULA.URL, RequiredBy: d.RequiredBy})
	}
	sort.SliceStable(p.Exec, func(i, j int) bool { return p.Exec[i].Where < p.Exec[j].Where })
	if p.Services == nil {
		p.Services = []PlanService{}
	}
	if p.Secrets == nil {
		p.Secrets = []PlanSecret{}
	}
	if p.Seeds == nil {
		p.Seeds = []PlanSeed{}
	}
	if p.Playbooks == nil {
		p.Playbooks = []PlanPlaybook{}
	}
	if p.Licenses == nil {
		p.Licenses = []PlanLicense{}
	}
	if p.Exec == nil {
		p.Exec = []PlanExec{}
	}
	if p.Warnings == nil {
		p.Warnings = []Finding{}
	}
	return p, nil
}

func sortedCopy(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}

// splitImageRef splits repo@sha256:… into an Image (tag unknown: inline
// services pin digests directly).
func splitImageRef(ref string) Image {
	if i := strings.Index(ref, "@"); i > 0 {
		return Image{Repository: ref[:i], Digest: ref[i+1:]}
	}
	return Image{Repository: ref}
}

// Render prints the plan in the UX §7 grammar: one label column (sized to
// the longest label so nothing collides), mono facts, sorted lists, full
// digests (a plan is a review artifact).
func (p *Plan) Render(pr *render.Printer) {
	type planRow struct{ section, label, detail string }
	var rows []planRow
	section := "top"
	row := func(label, detail string) {
		if !strings.HasPrefix(label, "  ") {
			section = "top"
		}
		rows = append(rows, planRow{section, label, detail})
	}
	sub := func(name string) { section = name }

	if p.Profile != nil {
		desc := p.Profile.Name
		if p.Profile.Description != "" {
			desc += " · " + p.Profile.Description
		}
		row("profile", desc)
	} else {
		row("profile", "none declared · module envelopes apply")
	}

	row(fmt.Sprintf("services (%d)", len(p.Services)), "")
	sub("services")
	for _, s := range p.Services {
		var facts []string
		if s.Module != "" {
			facts = append(facts, s.Module)
		} else {
			facts = append(facts, "inline")
		}
		if s.Embed != "" {
			facts = append(facts, s.Embed)
		}
		if s.Resources.CPU != "" {
			facts = append(facts, "cpu "+s.Resources.CPU)
		}
		if s.Resources.Memory != "" {
			facts = append(facts, "memory "+s.Resources.Memory)
		}
		if s.Readiness != nil && s.Readiness.Typical != "" {
			r := "ready typically " + s.Readiness.Typical
			if s.Readiness.Budget != "" {
				r += " (budget " + s.Readiness.Budget + ")"
			}
			facts = append(facts, r)
		}
		row("  "+s.Name, strings.Join(facts, " · "))
		row("    image", s.Image.Ref())
		if len(s.Endpoints) > 0 {
			var eps []string
			for _, e := range s.Endpoints {
				scheme := e.Scheme
				if scheme == "" {
					scheme = "http"
				}
				eps = append(eps, fmt.Sprintf("%s :%d/%s", e.Purpose, e.Port, scheme))
			}
			row("    endpoints", strings.Join(eps, " · "))
		}
		if s.Init != nil {
			row("    init", fmt.Sprintf("%s · %s · after healthy", s.Init.Image.Ref(), plural(s.Init.Requests, "request")))
		}
		if len(s.Env) > 0 || len(s.Files) > 0 {
			row("    config", fmt.Sprintf("%s · %s%s", plural(len(s.Env), "env var"), plural(len(s.Files), "file"), fileList(s.Files)))
		}
		if len(s.Sysctls) > 0 {
			var ks []string
			for _, k := range sortedKeys(s.Sysctls) {
				ks = append(ks, fmt.Sprintf("%s=%v", k, s.Sysctls[k]))
			}
			row("    requires", strings.Join(ks, " · "))
		}
		if s.EULA != "" {
			row("    eula", s.EULA+" · acceptance required at create")
		}
	}

	row("network", "one isolated network per instance · aliases: "+strings.Join(p.Network.Aliases, " · "))
	if len(p.Volumes) == 0 {
		row("volumes", "none declared · v1alpha2 modules keep state in container storage; destroy removes it")
	}
	sub("volumes")
	for _, v := range p.Volumes {
		row("  "+v.Service, v.Name)
	}

	var secrets []string
	for _, s := range p.Secrets {
		secrets = append(secrets, fmt.Sprintf("%s (%s)", s.Name, s.Kind))
	}
	row(fmt.Sprintf("secrets (%d)", len(p.Secrets)), joinOrNone(secrets)+" · generated per instance, never printed")

	row(fmt.Sprintf("seeds (%d)", len(p.Seeds)), "")
	sub("seeds")
	for _, s := range p.Seeds {
		facts := []string{fmt.Sprintf("%s (%s)", s.Generator, s.Kind)}
		if s.Count > 0 {
			facts = append(facts, fmt.Sprintf("count %d", s.Count))
		}
		if len(s.Params) > 0 {
			facts = append(facts, "params "+strings.Join(sortedKeys(s.Params), ", "))
		}
		if s.Image != "" {
			facts = append(facts, s.Image)
		}
		row("  "+s.Name, strings.Join(facts, " · "))
	}

	row("checkpoints", fmt.Sprintf("baseline %d · objectives %d", len(p.Checkpoints.Baseline), len(p.Checkpoints.Objective)))
	sub("checkpoints")
	for _, cp := range p.Checkpoints.Baseline {
		row("  "+cp.ID, fmt.Sprintf("baseline · %s · %s · %s", cp.Adapter, cp.Severity, cp.Source))
	}
	for _, cp := range p.Checkpoints.Objective {
		row("  "+cp.ID, fmt.Sprintf("objective · %s · %s · %s", cp.Adapter, cp.Severity, cp.Source))
	}

	row(fmt.Sprintf("playbooks (%d)", len(p.Playbooks)), "")
	sub("playbooks")
	for _, pb := range p.Playbooks {
		row("  "+pb.Name, fmt.Sprintf("%s · %s · %s · %s", pb.Title, plural(pb.Steps, "step"), plural(pb.Objectives, "objective"), strings.Join(pb.Modes, ", ")))
	}

	row(fmt.Sprintf("licenses (%d)", len(p.Licenses)), "")
	sub("licenses")
	for _, l := range p.Licenses {
		name := l.Name
		if name == "" {
			name = l.ID
		}
		row("  "+l.ID, fmt.Sprintf("%s · %s · required by %s", name, l.URL, strings.Join(l.RequiredBy, ", ")))
	}
	if len(p.Licenses) > 0 {
		row("  ", "acceptance is explicit and recorded at create (API §6.2); never defaulted")
	}

	if len(p.Exec) == 0 {
		row("exec images", "none · every judge and generator is built-in")
	} else {
		row(fmt.Sprintf("exec images (%d)", len(p.Exec)), "")
		sub("exec")
		for _, e := range p.Exec {
			grants := "no secret grants"
			if len(e.Secrets) > 0 {
				grants = "secrets " + strings.Join(e.Secrets, ", ")
			}
			row("  "+e.Where, e.Image+" · "+grants)
		}
	}

	widths := map[string]int{}
	for _, r := range rows {
		if n := len([]rune(r.label)) + 2; n > widths[r.section] {
			widths[r.section] = n
		}
	}
	head := p.Template.Name
	if p.Template.Version != "" {
		head += "@" + p.Template.Version
	}
	if p.Template.Title != "" {
		head += " · " + p.Template.Title
	}
	pr.Plain(head)
	for _, r := range rows {
		pr.Indent(r.label, widths[r.section], r.detail)
	}
	for _, wn := range p.Warnings {
		pr.Check(render.Warn, wn.Code, 10, wn.Path+"  "+wn.Message)
	}
}

func fileList(files []string) string {
	if len(files) == 0 {
		return ""
	}
	return " (" + strings.Join(files, ", ") + ")"
}

// Summary is the one-line validate result for a valid lab.
func (r *Result) Summary() string {
	t := r.Template
	if t == nil {
		return "valid"
	}
	baselines, objectives := 0, 0
	for _, cp := range t.Checkpoints {
		if cp.Class == "objective" {
			objectives++
		} else {
			baselines++
		}
	}
	steps := 0
	for _, lp := range r.Playbooks {
		steps += len(lp.Playbook.Steps)
		for _, st := range lp.Playbook.Steps {
			if st.Checkpoint != nil && st.Checkpoint.Ref == "" && (st.Checkpoint.Class == "" || st.Checkpoint.Class == "objective") {
				objectives++
			}
		}
	}
	// Objectives reached through refs are template-level and were counted
	// above by class; nothing to add here.
	parts := []string{
		"valid",
		plural(len(t.Services), "service"),
		plural(len(t.Seeds), "seed"),
		fmt.Sprintf("baseline %d · objectives %d", baselines, objectives),
		fmt.Sprintf("%s (%s)", plural(len(r.Playbooks), "playbook"), plural(steps, "step")),
	}
	return strings.Join(parts, " · ")
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// withDefaultScheme materializes the schema's default (`scheme: http`)
// so the JSON plan carries the effective scheme the human render assumes,
// never a missing field two readers could interpret differently.
func withDefaultScheme(eps []Endpoint) []Endpoint {
	if len(eps) == 0 {
		return eps
	}
	out := make([]Endpoint, len(eps))
	for i, e := range eps {
		if e.Scheme == "" {
			e.Scheme = "http"
		}
		out[i] = e
	}
	return out
}
