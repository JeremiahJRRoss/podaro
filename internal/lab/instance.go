// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// The instance-side views of a validated template (plan S6): the
// flattened checkpoint set an instance evaluates (spec 0001 §1: every
// checkpoint, by class), the playbooks the console serves, and which
// seeds create runs.

// FlatCheckpoint is one checkpoint as an instance addresses it (API §8:
// flattened per instance, addressed by id), with its class resolved and
// where it was declared.
type FlatCheckpoint struct {
	Checkpoint
	// ResolvedClass is the class with the location default applied.
	ResolvedClass string
	// Source names the declaration: "template", or "playbook <p> · step <s>".
	Source string
	// Playbook and Step are set for an inline step checkpoint.
	Playbook string
	Step     string
	// Steps lists every playbook step that carries or references the
	// checkpoint, as "<playbook>/<step>".
	Steps []string
	// Exec is the resolved implementation when Adapter names a module
	// alias (spec 0003 §10): what the engine runs, so a changed image,
	// args, env, secret grants or limits under the same alias name are a
	// changed definition. Nil for a
	// built-in adapter.
	Exec *ExecSpec
}

// DefinitionDigest identifies what a checkpoint's result is judged by:
// the resolved class, the adapter and — for a module alias — its resolved
// implementation, its params, the expectation, the timeout and the
// retries — every field that changes what an evaluation observes or how
// it is judged. A result row carries the digest it was
// made under; a row whose digest no longer matches starts over as pending.
// Hint, severity and location do not
// change a verdict and are left out.
func DefinitionDigest(c FlatCheckpoint) string {
	raw, _ := json.Marshal(struct {
		Class   string         `json:"class"`
		Adapter string         `json:"adapter"`
		Exec    *ExecSpec      `json:"exec,omitempty"`
		Params  map[string]any `json:"params,omitempty"`
		Expect  map[string]any `json:"expect,omitempty"`
		Timeout string         `json:"timeout,omitempty"`
		Retries *Retries       `json:"retries,omitempty"`
	}{c.ResolvedClass, c.Adapter, c.Exec, c.Params, c.Expect, c.Timeout, c.Retries})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

// Severity is the checkpoint's severity with the default applied.
func (c FlatCheckpoint) Severity() string {
	if c.Checkpoint.Severity == "" {
		return "gate"
	}
	return c.Checkpoint.Severity
}

// FlattenCheckpoints lists every checkpoint of a valid result: the
// template's (class defaults to baseline) in authored order, then each
// playbook's inline step checkpoints (class defaults to objective),
// playbooks by name, steps in order. A step's `{ref: id}` adds the step
// to the template checkpoint's Steps.
func FlattenCheckpoints(res *Result) []FlatCheckpoint {
	if res == nil || res.Template == nil {
		return nil
	}
	var out []FlatCheckpoint
	index := map[string]int{}
	for _, cp := range res.Template.Checkpoints {
		class := cp.Class
		if class == "" {
			class = "baseline"
		}
		index[cp.ID] = len(out)
		out = append(out, FlatCheckpoint{Checkpoint: cp, ResolvedClass: class, Source: "template"})
	}
	pbs := append([]*LoadedPlaybook(nil), res.Playbooks...)
	sort.Slice(pbs, func(i, j int) bool { return pbs[i].Playbook.Metadata.Name < pbs[j].Playbook.Metadata.Name })
	for _, lp := range pbs {
		pb := lp.Playbook
		for _, st := range pb.Steps {
			cp := st.Checkpoint
			if cp == nil {
				continue
			}
			at := pb.Metadata.Name + "/" + st.ID
			if cp.Ref != "" {
				if i, ok := index[cp.Ref]; ok {
					out[i].Steps = append(out[i].Steps, at)
				}
				continue
			}
			class := cp.Class
			if class == "" {
				class = "objective"
			}
			index[cp.ID] = len(out)
			out = append(out, FlatCheckpoint{Checkpoint: *cp, ResolvedClass: class, Source: fmt.Sprintf("playbook %s · step %s", pb.Metadata.Name, st.ID), Playbook: pb.Metadata.Name, Step: st.ID, Steps: []string{at}})
		}
	}
	// A module alias resolves to what the engine runs; the digest of a
	// checkpoint that names one covers it.
	if res.Composition != nil {
		for i := range out {
			if owner, ok := res.Composition.Adapters[out[i].Adapter]; ok {
				exec := owner.Exec
				out[i].Exec = &exec
			}
		}
	}
	return out
}

// SeedRoles reports, for every template seed, whether a playbook step
// invokes it as an action. Seeds no step names are the standing seeds
// create runs (the instance's starting data); a seed a step names is the
// learner's or presenter's act, run when its button is pressed — running
// it at create would pre-empt the step and turn its objective green at
// create (spec 0001 §1, PDR-W101).
func SeedRoles(res *Result) (standing, actions []string) {
	if res == nil || res.Template == nil {
		return nil, nil
	}
	named := map[string]bool{}
	for _, lp := range res.Playbooks {
		for _, st := range lp.Playbook.Steps {
			for _, a := range st.Actions {
				if a.Seed != "" {
					named[a.Seed] = true
				}
			}
		}
	}
	for _, name := range sortedKeys(res.Template.Seeds) {
		if named[name] {
			actions = append(actions, name)
		} else {
			standing = append(standing, name)
		}
	}
	return standing, actions
}

// PlaybookNamed returns a loaded playbook by name, or nil.
func PlaybookNamed(res *Result, name string) *Playbook {
	if res == nil {
		return nil
	}
	for _, lp := range res.Playbooks {
		if lp.Playbook.Metadata.Name == name {
			return lp.Playbook
		}
	}
	return nil
}

// EndpointOf finds a composed service's endpoint by purpose ("" for the
// first declared) — where the engine reaches a service, and what Spec
// 0002 hands to extensions.
func EndpointOf(res *Result, service, purpose string) (Endpoint, bool) {
	if res == nil || res.Composition == nil {
		return Endpoint{}, false
	}
	cs, ok := res.Composition.Services[service]
	if !ok {
		return Endpoint{}, false
	}
	var eps []Endpoint
	if cs.Module != nil {
		eps = cs.Module.Endpoints
	} else {
		eps = cs.Svc.Endpoints
	}
	for _, ep := range withDefaultScheme(eps) {
		if purpose == "" || ep.Purpose == purpose {
			return ep, true
		}
	}
	return Endpoint{}, false
}

// EndpointsOf lists a composed service's endpoints with the default
// scheme applied.
func EndpointsOf(res *Result, service string) []Endpoint {
	if res == nil || res.Composition == nil {
		return nil
	}
	cs, ok := res.Composition.Services[service]
	if !ok {
		return nil
	}
	if cs.Module != nil {
		return withDefaultScheme(cs.Module.Endpoints)
	}
	return withDefaultScheme(cs.Svc.Endpoints)
}

// InitOf returns a composed service's effective init block (module
// services only), or nil.
func InitOf(res *Result, service string) *Init {
	if res == nil || res.Composition == nil {
		return nil
	}
	cs, ok := res.Composition.Services[service]
	if !ok || cs.Module == nil {
		return nil
	}
	return cs.Module.Init
}

// ModuleNameOf returns the library name of the module a service uses,
// or "" for an inline service.
func ModuleNameOf(res *Result, service string) string {
	if res == nil || res.Composition == nil {
		return ""
	}
	cs, ok := res.Composition.Services[service]
	if !ok {
		return ""
	}
	return cs.moduleName()
}
