// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	"fmt"
	"sort"
	"strings"
)

// EffectiveConfig is what create hands the runtime for one service: the
// merged module configuration (spec 0003 §5 — `config: {env, command,
// args, files}` after service overrides) or, for an inline service, its
// own `env` and `command`. Semantics (spec 0003 changelog, plan S4):
// Entrypoint replaces the image entrypoint, Args the image command; an
// inline service's `command` replaces the image command.
type EffectiveConfig struct {
	Env        map[string]string
	Entrypoint []string
	Args       []string
	Files      []File
}

// Effective returns the composed service's configuration, or nil when
// the service is unknown.
func (c *Composition) Effective(name string) *EffectiveConfig {
	if c == nil {
		return nil
	}
	cs, ok := c.Services[name]
	if !ok {
		return nil
	}
	cfg := &EffectiveConfig{Env: map[string]string{}}
	if cs.Module != nil {
		if mc := cs.Module.Config; mc != nil {
			for k, v := range mc.Env {
				cfg.Env[k] = v
			}
			cfg.Entrypoint = append([]string(nil), mc.Command...)
			cfg.Args = append([]string(nil), mc.Args...)
			cfg.Files = append([]File(nil), mc.Files...)
		}
		if cs.Module.License != nil && cs.Module.License.EULA != nil {
			cfg.addEULA(cs.Module.License.EULA)
		}
		return cfg
	}
	for k, v := range cs.Svc.Env {
		cfg.Env[k] = v
	}
	cfg.Args = append([]string(nil), cs.Svc.Command...)
	if cs.Svc.EULA != nil {
		cfg.addEULA(cs.Svc.EULA)
	}
	return cfg
}

// addEULA injects the license-acceptance environment (spec 0003 §7):
// create runs only after the license gate recorded the acceptance, so
// the variables that turn acceptance into the image's own switch travel
// with the ordinary env.
func (e *EffectiveConfig) addEULA(eula *EULA) {
	for k, v := range eula.Env {
		e.Env[k] = v
	}
}

// NeedsRendering lists what the engine cannot yet produce for this
// service — `${secret:…}` references (per-instance secrets, plan S6) and
// config files (rendered and delivered at S6). Empty means the runtime
// can be handed the configuration as written.
func (e *EffectiveConfig) NeedsRendering() []string {
	if e == nil {
		return nil
	}
	var needs []string
	keys := make([]string, 0, len(e.Env))
	for k := range e.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if secretRef.MatchString(e.Env[k]) {
			needs = append(needs, fmt.Sprintf("env %s references %s", k, strings.Join(secretNamesIn(e.Env[k]), ", ")))
		}
	}
	for _, list := range [][]string{e.Entrypoint, e.Args} {
		for _, a := range list {
			if secretRef.MatchString(a) {
				needs = append(needs, fmt.Sprintf("command references %s", strings.Join(secretNamesIn(a), ", ")))
			}
		}
	}
	if n := len(e.Files); n > 0 {
		needs = append(needs, fmt.Sprintf("%d config file(s) to render", n))
	}
	return needs
}

func secretNamesIn(s string) []string {
	var names []string
	for _, m := range secretRef.FindAllStringSubmatch(s, -1) {
		names = append(names, "${secret:"+m[1]+"}")
	}
	return names
}

// EnvFile renders the environment in Podman's --env-file form, one
// KEY=VALUE per line, keys sorted. A value containing a newline cannot be
// expressed and is an error.
func (e *EffectiveConfig) EnvFile() (string, error) {
	keys := make([]string, 0, len(e.Env))
	for k := range e.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v := e.Env[k]
		if strings.ContainsAny(v, "\n\r") {
			return "", fmt.Errorf("env %s: multi-line values cannot be passed through an env file", k)
		}
		if strings.ContainsAny(k, "=\n\r ") || k == "" {
			return "", fmt.Errorf("env %q: not a valid variable name", k)
		}
		fmt.Fprintf(&b, "%s=%s\n", k, v)
	}
	return b.String(), nil
}
