// SPDX-License-Identifier: AGPL-3.0-only

package podaro

import (
	_ "embed"
	"encoding/json"
	"sync"
)

// The retirement manifest (hack/retirement.json) travels inside the binary
// so the retired-name diagnostics can recognise what the owner retired on
// 2026-09-23 without spelling it: PDR-E106 (a manifest names a retired
// adapter, generator or module) and PDR-E107 (`up` of a retired template)
// read the names from here, never from a Go table or a message (the
// reconciliation plan's Q-R5), and R3's catalog filter reuses the same
// accessor. The file is embedded byte for byte — hack/reconciliation_check.py's
// check 5 allows a retired name in a binary only inside such a copy.
//
//go:embed hack/retirement.json
var retirementManifest []byte

// RetirementManifest is the part of hack/retirement.json the engine reads:
// the retired identifiers by registry role, and the record that retired
// them.
type RetirementManifest struct {
	RetiredOn string   `json:"retired_on"`
	Authority []string `json:"authority"`
	Scenarios []struct {
		Name      string   `json:"name"`
		Playbooks []string `json:"playbooks"`
		Licenses  []string `json:"licenses"`
	} `json:"scenarios"`
	Modules []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Use     string `json:"use"`
	} `json:"modules"`
	Adapters struct {
		Product    []string `json:"product"`
		Composites []string `json:"composites_over_them"`
	} `json:"adapters"`
	Generators []string `json:"generators"`
}

var (
	retirementOnce   sync.Once
	retirementParsed RetirementManifest
)

// Retirement returns the embedded retirement manifest. The manifest is
// part of the build: a copy that does not parse is a broken binary, which
// TestRetirementManifestIsEmbedded refuses before one is ever made.
func Retirement() RetirementManifest {
	retirementOnce.Do(func() {
		if err := json.Unmarshal(retirementManifest, &retirementParsed); err != nil {
			panic("embedded hack/retirement.json: " + err.Error())
		}
	})
	return retirementParsed
}

// RetirementManifestBytes is the embedded manifest as it is in the tree.
func RetirementManifestBytes() []byte { return append([]byte(nil), retirementManifest...) }

// Template reports whether name is a retired template (scenario).
func (m RetirementManifest) Template(name string) bool {
	for _, s := range m.Scenarios {
		if s.Name == name {
			return true
		}
	}
	return false
}

// Catalog splits installed template names into the ones a surface may
// offer and the ones the manifest lists, each in the order given. It is
// the catalog filter of the reconciliation plan's R3: an earlier build
// may have left a retired template in <state>/catalog/, where it stays —
// nothing deletes it — but every surface that offers templates reads
// through this, so it is never offered, and the surface says once that
// it is present and unsupported (PDR-W103).
func (m RetirementManifest) Catalog(names []string) (offered, retired []string) {
	for _, n := range names {
		if m.Template(n) {
			retired = append(retired, n)
		} else {
			offered = append(offered, n)
		}
	}
	return offered, retired
}

// Module reports whether name is a retired module.
func (m RetirementManifest) Module(name string) bool {
	for _, x := range m.Modules {
		if x.Name == name {
			return true
		}
	}
	return false
}

// Adapter reports whether name is a retired checkpoint adapter — a
// product adapter or a composite over them — and which role it had.
func (m RetirementManifest) Adapter(name string) (role string, retired bool) {
	for _, a := range m.Adapters.Product {
		if a == name {
			return "a product adapter", true
		}
	}
	for _, a := range m.Adapters.Composites {
		if a == name {
			return "a composite adapter over the retired product adapters", true
		}
	}
	return "", false
}

// Generator reports whether name is a retired seed generator.
func (m RetirementManifest) Generator(name string) bool {
	for _, g := range m.Generators {
		if g == name {
			return true
		}
	}
	return false
}
