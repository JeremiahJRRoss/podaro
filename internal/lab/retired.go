// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// The retired-name rule (PDR-E106; spec 0001 §11, spec 0003 §13). The
// owner retired a lab on 2026-09-23 together with the adapters, generators
// and modules that existed only for it (ADR-0004 D9). A manifest that
// names one fails validation — under v1alpha1 and v1alpha2 alike, before
// any plan or pull — with a finding that names the identifier, the record
// that retired it and the migration, instead of the "unknown name" a
// reduced registry would otherwise answer.
//
// The names come from the retirement manifest the binary embeds
// (podaro.Retirement(), hack/retirement.json), never from a table here:
// the compiled engine spells none of them (the reconciliation plan's Q-R5).
// A name is judged before any library or alias lookup, so a module
// library or a module alias that reuses a retired name is refused too.

// retirementRecord is how a finding cites the retirement.
func retirementRecord(role string) string {
	m := podaro.Retirement()
	return "retired by the owner on " + m.RetiredOn + " as " + role + " (the retirement manifest, hack/retirement.json; ADR-0004 D9)"
}

// retiredAdapter reports a retired checkpoint adapter at ptr.
func (v *validation) retiredAdapter(doc *Document, name string, ptr ...string) bool {
	role, retired := podaro.Retirement().Adapter(name)
	if !retired {
		return false
	}
	v.fail(pdr.CodeLabRetired, RuleRetired, doc.Loc(ptr...),
		"adapter %q is %s — remove the checkpoint, or judge it with http, container or an exec adapter of your own (spec 0001 §11)",
		name, retirementRecord(role))
	return true
}

// retiredGenerator reports a retired seed generator at ptr.
func (v *validation) retiredGenerator(doc *Document, name string, ptr ...string) bool {
	if !podaro.Retirement().Generator(name) {
		return false
	}
	v.fail(pdr.CodeLabRetired, RuleRetired, doc.Loc(ptr...),
		"generator %q is %s — remove the seed, or generate with web-logs, http-requests or an exec generator of your own (spec 0001 §11)",
		name, retirementRecord("a seed generator"))
	return true
}

// retiredModule reports a retired module named by a service's use: at ptr
// in the template.
func (v *validation) retiredModule(name, use string, ptr ...string) bool {
	if !podaro.Retirement().Module(name) {
		return false
	}
	v.fail(pdr.CodeLabRetired, RuleRetired, v.doc.Loc(ptr...),
		"%s: module %q is %s — remove the service and the checkpoints that judge it, or bring an image of your own as an inline service pinned by digest (spec 0003 §3, §13)",
		use, name, retirementRecord("a module"))
	return true
}
