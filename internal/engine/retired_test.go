// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// `up <name>` of a template the retirement manifest lists is PDR-E107,
// refused before the catalog is read or anything validated — even when an
// earlier build left a directory of that name in the catalog, and even when
// what sits there would validate. The refusal offers the rest of the
// catalog, never the retired name. The name is read from the embedded
// manifest, so this test spells none.
func TestARetiredTemplateIsRefusedByName(t *testing.T) {
	m := podaro.Retirement()
	if len(m.Scenarios) == 0 {
		t.Fatal("the embedded manifest lists no retired template")
	}
	retired := m.Scenarios[0].Name
	h := newHarness(t)
	catalog := t.TempDir()
	for _, name := range []string{retired, "hello-nginx"} {
		if err := copyTree(fixture, filepath.Join(catalog, name)); err != nil {
			t.Fatal(err)
		}
	}
	h.eng.opts.CatalogDir = catalog
	_, err := h.eng.Create(context.Background(), CreateRequest{Template: retired, Name: "old"})
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != pdr.CodeTemplateRetired {
		t.Fatalf("up of a retired template: %v, want %s", err, pdr.CodeTemplateRetired)
	}
	if !strings.Contains(pe.Message, "retired by the owner on "+m.RetiredOn) {
		t.Errorf("the refusal does not say who retired it and when: %q", pe.Message)
	}
	if !strings.Contains(pe.Cause, "podaro explain "+pdr.CodeTemplateRetired) || !strings.Contains(pe.Cause, "hello-nginx") || strings.Contains(pe.Cause, retired) {
		t.Errorf("the cause must name the explain entry and offer only the rest of the catalog: %q", pe.Cause)
	}
	if list, _ := h.store.ListInstances(); len(list) != 0 {
		t.Errorf("a refused up left instances behind: %v", list)
	}
	if _, ok := pdr.Lookup(pdr.CodeTemplateRetired); !ok {
		t.Errorf("%s has no explain entry", pdr.CodeTemplateRetired)
	}
}
