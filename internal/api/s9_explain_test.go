// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// Plan S9, API §5: `GET /system/errors/{code}` expands a code from the
// embedded registry — the same answer `podaro explain` prints, for the
// clients that are not the CLI. It reads no state and touches no
// instance, so it answers while the engine is otherwise unwell.
func TestErrorHelpExpandsACodeFromTheEmbeddedRegistry(t *testing.T) {
	srv, _ := newServer(t)
	code, out := call(t, srv, http.MethodGet, "/system/errors/PDR-E503", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /system/errors/PDR-E503: %d %v", code, out)
	}
	help, _ := out["error_help"].(map[string]any)
	entry, _ := pdr.Lookup(pdr.CodeExecTimeout)
	if help["code"] != entry.Code || help["title"] != entry.Title || help["cause"] != entry.Cause || help["next"] != entry.Next {
		t.Fatalf("the endpoint and the registry disagree: %v", help)
	}
	// The same code, spelled the way an operator types it.
	if code, _ := call(t, srv, http.MethodGet, "/system/errors/e503", nil); code != http.StatusOK {
		t.Fatalf("GET /system/errors/e503: %d", code)
	}
	code, out = call(t, srv, http.MethodGet, "/system/errors/PDR-E999", nil)
	if code != http.StatusNotFound {
		t.Fatalf("an unregistered code is 404, got %d %v", code, out)
	}
	e, _ := out["error"].(map[string]any)
	if e["code"] != pdr.CodeExplainUnknown {
		t.Fatalf("the refusal carries its own code: %v", e)
	}
}
