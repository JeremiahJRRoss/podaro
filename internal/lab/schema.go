// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	podaro "github.com/jeremiahjrross/podaro"
)

// The manifest versions the engine reads (docs/DEVELOPMENT_PLAN_RECONCILIATION.md
// D-R2): v1alpha2 is the current contract — what `lab init` scaffolds and
// the catalog ships — and v1alpha1 is frozen history, still read, so a
// document that names nothing retired means the same under either. A
// retired adapter, generator or module fails validation under both
// (PDR-E106, retired.go).
const (
	APIVersionV1alpha1 = "lab.podaro.dev/v1alpha1"
	APIVersionV1alpha2 = "lab.podaro.dev/v1alpha2"
	// APIVersion is the version the engine writes.
	APIVersion = APIVersionV1alpha2
)

// The kinds a schema describes; a schema is chosen by kind and version.
const (
	KindTemplate   = "template"
	KindModule     = "module"
	KindPlaybook   = "playbook"
	KindCheckpoint = "checkpoint"
)

// The schema ids (schemas/*.json `$id`). The template schema's id is
// …/lab/… by Manual §11's normative header line (spec 0003 status). The
// unversioned names are the current contract's.
const (
	SchemaTemplate   = "https://schemas.podaro.dev/lab/v1alpha2.json"
	SchemaModule     = "https://schemas.podaro.dev/module/v1alpha2.json"
	SchemaPlaybook   = "https://schemas.podaro.dev/playbook/v1alpha2.json"
	SchemaCheckpoint = "https://schemas.podaro.dev/checkpoint/v1alpha2.json"

	SchemaTemplateV1alpha1   = "https://schemas.podaro.dev/lab/v1alpha1.json"
	SchemaModuleV1alpha1     = "https://schemas.podaro.dev/module/v1alpha1.json"
	SchemaPlaybookV1alpha1   = "https://schemas.podaro.dev/playbook/v1alpha1.json"
	SchemaCheckpointV1alpha1 = "https://schemas.podaro.dev/checkpoint/v1alpha1.json"
)

var schemaFiles = map[string]string{
	SchemaTemplate:   "template.v1alpha2.json",
	SchemaModule:     "module.v1alpha2.json",
	SchemaPlaybook:   "playbook.v1alpha2.json",
	SchemaCheckpoint: "checkpoint.v1alpha2.json",

	SchemaTemplateV1alpha1:   "template.v1alpha1.json",
	SchemaModuleV1alpha1:     "module.v1alpha1.json",
	SchemaPlaybookV1alpha1:   "playbook.v1alpha1.json",
	SchemaCheckpointV1alpha1: "checkpoint.v1alpha1.json",
}

var schemaIDs = map[string]map[string]string{
	APIVersionV1alpha2: {KindTemplate: SchemaTemplate, KindModule: SchemaModule, KindPlaybook: SchemaPlaybook, KindCheckpoint: SchemaCheckpoint},
	APIVersionV1alpha1: {KindTemplate: SchemaTemplateV1alpha1, KindModule: SchemaModuleV1alpha1, KindPlaybook: SchemaPlaybookV1alpha1, KindCheckpoint: SchemaCheckpointV1alpha1},
}

// schemaFor chooses the schema a document is validated against: its kind,
// and the version its own apiVersion declares, read before any schema
// runs. A document that declares neither version — or no apiVersion at
// all — is judged by the current contract, whose const names the version
// it expects.
func schemaFor(kind string, value any) string {
	if m, ok := value.(map[string]any); ok {
		if v, ok := m["apiVersion"].(string); ok {
			if ids, ok := schemaIDs[v]; ok {
				return ids[kind]
			}
		}
	}
	return schemaIDs[APIVersion][kind]
}

var (
	schemaOnce sync.Once
	schemaSet  map[string]*jsonschema.Schema
	schemaErr  error
)

// compileSchemas registers the eight embedded schemas under their `$id`s
// so the sibling-relative cross-file $refs (`../checkpoint/v1alpha2.json`,
// and v1alpha1's to its own siblings) resolve exactly as spec 0001's
// 2026-08-10 housekeeping note intends: each version refers only to its
// own set.
func compileSchemas() (map[string]*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		c := jsonschema.NewCompiler()
		for id, name := range schemaFiles {
			f, err := podaro.Schemas().Open(name)
			if err != nil {
				schemaErr = fmt.Errorf("embedded schema %s: %w", name, err)
				return
			}
			doc, err := jsonschema.UnmarshalJSON(f)
			f.Close()
			if err != nil {
				schemaErr = fmt.Errorf("embedded schema %s: %w", name, err)
				return
			}
			if err := c.AddResource(id, doc); err != nil {
				schemaErr = fmt.Errorf("embedded schema %s: %w", name, err)
				return
			}
		}
		set := make(map[string]*jsonschema.Schema, len(schemaFiles))
		for id := range schemaFiles {
			s, err := c.Compile(id)
			if err != nil {
				schemaErr = fmt.Errorf("compile %s: %w", id, err)
				return
			}
			set[id] = s
		}
		schemaSet = set
	})
	return schemaSet, schemaErr
}

// schemaViolation is one leaf schema error at an instance location.
type schemaViolation struct {
	Pointer []string
	Message string
}

// schemaViolations validates v against the schema id and returns the leaf
// violations, ordered by instance location then message, deduplicated.
func schemaViolations(id string, v any) ([]schemaViolation, error) {
	set, err := compileSchemas()
	if err != nil {
		return nil, err
	}
	err = set[id].Validate(v)
	if err == nil {
		return nil, nil
	}
	ve, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return nil, err
	}
	seen := map[string]bool{}
	var out []schemaViolation
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) > 0 {
			for _, c := range e.Causes {
				walk(c)
			}
			return
		}
		msg := e.ErrorKind.LocalizedString(englishPrinter)
		key := strings.Join(e.InstanceLocation, "/") + "\x00" + msg
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, schemaViolation{Pointer: append([]string(nil), e.InstanceLocation...), Message: msg})
	}
	walk(ve)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := strings.Join(out[i].Pointer, "/"), strings.Join(out[j].Pointer, "/")
		if a != b {
			return a < b
		}
		return out[i].Message < out[j].Message
	})
	return out, nil
}

// englishPrinter renders the library's messages; Podaro speaks one voice.
var englishPrinter = message.NewPrinter(language.English)
