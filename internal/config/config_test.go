// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func asPDR(t *testing.T, err error, code string) *pdr.Error {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	e, ok := err.(*pdr.Error)
	if !ok {
		t.Fatalf("error is %T, want *pdr.Error: %v", err, err)
	}
	if e.Code != code {
		t.Fatalf("code = %s, want %s (%v)", e.Code, code, e)
	}
	return e
}

func TestMissingFileIsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Exists || cfg.Gateway.Port != DefaultGatewayPort {
		t.Fatalf("defaults wrong: %+v", cfg)
	}
}

// The S1 acceptance item: an unknown key fails with file:line.
func TestUnknownKeyFailsWithFileLine(t *testing.T) {
	path := write(t, "domain: lab.example.com\nobservabilty:\n  logs: {}\n")
	_, err := Load(path)
	e := asPDR(t, err, pdr.CodeConfigUnknownKey)
	if want := path + ":2"; !strings.Contains(e.Message, want) {
		t.Fatalf("message %q lacks file:line %q", e.Message, want)
	}
	if !strings.Contains(e.Message, `"observabilty"`) {
		t.Fatalf("message %q does not name the key", e.Message)
	}
}

func TestValidFullConfig(t *testing.T) {
	token := filepath.Join(t.TempDir(), "hec.token")
	if err := os.WriteFile(token, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(write(t, `
domain: lab.example.com
gateway: { port: 8443 }
observability:
  logs:    { exporter: hec,  endpoint: https://splunk.corp:8088, token_file: `+token+` }
  metrics: { exporter: otlp, endpoint: https://otel.corp:4318 }
  traces:  { exporter: otlp, endpoint: https://otel.corp:4318 }
  attributes: { host: lab-01 }
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Observability.Logs.Exporter != "hec" || cfg.Domain != "lab.example.com" {
		t.Fatalf("parsed wrong: %+v", cfg)
	}
}

func TestTracesAreOTLPOnly(t *testing.T) {
	_, err := Load(write(t, "observability:\n  traces: { exporter: http, endpoint: https://x.example:1 }\n"))
	e := asPDR(t, err, pdr.CodeConfigInvalid)
	if !strings.Contains(e.Message, "OTLP-only") {
		t.Fatalf("message %q should say traces are OTLP-only", e.Message)
	}
}

func TestHECRequiresTokenFile(t *testing.T) {
	_, err := Load(write(t, "observability:\n  logs: { exporter: hec, endpoint: https://splunk.corp:8088 }\n"))
	e := asPDR(t, err, pdr.CodeConfigInvalid)
	if !strings.Contains(e.Message, "token_file") {
		t.Fatalf("message %q should require token_file", e.Message)
	}
}

func TestTokenFileMustBe0600(t *testing.T) {
	token := filepath.Join(t.TempDir(), "hec.token")
	if err := os.WriteFile(token, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(write(t, "observability:\n  logs: { exporter: hec, endpoint: https://splunk.corp:8088, token_file: "+token+" }\n"))
	e := asPDR(t, err, pdr.CodeConfigInvalid)
	if !strings.Contains(e.Message, "0600") {
		t.Fatalf("message %q should demand 0600", e.Message)
	}
}

func TestBadPort(t *testing.T) {
	_, err := Load(write(t, "gateway: { port: 70000 }\n"))
	asPDR(t, err, pdr.CodeConfigInvalid)
}

// An explicit zero must be rejected, not silently defaulted.
func TestExplicitZeroPortRejected(t *testing.T) {
	_, err := Load(write(t, "gateway: { port: 0 }\n"))
	e := asPDR(t, err, pdr.CodeConfigInvalid)
	if !strings.Contains(e.Message, "gateway.port") {
		t.Fatalf("message %q should name gateway.port", e.Message)
	}
}

// A second YAML document would be silently ignored by a single Decode —
// strictness covers the whole file.
func TestMultiDocumentRejected(t *testing.T) {
	_, err := Load(write(t, "domain: lab.example.com\n---\nobservabilty: { }\n"))
	e := asPDR(t, err, pdr.CodeConfigUnreadable)
	if !strings.Contains(e.Message, "multiple YAML documents") {
		t.Fatalf("message %q should reject multi-document files", e.Message)
	}
}

func TestBadYAML(t *testing.T) {
	_, err := Load(write(t, "domain: [unclosed\n"))
	asPDR(t, err, pdr.CodeConfigUnreadable)
}
