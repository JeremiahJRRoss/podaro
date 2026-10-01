// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// legal.source_url (User Manual §4; the reconciliation plan's R5): the
// operator's statement of where the source of the build they run is
// published. It is printed on the public /legal page, so it is a plain
// http(s) location — no credential, no query, no fragment — and it is
// the one key of its block.
func TestLegalSourceURL(t *testing.T) {
	cfg, err := Load(write(t, "legal:\n  source_url: https://git.example.com/fork/podaro\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Legal == nil || cfg.Legal.SourceURL != "https://git.example.com/fork/podaro" {
		t.Fatalf("legal = %+v", cfg.Legal)
	}
	if cfg, err := Load(write(t, "domain: lab.example.com\n")); err != nil || cfg.Legal != nil {
		t.Fatalf("no legal block: %+v %v", cfg, err)
	}
	for _, bad := range []struct{ yaml, says string }{
		{"legal: {}\n", "required"},
		{"legal:\n  source_url: ftp://git.example.com/podaro\n", "not an http(s) URL"},
		{"legal:\n  source_url: https://user:secret@git.example.com/podaro\n", "carries userinfo"},
		{"legal:\n  source_url: https://git.example.com/podaro?ref=main\n", "no query"},
		{"legal:\n  source_url: https://git.example.com/podaro#readme\n", "no query"},
	} {
		_, err := Load(write(t, bad.yaml))
		e := asPDR(t, err, pdr.CodeConfigInvalid)
		if !strings.Contains(e.Message, "legal.source_url") || !strings.Contains(e.Message, bad.says) {
			t.Errorf("%q: %s", bad.yaml, e.Message)
		}
		if strings.Contains(e.Message, "secret") {
			t.Errorf("the refusal repeats the credential: %s", e.Message)
		}
	}
	_, err = Load(write(t, "legal:\n  source_url: https://git.example.com/podaro\n  mirror: https://x.example\n"))
	asPDR(t, err, pdr.CodeConfigUnknownKey)
}
