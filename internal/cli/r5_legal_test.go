// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/legal"
)

const (
	formulation1 = "Copyright © 2026 Jeremiah Ross, to the extent copyright subsists in first-party material and such copyright is owned by Jeremiah Ross. No copyright is claimed in AI-generated material that is not eligible for copyright protection under applicable law."
	formulation2 = "To the extent copyright subsists, copyrightable first-party material owned by Jeremiah Ross is licensed under AGPL-3.0-only."
)

func legalHome(t *testing.T) (configDir, stateDir string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	return filepath.Join(root, "config", "podaro"), filepath.Join(root, "state", "podaro")
}

// `podaro legal` (the reconciliation plan's R5, task 3): offline, from the
// binary — the product and version, AGPL-3.0-only, NOTICE's two
// statements verbatim, the offer of this build's source, where releases
// are published and how to verify one, the name policy, the third-party
// components, and where the files are.
func TestLegalPrintsTheLicenceAndTheSourceOffer(t *testing.T) {
	legalHome(t)
	code, out, errOut := run(t, "legal")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	squashed := strings.Join(strings.Fields(out), " ")
	for _, want := range []string{
		"v" + podaro.Version() + " — licence and source",
		"AGPL-3.0-only",
		formulation1,
		formulation2,
		podaro.SourceURL(),
		"sha256sum --ignore-missing -c SHA256SUMS",
		"TRADEMARKS.md",
		"github.com/spf13/cobra v1.10.2 · Apache-2.0",
		"podaro system install writes them to",
		"podaro legal --licenses",
	} {
		if !strings.Contains(squashed, want) {
			t.Errorf("podaro legal printed no %q", want)
		}
	}
	if legal.Unreleased(podaro.Version()) && !strings.Contains(out, "obtain its source from whoever gave you this binary") {
		t.Error("an unreleased build's offer is missing")
	}
	// Assembled at run time, so this file spells none of the forms the
	// reconciliation's checks look for (hack/spdx_check_test.sh does the same).
	for _, bad := range []string{"All rights" + " reserved", "\u00ae", "registered" + " trademark"} {
		if strings.Contains(out, bad) {
			t.Errorf("podaro legal carries %q", bad)
		}
	}
}

// --json is the same summary as data (GET /system/legal's shape), and the
// operator's legal.source_url rides beside the build's own offer.
func TestLegalJSONCarriesTheOperatorsStatement(t *testing.T) {
	cfgDir, _ := legalHome(t)
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.yaml"), []byte("legal:\n  source_url: https://git.example.com/fork/podaro\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := run(t, "legal", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var got struct {
		Legal legal.Info `json:"legal"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got.Legal.Copyright != formulation1 || got.Legal.Licensing != formulation2 || got.Legal.License != "AGPL-3.0-only" {
		t.Errorf("the statements: %+v", got.Legal)
	}
	if got.Legal.Source.Operator != "https://git.example.com/fork/podaro" || got.Legal.Source.Repository != podaro.SourceURL() || got.Legal.Source.Offer == "" {
		t.Errorf("the source offer: %+v", got.Legal.Source)
	}
	code, out, _ = run(t, "legal")
	if code != 0 || !strings.Contains(out, "the operator of this installation says the source of the build it runs is at https://git.example.com/fork/podaro") {
		t.Errorf("the operator's statement is not printed:\n%s", out)
	}
}

// A configuration that cannot be read does not stop the command — the
// binary's own licence and offer are what it prints — but stderr says the
// operator's statement is not shown.
func TestLegalAnswersWithABrokenConfiguration(t *testing.T) {
	cfgDir, _ := legalHome(t)
	_ = os.MkdirAll(cfgDir, 0o700)
	_ = os.WriteFile(filepath.Join(cfgDir, "config.yaml"), []byte("flavour: mint\n"), 0o600)
	code, out, errOut := run(t, "legal")
	if code != 0 || !strings.Contains(out, "AGPL-3.0-only") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(errOut, "config.yaml could not be read (PDR-E011)") {
		t.Errorf("stderr does not say the configuration was unreadable: %q", errOut)
	}
}

// --licenses prints every licence and notice text the binary carries: the
// AGPL first, NOTICE, the Apache-2.0 text the Go modules carry, and the
// third-party notices, which hold the fonts' OFL; --json the same as data.
func TestLegalLicensesPrintsEveryText(t *testing.T) {
	legalHome(t)
	code, out, errOut := run(t, "legal", "--licenses")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"==> LICENSE <==", "GNU AFFERO GENERAL PUBLIC LICENSE", "==> NOTICE <==",
		"==> LICENSES/Apache-2.0.txt <==", "Apache License", "==> THIRD-PARTY-NOTICES.md <==", "SIL OPEN FONT LICENSE"} {
		if !strings.Contains(out, want) {
			t.Errorf("podaro legal --licenses printed no %q", want)
		}
	}
	code, out, _ = run(t, "legal", "--licenses", "--json")
	var got struct {
		Licenses []legal.Text `json:"licenses"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &got) != nil || len(got.Licenses) != 4 || got.Licenses[0].Name != "LICENSE" {
		t.Fatalf("--licenses --json: exit %d, %d texts\n%.200s", code, len(got.Licenses), out)
	}
}

// Once `system install` wrote <state>/legal/, the summary says where the
// files are instead of how to get them.
func TestLegalNamesTheFilesOnDisk(t *testing.T) {
	_, stateDir := legalHome(t)
	if err := legal.WriteDir(filepath.Join(stateDir, "legal")); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "legal")
	if code != 0 || !strings.Contains(out, "as files in ") || !strings.Contains(out, filepath.Join("state", "podaro", "legal")+"/") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}
