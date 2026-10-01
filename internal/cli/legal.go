// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/legal"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// legalColumn is `podaro legal`'s label column: the explanation's layout
// (UX §7), wide enough for its longest label.
const legalColumn = 14

// newLegal builds `podaro legal` (the reconciliation §7.2; the
// reconciliation plan's R5, task 3): the licence, the owner's two
// statements, the offer of this binary's exact source, where releases are
// published and how to verify one, the name policy, and the third-party
// components — read from the files inside this binary, like `explain`
// from its registry, so it answers with no engine, no socket and no
// network. `--licenses` prints every licence and notice text the binary
// carries; `--json` the same as data. The console's /legal page is the
// same summary for anyone who can reach the gateway.
func newLegal() *cobra.Command {
	licenses := false
	cmd := &cobra.Command{
		Use:   "legal",
		Short: "the licence, the notices and the offer of this binary's source, offline",
		Long: "Print the licence Podaro is under, the project's copyright and licensing statements, " +
			"the offer of the exact source of this binary, where releases are published and how to " +
			"verify one, the policy for the name, and the third-party components it carries — all read " +
			"from the binary itself, with no engine and no network. --licenses prints every licence " +
			"and notice text the binary carries.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if licenses {
				texts, err := legal.Texts()
				if err != nil {
					return legalBroken(err)
				}
				if jsonOut {
					return json.NewEncoder(os.Stdout).Encode(map[string]any{"licenses": texts})
				}
				for i, x := range texts {
					if i > 0 {
						fmt.Println()
					}
					fmt.Printf("==> %s <==\n", x.Name)
					fmt.Print(strings.TrimRight(x.Text, "\n") + "\n")
				}
				return nil
			}
			info, err := legal.Build(operatorSourceURL())
			if err != nil {
				return legalBroken(err)
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"legal": info})
			}
			renderLegal(render.Detect(os.Stdout), info)
			return nil
		},
	}
	cmd.Flags().BoolVar(&licenses, "licenses", false, "print every licence and notice text the binary carries")
	return cmd
}

// operatorSourceURL is config.yaml's legal.source_url. A configuration
// that cannot be read does not stop the command — the binary's own
// licence and source offer are what it prints — but it says, on stderr,
// that the operator's statement could not be read.
func operatorSourceURL() string {
	cfg, err := config.Load(config.Path())
	if err != nil {
		code := ""
		var pe *pdr.Error
		if errors.As(err, &pe) {
			code = " (" + pe.Code + ")"
		}
		fmt.Fprintf(os.Stderr, "! config.yaml could not be read%s: the operator's legal.source_url is not shown\n", code)
		return ""
	}
	if cfg == nil || cfg.Legal == nil {
		return ""
	}
	return cfg.Legal.SourceURL
}

func renderLegal(p *render.Printer, info legal.Info) {
	p.Plain(fmt.Sprintf("%s v%s — licence and source", info.Product, info.Version))
	p.Blank()
	row := func(label, value string) { p.Indent(label, legalColumn, value) }
	row("licence", info.License+" · "+info.LicenseText)
	row("copyright", info.Copyright)
	row("licensing", info.Licensing)
	row("source", info.Source.Offer)
	if info.Source.Operator != "" {
		row("operator", "the operator of this installation says the source of the build it runs is at "+info.Source.Operator)
	}
	row("repository", info.Source.Repository)
	row("releases", info.Releases.Verify)
	row("the name", info.Trademarks)
	for i, c := range info.ThirdParty {
		label := ""
		if i == 0 {
			label = "third party"
		}
		name := c.Name
		if c.Version != "" {
			name += " " + c.Version
		}
		row(label, name+" · "+c.License+" · "+c.How)
	}
	files := strings.Join(info.Files, " · ") + " — inside this binary"
	dir := filepath.Join(config.StateDir(), "legal")
	if _, err := os.Stat(filepath.Join(dir, "LICENSE")); err == nil {
		files += "; as files in " + tildify(dir) + "/"
	} else {
		files += "; podaro system install writes them to " + tildify(dir) + "/"
	}
	row("files", files)
	p.Blank()
	p.NextAction("podaro legal --licenses   (every licence and notice text)")
}

// legalBroken is the answer when the legal files inside the binary cannot
// be read — a build the tests would have refused; said as an engine fault
// rather than printed as an empty licence.
func legalBroken(err error) error {
	e := pdr.New(pdr.CodeRuntimeFailed, "the legal files inside this binary could not be read")
	e.Cause = err.Error()
	e.Next = "the files are LICENSE, NOTICE and THIRD-PARTY-NOTICES.md beside the release's binary, and at the source the release names"
	return e
}
