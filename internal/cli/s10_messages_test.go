// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Plan S10, the drift audit, made executable: every `podaro …` command a
// message names has to exist.
//
// An error's `next` is an action (User Manual §14, UX §6: "next, as a real
// button or copyable command"), and a message telling an operator to run
// something the binary does not have is a dead end at the moment they are
// most stuck. The scan reads the string literals of every non-test source
// file, finds each `podaro ` in them, and resolves the words that follow
// against the real command tree — the same tree `Execute` runs — checking
// that the command exists, that it is runnable rather than a bare group,
// and that every flag named on it is one it accepts.
//
// It found `podaro system shows what it serves` (setup's rollback line,
// internal/system/setup.go) — `system` is a group with nothing to run, and
// nothing in the CLI prints what the gateway serves. The message now
// points at the journal, where the engine logs its gateway posture at
// every start. The same scan would have caught the `--check` flag the
// manual promised on `doctor` and the binary never had.
func TestEveryCommandAMessageNamesExists(t *testing.T) {
	root := newRoot()
	fset := token.NewFileSet()
	type mention struct {
		file, text string
	}
	var mentions []mention
	repo := filepath.Join("..", "..")
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(repo, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Fatalf("parsing %s: %v", path, perr)
			}
			rel, _ := filepath.Rel(repo, path)
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				text, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					return true
				}
				for _, m := range commandMentions(text) {
					mentions = append(mentions, mention{file: rel, text: m})
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}
	if len(mentions) < 20 {
		t.Fatalf("the scan found only %d command mentions; it is not reading the tree", len(mentions))
	}

	var problems []string
	for _, m := range mentions {
		if prose[m.file+": "+m.text] {
			continue
		}
		if why := resolves(root, m.text); why != "" {
			problems = append(problems, m.file+": \"podaro "+m.text+"\" — "+why)
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		t.Fatalf("messages naming commands this binary does not have:\n  %s", strings.Join(problems, "\n  "))
	}
}

// prose is the short list of strings where "podaro" is the product's name
// rather than a command to run — each one written out in full, so changing
// the sentence brings it back to this test's attention. Nothing here is a
// next action; nothing here asks an operator to type anything.
var prose = map[string]bool{
	// `podaro.service` is the systemd unit; this is its own summary line.
	"internal/cli/system.go: service": true,
	// A remediation about *who* runs the binary, not about a subcommand.
	"internal/doctor/doctor.go: as your own user with rootless Podman configured": true,
	// The fake runtime's label on a container record.
	"internal/runtime/logs.go: fake runtime": true,
	// The engine's own journal lines at start and stop; `--user` in the
	// registry entry belongs to systemd.
	"internal/system/serve.go: engine v%s":                               true,
	"internal/system/serve.go: engine stopped":                           true,
	"internal/system/serve.go: engine stop: %v":                          true,
	"internal/pdr/pdr.go: system install and managed by systemd --user.": true,
}

// commandMentions pulls each `podaro …` invocation out of one string. A
// mention ends where the sentence does: the separators the CLI's own
// messages use to chain actions (`·`), and the punctuation that ends a
// clause.
func commandMentions(text string) []string {
	var out []string
	rest := text
	for {
		i := strings.Index(rest, "podaro ")
		if i < 0 {
			return out
		}
		// `podaro` has to start a word: not `pdr-podaro `, not a path.
		if i > 0 && !strings.ContainsRune(" \t\n(:>`'\"", rune(rest[i-1])) {
			rest = rest[i+len("podaro "):]
			continue
		}
		rest = rest[i+len("podaro "):]
		end := strings.IndexAny(rest, "·;,()\n\t\"`")
		clause := rest
		if end >= 0 {
			clause = rest[:end]
		}
		if fields := strings.Fields(clause); len(fields) > 0 {
			out = append(out, strings.Join(fields, " "))
		}
	}
}

// resolves walks a mention's words down the command tree and reports why
// it does not resolve, or "" when it does. Words after the deepest
// command are prose (`podaro up again to resume`) and are not checked —
// except flags, which are.
func resolves(root *cobra.Command, mention string) string {
	words := strings.Fields(mention)
	cmd := root
	var path []string
	for _, w := range words {
		if strings.HasPrefix(w, "-") {
			break
		}
		child := childNamed(cmd, w)
		if child == nil {
			break
		}
		cmd, path = child, append(path, w)
	}
	if len(path) == 0 {
		// Not a command mention at all (`podaro is running`, a hostname,
		// a prose sentence) unless the first word looks like one.
		if strings.HasPrefix(words[0], "-") {
			return flagProblem(root, words)
		}
		if looksLikeCommand(words[0]) {
			return "no such command: " + words[0]
		}
		return ""
	}
	if cmd.Runnable() {
		return flagProblem(cmd, words[len(path):])
	}
	// A group with nothing to run: naming it as an action is naming
	// nothing. `podaro auth` alone is a group reference, not an action, so
	// only a mention that carries further words is a problem.
	if len(words) > len(path) {
		return "podaro " + strings.Join(path, " ") + " is a command group with nothing to run"
	}
	return ""
}

// looksLikeCommand keeps prose out of the report: a word with a space
// after `podaro ` that is lowercase and not obviously English punctuation
// is only reported when it reads like a command — one word, letters and
// hyphens, and not a known prose opener.
func looksLikeCommand(word string) bool {
	if word == "" || strings.ContainsAny(word, "/.:=<>@") {
		return false
	}
	for _, r := range word {
		if !(r >= 'a' && r <= 'z') && r != '-' {
			return false
		}
	}
	switch word {
	// English openers, and `v` — `podaro v0.1.0` is the version line, not
	// a command (internal/cli/version.go, internal/system/upgrade.go).
	case "is", "and", "or", "the", "a", "an", "to", "will", "never", "only", "v":
		return false
	}
	return true
}

// flagProblem checks the flags a mention names against the command it
// named — `--check` on `doctor` is how a manual promise becomes a dead
// end.
func flagProblem(cmd *cobra.Command, words []string) string {
	for _, w := range words {
		if !strings.HasPrefix(w, "--") {
			continue
		}
		name := strings.TrimPrefix(w, "--")
		if i := strings.IndexAny(name, "=<"); i >= 0 {
			name = name[:i]
		}
		name = strings.Trim(name, ".…")
		if name == "" {
			continue
		}
		if cmd.Flags().Lookup(name) == nil && cmd.InheritedFlags().Lookup(name) == nil && cmd.PersistentFlags().Lookup(name) == nil {
			return "no such flag --" + name + " on " + cmd.CommandPath()
		}
	}
	return ""
}

func childNamed(cmd *cobra.Command, name string) *cobra.Command {
	for _, c := range cmd.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}
