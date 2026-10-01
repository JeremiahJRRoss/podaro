// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/client"
	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
	"github.com/jeremiahjrross/podaro/internal/state"
	"github.com/jeremiahjrross/podaro/internal/system"
)

// The instance lifecycle commands (User Manual §8): up, status, destroy —
// all clients of the engine's local socket door (API §1), rendering the
// ladder exactly as UX §5 lays it out.

func socketPath() string { return filepath.Join(config.RuntimeDir(), "api.sock") }

func newClient() *client.Client { return client.New(socketPath()) }

func newUp() *cobra.Command {
	var (
		name, profile, mode string
		accept              []string
		yes                 bool
	)
	cmd := &cobra.Command{
		Use:   "up <template|dir>",
		Short: "create an instance and climb the ladder, streaming progress",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := engine.CreateRequest{Name: name, Profile: profile, Mode: mode, AcceptLicenses: accept}
			var err error
			if req.Path, req.Template, err = sourceOf(args[0]); err != nil {
				return err
			}
			c := newClient()
			ctx := context.Background()
			job, err := c.Create(ctx, req)
			if err != nil {
				var pe *pdr.Error
				if errors.As(err, &pe) && pe.Code == pdr.CodeLicenseRequired && !jsonOut && !yes && isTerminal(os.Stdin) {
					// API §6.2: interactive acceptance, never defaulted — and
					// never a reflex. The terms are a vendor's, for proprietary
					// software, so each is accepted by typing its id, the way
					// destroy takes the instance's name; a bare Enter, a "y" or
					// a typo stops the create with nothing pulled.
					in := bufio.NewReader(os.Stdin)
					for _, d := range pe.Details {
						fmt.Printf("%s requires acceptance of %s\n  %s\n", args[0], d.License, d.URL)
						fmt.Println("  These are a vendor's own terms for proprietary software. Accept only if you are permitted to use it.")
						fmt.Printf("type %s to accept, anything else to stop: ", d.License)
						line, _ := in.ReadString('\n')
						if strings.TrimSpace(line) != d.License {
							return pe
						}
						req.AcceptLicenses = append(req.AcceptLicenses, d.License)
					}
					job, err = c.Create(ctx, req)
				}
				if err != nil {
					return jsonOrErr(err, 1)
				}
			}
			final, err := followJob(ctx, c, job, os.Stdout)
			if err != nil {
				return jsonOrErr(err, 1)
			}
			if final.State != state.JobSucceeded {
				return jobFailure(final)
			}
			if jsonOut {
				v, err := c.Instance(ctx, job.Instance)
				if err != nil {
					return jsonOrErr(err, 1)
				}
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"instance": v, "job": final})
			}
			v, err := c.Instance(ctx, job.Instance)
			if err != nil {
				return err
			}
			// The closing block (User Manual §6): W101 warnings from the
			// job's journal, the ready line with the class-split tally, and
			// the console URL last, alone on its line (UX §7).
			_, events, err := c.Job(ctx, final.ID)
			if err != nil {
				return err
			}
			completion(render.Detect(os.Stdout), v, events)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "instance name (generated from the template name when absent)")
	cmd.Flags().StringVar(&profile, "profile", "", "resource profile (default: standard when the template declares it)")
	cmd.Flags().StringVar(&mode, "mode", "", "authoring | delivery (default: path → authoring, template → delivery)")
	cmd.Flags().StringArrayVar(&accept, "accept-license", nil, "accept a declared EULA by id (repeatable; never defaulted)")
	cmd.Flags().BoolVar(&yes, "yes", false, "never prompt (scripts); a required license then fails with PDR-E031")
	return cmd
}

// sourceOf turns the up argument into the request's source: a directory
// becomes an absolute path — the engine is another process with its own
// working directory, so a relative spelling would resolve there, not
// here — and anything else is a template name for the catalog.
func sourceOf(arg string) (path, template string, err error) {
	if fi, err := os.Stat(arg); err == nil && fi.IsDir() {
		abs, err := filepath.Abs(arg)
		if err != nil {
			return "", "", err
		}
		return abs, "", nil
	}
	return "", arg, nil
}

func newStatus() *cobra.Command {
	var watch bool
	cmd := &cobra.Command{
		Use:   "status [instance]",
		Short: "the ready ladder",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient()
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			if watch {
				// A watch ends on Ctrl-C — or when the lab it watches is
				// gone, which is the one end that is not the operator's
				// own (User Manual §8: "the ladder, live").
				ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
				defer stop()
				return watchStatus(ctx, c, name, os.Stdout)
			}
			lines, body, err := statusFrame(cmd.Context(), c, render.Detect(os.Stdout), name)
			if err != nil {
				return jsonOrErr(err, 1)
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(body)
			}
			p := render.Detect(os.Stdout)
			for _, l := range lines {
				p.Plain(l)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&watch, "watch", false, "re-render as the ladder moves, until Ctrl-C (--json emits one object per change)")
	return cmd
}

// statusFrame reads one frame of `podaro status`: the lines a terminal
// gets and the object `--json` gets, from the same read. One function, so
// a watch can never render something the one-shot read would not.
func statusFrame(ctx context.Context, c *client.Client, p *render.Printer, name string) ([]string, any, error) {
	if name == "" {
		views, err := c.Instances(ctx)
		if err != nil {
			return nil, nil, err
		}
		body := map[string]any{"instances": views}
		if len(views) == 0 {
			return emptyStateLines(p), body, nil
		}
		lines := make([]string, 0, len(views))
		for _, v := range views {
			lines = append(lines, headline(v))
		}
		return lines, body, nil
	}
	v, err := c.Instance(ctx, name)
	if err != nil {
		return nil, nil, err
	}
	lines := ladderLines(p, v)
	if v.Unsupported != "" {
		lines = append(lines, p.Row(render.Warn, "", 0, pdr.CodeRetiredPresent+" unsupported by this release: "+v.Unsupported+"; not reconciled, its containers left as they are · podaro explain "+pdr.CodeRetiredPresent, ""))
	}
	if v.Error != nil {
		lines = append(lines, p.AnatomyLines(v.Error)...)
	}
	return lines, map[string]any{"instance": v}, nil
}

// watchStatus re-renders the frame until the watch is stopped or the
// instance is gone. On a TTY the frame is redrawn in place, exactly as
// `up` streams it; piped, only changes are printed, so a log of a watch
// is a log of what changed. Under --json each change is one object on its
// own line — the shape the one-shot read returns, repeated, because a
// stream of states is what was asked for.
func watchStatus(ctx context.Context, c *client.Client, name string, out *os.File) error {
	p := render.Detect(out)
	tty := isTerminal(out)
	lastLines, last := 0, ""
	for {
		lines, body, err := statusFrame(ctx, c, p, name)
		if err != nil {
			if ctx.Err() != nil {
				return nil // stopped mid-read: the watch ended, nothing failed
			}
			return jsonOrErr(err, 1)
		}
		switch {
		case jsonOut:
			raw, err := json.Marshal(body)
			if err != nil {
				return err
			}
			if string(raw) != last {
				fmt.Fprintln(out, string(raw))
				last = string(raw)
			}
		case tty:
			lastLines = redrawFrame(out, lastLines, lines)
		default:
			if key := strings.Join(lines, "\n"); key != last {
				for _, l := range lines {
					fmt.Fprintln(out, l)
				}
				last = key
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(watchInterval):
		}
	}
}

// watchInterval is how often a watch re-reads. UX §11 puts status
// freshness at two seconds; one keeps the ladder live without hammering
// the socket, and the engine is answering from its own state. Tests
// shorten it.
var watchInterval = time.Second

// emptyStateLines is the empty state of INSTALL §2 step 6: the dual
// on-ramp (Journey §2 stage 0), one line per installed template with the
// standard profile's own description as its clause — the flagship first,
// as `system install` extracts them. Read from the catalog on disk rather
// than asked of the engine: `GET /catalog/templates` is not routed in
// this release (API §6), and the catalog is a directory the CLI can read.
// An unreadable or empty catalog still names the action that fills the
// screen (UX §6), with the open-source lab as the offer. A retired
// template in the catalog is not offered; one PDR-W103 line says it is
// there (the reconciliation plan's R3).
func emptyStateLines(p *render.Printer) []string {
	lines := []string{"no instances yet"}
	offers, retired := catalogOffers()
	if len(offers) == 0 {
		lines = append(lines, p.Row(render.Next, "", 0, "podaro up grafana-prometheus-intro", ""))
	}
	// The gap between the command and its clause is this block's own
	// (Row's 15-wide stage column is for stage words, and these are
	// commands): the widest command plus four, so the clauses line up
	// exactly as INSTALL §2 step 6 shows them.
	width := 0
	for _, o := range offers {
		if n := len("podaro up "+o.name) + 4; n > width {
			width = n
		}
	}
	for _, o := range offers {
		lines = append(lines, p.Row(render.Next, "", 0, fmt.Sprintf("%-*s%s", width, "podaro up "+o.name, o.description), ""))
	}
	if len(retired) > 0 {
		lines = append(lines, retiredCatalogLine(p, retired))
	}
	return lines
}

// retiredCatalogLine is the one PDR-W103 line a surface that offers the
// catalog prints when an earlier build left a retired template in it: the
// entry is present, unsupported, and not offered — named, never deleted.
func retiredCatalogLine(p *render.Printer, retired []string) string {
	return p.Row(render.Warn, "", 0, pdr.CodeRetiredPresent+" "+strings.Join(retired, ", ")+" in the catalog: retired, unsupported by this release, not offered · podaro explain "+pdr.CodeRetiredPresent, "")
}

func newDestroy() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "destroy <instance>",
		Short: "remove the instance entirely — containers, network, secrets, state",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			confirm := name
			if !yes {
				if !isTerminal(os.Stdin) {
					pe := pdr.New(pdr.CodeDestroyConfirm, "destroy needs confirmation: type the instance name, or pass --yes in scripts")
					pe.Next = "podaro destroy " + name + " --yes"
					return jsonOrErr(pe, 2)
				}
				fmt.Printf("destroy %s completely — containers, network, secrets, evidence, state.\ntype the instance name to confirm: ", name)
				line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				confirm = strings.TrimSpace(line)
			}
			c := newClient()
			ctx := context.Background()
			job, err := c.Destroy(ctx, name, confirm)
			if err != nil {
				return jsonOrErr(err, 1)
			}
			final, err := followJob(ctx, c, job, os.Stdout)
			if err != nil {
				return jsonOrErr(err, 1)
			}
			if final.State != state.JobSucceeded {
				return jobFailure(final)
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"job": final})
			}
			render.Detect(os.Stdout).Check(render.Pass, name+" destroyed", len(name)+11, "· nothing left behind")
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the type-the-name confirmation (scripts)")
	return cmd
}

// jobFailure turns a failed job's envelope into the CLI's error path.
func jobFailure(j *state.Job) error {
	if j.Error != nil && j.Error.Code != "" {
		return jsonOrErr(j.Error, 1)
	}
	e := pdr.New(pdr.CodeRuntimeFailed, "%s job %s failed", j.Kind, j.ID)
	e.Next = "podaro status " + j.Instance
	return jsonOrErr(e, 1)
}

// followJob polls the job and redraws the ladder until it ends: in place
// on a TTY (UX §7: no scroll spam), one line per transition otherwise.
func followJob(ctx context.Context, c *client.Client, job *state.Job, out *os.File) (*state.Job, error) {
	if jsonOut {
		return c.WaitJob(ctx, job.ID, job.Instance, 500*time.Millisecond, nil)
	}
	p := render.Detect(out)
	tty := isTerminal(out)
	lastLines := 0
	lastKey := ""
	tick := func(j *state.Job, v *engine.InstanceView) {
		var lines []string
		if v != nil {
			lines = ladderLines(p, v)
		} else {
			lines = []string{fmt.Sprintf("%s · %s job · %s", job.Instance, j.Kind, j.Stage)}
		}
		key := strings.Join(lines, "\n")
		if tty {
			lastLines = redrawFrame(out, lastLines, lines)
			return
		}
		if key != lastKey {
			for _, l := range lines {
				fmt.Fprintln(out, l)
			}
			lastKey = key
		}
	}
	return c.WaitJob(ctx, job.ID, job.Instance, 500*time.Millisecond, tick)
}

// redrawFrame replaces the previous frame in place on a terminal and
// returns the number of lines it wrote: up over the last frame, erase
// everything below the cursor, print the new one.
//
// The erase is the whole point. A frame can *shrink* — services go as a
// destroy removes them, an error clears, a watch outlives its lab — and
// clearing line by line leaves the tail of the taller frame on screen
// below the new one, which reads as a ladder that still holds services
// the instance no longer has. A stale reading is the one thing this
// display may never give (UX §1: every filled dot is a verified fact).
func redrawFrame(out io.Writer, lastLines int, lines []string) int {
	for i := 0; i < lastLines; i++ {
		fmt.Fprint(out, "\x1b[F")
	}
	fmt.Fprint(out, "\x1b[J")
	rows := 0
	for _, l := range lines {
		fmt.Fprintln(out, l)
		// A frame's own lines are one row each, but nothing stops a
		// value inside one from carrying a newline (an init failure's
		// cause is a helper's output), and the count is what the next
		// frame moves the cursor up by.
		rows += 1 + strings.Count(l, "\n")
	}
	return rows
}

// headline is the one-line form: name · template · bar stage.
func headline(v engine.InstanceView) string {
	return fmt.Sprintf("%s · %s · %s %s", v.Name, v.Template, v.Ladder.Condensed, v.Ladder.Label)
}

// ladderLines renders the full UX §5 block.
func ladderLines(p *render.Printer, v *engine.InstanceView) []string {
	width := 14
	for _, s := range v.Services {
		if len(s.Name)+2 > width {
			width = len(s.Name) + 2
		}
	}
	lines := []string{headline(*v)}
	for _, s := range v.Services {
		g := render.Pending
		switch {
		case s.Error != "":
			g = render.Fail
		case s.Stage == string(state.StageAlive) && v.Ladder.InProgress:
			g = render.Progress
		case s.Stage != "":
			g = render.Complete
		}
		lines = append(lines, "  "+p.Row(g, s.Name, width, s.Word, s.Context))
	}
	lines = append(lines, "  "+p.Row(render.None, "checkpoints", width,
		fmt.Sprintf("baseline %d/%d · objectives %d/%d", v.Checkpoints.Baseline.Passed, v.Checkpoints.Baseline.Total, v.Checkpoints.Objective.Passed, v.Checkpoints.Objective.Total), ""))
	return lines
}

// offer is one installed template as the empty state names it.
type offer struct{ name, description string }

// catalogOffers reads the installed catalog (INSTALL §3) for the empty
// state's dual on-ramp: each template's name and the description its
// standard profile declares — `4 GB host · all open source` is the
// template's own words, not this command's opinion of it. A template
// whose manifest cannot be read is offered without a clause rather than
// hidden: the name is still the action. A template the retirement
// manifest lists is never offered (the reconciliation plan's R3): an
// earlier build may have left one in the catalog, and it comes back as
// retired, for the one line that says it is there.
func catalogOffers() (offers []offer, retired []string) {
	dir := filepath.Join(config.StateDir(), "catalog")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	var names []string
	for _, e := range entries {
		if fi, err := os.Stat(filepath.Join(dir, e.Name(), "lab.yaml")); err == nil && fi.Mode().IsRegular() {
			names = append(names, e.Name())
		}
	}
	system.SortCatalog(names)
	names, retired = podaro.Retirement().Catalog(names)
	offers = make([]offer, 0, len(names))
	for _, name := range names {
		offers = append(offers, offer{name: name, description: profileDescription(filepath.Join(dir, name, "lab.yaml"))})
	}
	return offers, retired
}

// profileDescription is the standard profile's own description (spec 0003
// §8), or the single declared profile's when a template names another.
func profileDescription(manifest string) string {
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return ""
	}
	var doc struct {
		Profiles map[string]struct {
			Description string `yaml:"description"`
		} `yaml:"profiles"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return ""
	}
	if p, ok := doc.Profiles["standard"]; ok {
		return p.Description
	}
	if len(doc.Profiles) == 1 {
		for _, p := range doc.Profiles {
			return p.Description
		}
	}
	return ""
}

func isTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }
