// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// `system upgrade`'s preflight (INSTALL §6; the reconciliation plan's R3):
// before anything is fetched or replaced, the upgrade says what an
// earlier build left that this release does not operate — a template the
// owner retired, still in the catalog; an instance created from one, and
// how many of its containers are running. It reports and proceeds: the
// engine never reconciles, repairs, restarts or stops such an instance
// (PDR-W103), so nothing about it depends on which binary serves. What
// refuses the upgrade is a state database whose instance rows cannot be
// read — then nothing can say which instances are isolated, and nothing
// is replaced.

// retiredInventory is what the preflight found.
type retiredInventory struct {
	catalog   []string
	instances []retiredInstance
}

// retiredInstance is one unsupported instance: the containers carrying
// its label, how many of them run, or why the runtime could not say.
type retiredInstance struct {
	name       string
	containers int
	running    int
	err        error
}

// inventoryRetired reads the catalog and the state database's instance
// rows read-only, and the runtime only for an instance of a retired
// template — opened once, and only then.
func inventoryRetired(ctx context.Context, stateDir string, open func() (runtime.ContainerReader, error)) (retiredInventory, error) {
	inv := retiredInventory{catalog: RetiredCatalog(stateDir)}
	rows, err := state.InstanceRowsOf(filepath.Join(stateDir, "state.db"))
	if err != nil {
		return inv, err
	}
	var rd runtime.ContainerReader
	var openErr error
	opened := false
	for _, r := range rows {
		if !podaro.Retirement().Template(r.Template) {
			continue
		}
		if !opened {
			rd, openErr = open()
			opened = true
		}
		ri := retiredInstance{name: r.Name, err: openErr}
		if openErr == nil {
			ri.containers, ri.running, ri.err = countContainers(ctx, rd, r.Name)
		}
		inv.instances = append(inv.instances, ri)
	}
	return inv, nil
}

// countContainers counts the containers labeled with an instance and
// the ones among them that run.
func countContainers(ctx context.Context, rd runtime.ContainerReader, instance string) (total, running int, err error) {
	objs, err := rd.Objects(ctx, instance)
	if err != nil {
		return 0, 0, err
	}
	for _, c := range objs.Containers {
		st, err := rd.Inspect(ctx, c)
		if err != nil {
			return 0, 0, err
		}
		if st == nil {
			continue // gone between the listing and the look
		}
		total++
		if st.Running {
			running++
		}
	}
	return total, running, nil
}

// render prints the preflight's rows: none when there is nothing to
// report, so the board of a host that never held retired content is the
// one INSTALL §6 shows.
func (inv retiredInventory) render(p *render.Printer) {
	if len(inv.catalog) > 0 {
		p.Check(render.Warn, "retired template", upgradeColumn,
			strings.Join(inv.catalog, " · ")+" in the catalog · not offered, never recreated · "+pdr.CodeRetiredPresent)
	}
	for _, ri := range inv.instances {
		var what string
		switch {
		case ri.err != nil:
			what = "its containers cannot be read: " + ri.err.Error()
		case ri.containers == 0:
			what = "no containers"
		default:
			what = fmt.Sprintf("%d of %d containers running, left as they are", ri.running, ri.containers)
		}
		p.Check(render.Warn, "unsupported instance", upgradeColumn,
			ri.name+" · retired template · "+what+" · not reconciled · "+pdr.CodeRetiredPresent)
	}
}

// readContainers opens the runtime the engine is configured with
// (SelectRuntime's choice) for reading alone.
func readContainers(stateDir string) (runtime.ContainerReader, error) {
	switch os.Getenv(EnvRuntime) {
	case "", "podman":
		return runtime.NewPodman(), nil
	case "fake":
		return runtime.ReadFake(FakeWorldPath(stateDir))
	default:
		return nil, fmt.Errorf("%s=%q: podman or fake", EnvRuntime, os.Getenv(EnvRuntime))
	}
}
