// SPDX-License-Identifier: AGPL-3.0-only

// Command earlierbuild is test support for hack/retirement_migration_test.sh
// (the reconciliation plan's R3). It lays down, in a state directory, what an
// earlier build of Podaro left there for one instance — its row at ready, a
// snapshot of its template, a generated secret, a finished create job, a
// result row, evidence entries, a reveal in the audit stream, and container
// records in the fake runtime's world, some running and some stopped — so the
// script can start this build's engine over it and prove what the engine does
// with it and what it never does.
//
// It is never part of the product: nothing imports it and the podaro binary
// does not carry it. It names no template of its own; the script passes every
// name, reading the retired one from the retirement manifest. The state file
// is written at this build's schema — the migration that brings an earlier
// build's file forward is proved by internal/state's own tests.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/secrets"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// image is what the recorded containers ran: never pulled from anywhere —
// the fake records it — and pinned to a digest no registry serves.
const image = "example/earlier-build@sha256:0000000000000000000000000000000000000000000000000000000000000000"

type options struct {
	state, instance, template, source string
	running, stopped                  []string
}

func main() {
	var o options
	var running, stopped string
	flag.StringVar(&o.state, "state", "", "the state directory (XDG_STATE_HOME/podaro)")
	flag.StringVar(&o.instance, "instance", "", "the instance's name")
	flag.StringVar(&o.template, "template", "", "the template the row records it was created from")
	flag.StringVar(&o.source, "source", "", "the template directory the earlier build snapshotted")
	flag.StringVar(&running, "running", "", "services whose containers run, comma-separated")
	flag.StringVar(&stopped, "stopped", "", "services whose containers were stopped, comma-separated")
	flag.Parse()
	o.running, o.stopped = split(running), split(stopped)
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "earlierbuild:", err)
		os.Exit(1)
	}
}

func split(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func run(o options) error {
	if o.state == "" || o.instance == "" || o.template == "" || o.source == "" || len(o.running)+len(o.stopped) == 0 {
		return errors.New("-state, -instance, -template, -source and at least one of -running and -stopped are required")
	}
	if os.Getenv("PODARO_RUNTIME") != "fake" {
		return errors.New("the container records go into the fake runtime's world: run with PODARO_RUNTIME=fake")
	}
	ctx := context.Background()
	store, err := state.OpenSQLite(filepath.Join(o.state, "state.db"))
	if err != nil {
		return err
	}
	defer store.Close()

	dir := filepath.Join(o.state, "instances", o.instance)
	snapshot := filepath.Join(dir, "template")
	if err := copyTree(o.source, snapshot); err != nil {
		return fmt.Errorf("snapshot %s: %w", o.source, err)
	}
	// The pinned module library a delivery instance keeps beside its
	// snapshot; empty, since a retired module's definition has no place
	// in the tree — this build refuses the names before any lookup.
	if err := os.MkdirAll(filepath.Join(dir, "modules"), 0o700); err != nil {
		return err
	}
	if _, err := secrets.NewStore(filepath.Join(dir, "secrets")).Ensure("admin-password", secrets.KindPassword); err != nil {
		return err
	}

	from, err := store.LatestAuditSeq()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	inst := state.Instance{Name: o.instance, Template: o.template, Version: "1.0.0", Mode: state.ModeDelivery, Source: snapshot,
		Created: now, Updated: now, Stage: state.StageReady, Reached: state.StageReady, AuditFrom: from}
	if err := store.PutInstance(inst); err != nil {
		return err
	}
	if err := store.AddGeneratedSecrets(o.instance, []string{"admin-password"}); err != nil {
		return err
	}
	jobID := "job_earlier_build_" + strings.ReplaceAll(o.instance, "-", "_")
	if err := store.PutJob(state.Job{ID: jobID, Kind: "create", Instance: o.instance, Gen: from, State: state.JobSucceeded, Stage: "done", Started: now, Finished: &now}); err != nil {
		return err
	}
	if err := store.AppendEvent(state.Event{Job: jobID, At: now, Step: "job", Status: "succeeded"}); err != nil {
		return err
	}

	world, err := runtime.NewFake(filepath.Join(o.state, "fake-runtime.json"))
	if err != nil {
		return err
	}
	defer world.Close()
	network := "pdr-" + o.instance
	if err := world.EnsureNetwork(ctx, network, map[string]string{runtime.LabelInstance: o.instance, runtime.LabelTemplate: o.template, runtime.LabelManaged: "true"}, false); err != nil {
		return err
	}
	if err := world.Pull(ctx, image); err != nil {
		return err
	}
	for _, svc := range append(append([]string(nil), o.running...), o.stopped...) {
		spec := runtime.ContainerSpec{Name: "pdr-" + o.instance + "-" + svc, Image: image, Network: network, Alias: svc, Publish: []int{8080},
			Labels: map[string]string{runtime.LabelInstance: o.instance, runtime.LabelService: svc, runtime.LabelTemplate: o.template, runtime.LabelManaged: "true"}}
		id, err := world.Create(ctx, spec)
		if err != nil {
			return err
		}
		if err := world.Start(ctx, spec.Name); err != nil {
			return err
		}
		st, err := world.Inspect(ctx, spec.Name)
		if err != nil || st == nil {
			return fmt.Errorf("inspect %s: %v", spec.Name, err)
		}
		started := st.StartedAt
		if err := store.PutService(state.Service{Instance: o.instance, Name: svc, Image: image, Container: spec.Name, ContainerID: id,
			Stage: state.StageReady, Ports: st.Ports, StartedAt: &started, HealthyAt: &started, RanImage: image}); err != nil {
			return err
		}
	}
	for _, svc := range o.stopped {
		if err := world.Stop(ctx, "pdr-"+o.instance+"-"+svc, 0); err != nil {
			return err
		}
	}

	result := state.CheckpointResult{Instance: o.instance, ID: "events-arrived", Class: "baseline", Adapter: "http", Status: "pass", At: now,
		Message: "recorded by an earlier build"}
	if err := store.PutCheckpointResult(result); err != nil {
		return err
	}
	journal := evidence.Open(filepath.Join(dir, "evidence"))
	for _, e := range []evidence.Entry{
		{Type: evidence.TypeCheckpoint, Instance: o.instance, Job: jobID, Checkpoint: &result},
		{Type: evidence.TypeLifecycle, Instance: o.instance, Job: jobID, Lifecycle: &evidence.Lifecycle{Event: "ready", Stage: "ready", Detail: "baseline 1/1 verified (recorded by an earlier build)"}},
	} {
		if _, err := journal.Append(e); err != nil {
			return err
		}
	}
	if err := store.AppendAudit(state.Audit{At: now, Instance: o.instance, Action: "reveal", Actor: "operator", Mechanism: "socket", Detail: "admin-password"}); err != nil {
		return err
	}
	line := "an earlier build's " + o.instance + ": template " + o.template
	if len(o.running) > 0 {
		line += " · running " + strings.Join(o.running, ",")
	}
	if len(o.stopped) > 0 {
		line += " · stopped " + strings.Join(o.stopped, ",")
	}
	fmt.Println(line)
	return nil
}

// copyTree copies a template directory's regular files.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", path)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o600)
	})
}
