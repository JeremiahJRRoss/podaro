// SPDX-License-Identifier: AGPL-3.0-only

package engine

// Plan S9, API §7: service logs, and the one property that matters about
// them — no byte leaves before the instance's redaction filter has seen
// it. A product prints what it was configured with, and it was
// configured with this lab's secrets.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// loggingRuntime wraps the fake and answers Logs with whatever the test
// wants a product to have printed.
type loggingRuntime struct {
	runtime.Runtime
	out string
}

func (l *loggingRuntime) Logs(context.Context, string, runtime.LogOptions) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(l.out)), nil
}

// secretOf reads the value the instance generated, so the test can look
// for exactly the string a product would have printed.
func secretOf(t *testing.T, h *harness, instance, name string) string {
	t.Helper()
	values, err := h.eng.secretStore(instance).Values()
	if err != nil {
		t.Fatal(err)
	}
	v := values[name]
	if v == "" {
		t.Fatalf("instance %s generated no secret %q", instance, name)
	}
	return v
}

func loggingLab(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: loud, version: 1.0.0 }
secrets:
  tok: { kind: token }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
`
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestLogsAreFiltered: a product that prints its own credential is
// printed without it, on a line, across a chunk boundary, and at the end
// of a stream that has no final newline.
func TestLogsAreFiltered(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: loggingLab(t), Name: "loud"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	tok := secretOf(t, h, "loud", "tok")

	for _, tc := range []struct{ name, out string }{
		{"on a line", "starting up\nbootstrap password is " + tok + "\nready\n"},
		{"with no trailing newline", "auth failed for token " + tok},
		{"repeated", strings.Repeat("tok="+tok+" retrying\n", 40)},
		{"inside a long line", strings.Repeat("x", MaxLogLine) + tok + "\n"},
		// The dangerous one: the value straddles the boundary where a
		// line past the cap is cut, so no single chunk contains it.
		{"straddling the line cap", strings.Repeat("x", MaxLogLine-len(tok)/2) + tok + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.eng.opts.Runtime = &loggingRuntime{Runtime: h.fake, out: tc.out}
			stream, err := h.eng.Logs(ctx, "loud", "web", LogOptions{}, Socket)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			got, err := io.ReadAll(stream)
			if err != nil {
				t.Fatal(err)
			}
			// Not the value, and not a run of it either: a stream cut
			// mid-secret must not deliver the half that survived the cut.
			// Nothing here prints the output — a failing leak test that
			// prints the leak is a second leak, into CI's logs.
			if n := longestRun(string(got), tok); n >= fragmentFloor {
				t.Fatalf("%d consecutive characters of the secret reached the reader (of %d)", n, len(tok))
			}
			if !bytes.Contains(got, []byte("[redacted:tok]")) {
				t.Fatalf("nothing was filtered: %d bytes out, no mask in them", len(got))
			}
		})
	}
}

// fragmentFloor is the longest run of a secret's characters this test
// tolerates in output. Some overlap is unavoidable — a token's alphabet
// is the alphabet ordinary text is written in — but eight in a row is
// not coincidence.
const fragmentFloor = 8

// longestRun reports the longest substring of needle that appears in
// haystack. It never returns the substring itself.
func longestRun(haystack, needle string) int {
	best := 0
	for i := range needle {
		for j := len(needle); j > i+best; j-- {
			if strings.Contains(haystack, needle[i:j]) {
				best = j - i
				break
			}
		}
	}
	return best
}

// TestLogsWithheldWhenTheFilterCannotBeBuilt: an instance whose secret
// store cannot be read gets no logs at all — the same PDR-E412 refusal
// every other path that would persist or print product text raises.
func TestLogsWithheldWhenTheFilterCannotBeBuilt(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: loggingLab(t), Name: "loud"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	h.eng.opts.Runtime = &loggingRuntime{Runtime: h.fake, out: "anything at all\n"}
	dir := h.eng.secretStore("loud").Dir()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = h.eng.Logs(ctx, "loud", "web", LogOptions{}, Socket)
	if code(err) != pdr.CodeSecretStoreUnreadable {
		t.Fatalf("logs with an unreadable secret store: %v — want %s", err, pdr.CodeSecretStoreUnreadable)
	}
}

// TestLogsNameTheServicesTheInstanceHas: a service that does not exist,
// and one that exists but has no container, are told apart.
func TestLogsNameTheServicesTheInstanceHas(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: loggingLab(t), Name: "loud"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	_, err = h.eng.Logs(ctx, "loud", "nope", LogOptions{}, Socket)
	if code(err) != pdr.CodeServiceNotFound {
		t.Fatalf("an unknown service: %v — want %s", err, pdr.CodeServiceNotFound)
	}
	var pe *pdr.Error
	if !errors.As(err, &pe) || !strings.Contains(pe.Cause, "web") {
		t.Fatalf("the refusal does not name the services there are: %v", err)
	}
	names, err := h.eng.ServiceNames("loud")
	if err != nil || len(names) != 1 || names[0] != "web" {
		t.Fatalf("ServiceNames = %v %v", names, err)
	}
}
