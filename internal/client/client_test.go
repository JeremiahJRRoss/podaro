// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/api"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// Reads are bounded by ReadTimeout; a mutation's admission is not — a
// create that takes longer than any blanket timeout still answers its
// 202, because the engine would run it anyway.
func TestMutationsCarryNoBlanketTimeout(t *testing.T) {
	dir, err := os.MkdirTemp("", "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "api.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(api.Prefix+"/system", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]any{"engine": "slow"})
	})
	mux.HandleFunc(api.Prefix+"/instances", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"job": map[string]any{"id": "job_slow", "kind": "create", "instance": "slow", "state": "queued"}})
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })

	c := New(sock)
	c.ReadTimeout = 50 * time.Millisecond
	ctx := context.Background()
	if _, err := c.System(ctx); err == nil || code(err) != pdr.CodeEngineUnavailable {
		t.Fatalf("a slow read must time out at ReadTimeout: %v", err)
	}
	job, err := c.Create(ctx, engine.CreateRequest{Path: "/lab", Name: "slow"})
	if err != nil || job == nil || job.ID != "job_slow" {
		t.Fatalf("a slow admission must still answer its 202: %+v %v", job, err)
	}
}

func code(err error) string {
	if pe, ok := err.(*pdr.Error); ok {
		return pe.Code
	}
	return ""
}

// A read timeout of zero disables the deadline for every read; JUnit
// used to apply it as a zero-length deadline, so every request expired
// before it left (client.go:468).
func TestJUnitHonoursADisabledReadTimeout(t *testing.T) {
	dir, err := os.MkdirTemp("", "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "api.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(api.Prefix+"/instances/intro/evidence/report.junit.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<testsuites/>`))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	c := New(sock)
	c.ReadTimeout = 0
	out, err := c.JUnit(context.Background(), "intro")
	if err != nil || string(out) != `<testsuites/>` {
		t.Fatalf("a disabled read timeout is no deadline: %q %v", out, err)
	}
}

// A JUnit report larger than the client reads is reported as such, never
// handed over cut at the cap as a well-formed-looking success (client.go:487);
// one that fits arrives whole.
func TestJUnitReportsAnOversizedReport(t *testing.T) {
	dir, err := os.MkdirTemp("", "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "api.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	size := maxJUnit // what the handler sends, set per request
	mux := http.NewServeMux()
	mux.HandleFunc(api.Prefix+"/instances/intro/evidence/report.junit.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		body := bytes.Repeat([]byte("x"), size)
		_, _ = w.Write(body)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	c := New(sock)
	out, err := c.JUnit(context.Background(), "intro")
	if err != nil || len(out) != maxJUnit {
		t.Fatalf("a report at the cap arrives whole: %d bytes, %v", len(out), err)
	}
	size = maxJUnit + 1
	out, err = c.JUnit(context.Background(), "intro")
	if err == nil || !strings.Contains(err.Error(), "larger than 8 MiB") || out != nil {
		t.Fatalf("a report past the cap is an error, never a cut: %d bytes, %v", len(out), err)
	}
}
