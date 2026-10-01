// SPDX-License-Identifier: AGPL-3.0-only

package runtime

// Service logs (API §7, plan S9). Both runtimes open a stream the caller
// closes; the engine filters every byte through the instance's
// redaction filter before any of it leaves, because a product prints
// what it was configured with and it was configured with this lab's
// secrets.

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// LogsArgs is the podman command a log read runs, exported so a test can
// state the command rather than infer it.
func LogsArgs(name string, opts LogOptions) []string {
	args := []string{"logs"}
	if opts.Since > 0 {
		args = append(args, "--since", strconv.FormatInt(int64(opts.Since.Seconds()), 10)+"s")
	}
	if opts.Tail > 0 {
		args = append(args, "--tail", strconv.Itoa(opts.Tail))
	}
	if opts.Follow {
		args = append(args, "--follow")
	}
	return append(args, name)
}

// Logs opens a container's combined output. Podman writes a container's
// stdout and stderr to two streams; they are merged here in arrival
// order, which is the order the operator saw them in the container.
func (p *Podman) Logs(ctx context.Context, name string, opts LogOptions) (io.ReadCloser, error) {
	args := LogsArgs(name, opts)
	cmd := exec.CommandContext(ctx, p.Exe, args...)
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		pw.Close()
		pr.Close()
		return nil, &CommandError{Args: args, Err: err, Stderr: err.Error()}
	}
	go func() {
		err := cmd.Wait()
		// A follow ended by the caller's context is not a failure: the
		// reader closed, which is how a client hanging up looks.
		if err != nil && ctx.Err() != nil {
			err = nil
		}
		pw.CloseWithError(err)
	}()
	return &procReader{r: pr, cancelled: func() { _ = cmd.Process.Kill() }}, nil
}

// procReader closes the pipe and stops the process behind it, so a
// client that hangs up does not leave a `podman logs --follow` running.
type procReader struct {
	r         *io.PipeReader
	cancelled func()
	closed    bool
}

func (p *procReader) Read(b []byte) (int, error) { return p.r.Read(b) }

func (p *procReader) Close() error {
	if !p.closed {
		p.closed = true
		if p.cancelled != nil {
			p.cancelled()
		}
	}
	return p.r.Close()
}

// Logs on the fake reports what the fake actually did with the
// container — created, started, the port it serves on, whether it is
// running now — and says plainly that it is the fake's own record.
//
// It does not invent a product's output. A fake container runs no
// product, so a line pretending to be a product's own would be a lie
// told by the one component whose whole job is to let the engine's paths
// be exercised honestly where Podman is absent.
// EnvFakeLogBytes pads the fake's log record to at least this many bytes.
const EnvFakeLogBytes = "PODARO_FAKE_LOG_BYTES"

func (f *Fake) Logs(ctx context.Context, ref string, opts LogOptions) (io.ReadCloser, error) {
	f.mu.Lock()
	name, c := f.resolve(ref)
	if c == nil {
		f.mu.Unlock()
		return nil, fmt.Errorf("no such container: %s", ref)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "podaro fake runtime · the record of container %s; no product runs here\n", name)
	fmt.Fprintf(&b, "image %s\n", c.Spec.Image)
	if !c.StartedAt.IsZero() {
		fmt.Fprintf(&b, "%s started\n", c.StartedAt.UTC().Format(time.RFC3339))
	}
	for port, host := range c.Ports {
		fmt.Fprintf(&b, "listening on container port %d (host %d)\n", port, host)
	}
	if c.Running {
		b.WriteString("running\n")
	} else {
		b.WriteString("stopped\n")
	}
	f.mu.Unlock()
	out := b.String()
	// A product's log grows; this record does not, so a reader whose
	// behaviour depends on length — the API's read cap above all — had
	// nothing here to read. The padding is ordinary lines and is the
	// fake's alone.
	if n, err := strconv.Atoi(os.Getenv(EnvFakeLogBytes)); err == nil && n > len(out) {
		var pad strings.Builder
		pad.WriteString(out)
		for i := 0; pad.Len() < n; i++ {
			fmt.Fprintf(&pad, "line %d · the fake runtime has nothing else to say\n", i)
		}
		out = pad.String()
	}
	if opts.Tail > 0 {
		out = lastLines(out, opts.Tail)
	}
	// Follow adds nothing here: the fake's record does not grow while it
	// is read, so the stream ends rather than holding a client open on a
	// promise it cannot keep.
	return io.NopCloser(strings.NewReader(out)), nil
}

// lastLines keeps the final n lines of a log.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[len(lines)-n:], "\n") + "\n"
}
