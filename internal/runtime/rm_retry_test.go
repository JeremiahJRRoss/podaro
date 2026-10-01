// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The first `podman rm` fails the way Podman 5.7 with pasta did on a real
// host; the second succeeds, and that is the answer. Any other failure is
// reported at once, without a retry.
func TestRemoveRetriesOnceWhenPodmanCannotKillItsNetworkHelper(t *testing.T) {
	denied := &CommandError{Args: []string{"rm"}, Err: errors.New("exit status 125"),
		Stderr: "Error: cleaning up container 558d: removing container 558d network: 1 error occurred:\n\t* rootless netns: kill network process: permission denied"}
	calls := 0
	p := &Podman{Exe: "podman", Exec: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, denied
		}
		return nil, nil
	}}
	if err := p.rm(context.Background(), "pdr-intro-prometheus"); err != nil {
		t.Fatalf("the retry should have removed it: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected one retry, got %d calls", calls)
	}

	calls = 0
	other := &CommandError{Args: []string{"rm"}, Err: errors.New("exit status 125"), Stderr: "Error: no such container"}
	p.Exec = func(_ context.Context, _ string, args ...string) ([]byte, error) { calls++; return nil, other }
	err := p.rm(context.Background(), "pdr-intro-prometheus")
	if err == nil || !strings.Contains(err.Error(), "no such container") || calls != 1 {
		t.Fatalf("another failure is reported at once: err=%v calls=%d", err, calls)
	}

	calls = 0
	p.Exec = func(_ context.Context, _ string, args ...string) ([]byte, error) { calls++; return nil, denied }
	if err := p.rm(context.Background(), "pdr-intro-prometheus"); err == nil || calls != 2 {
		t.Fatalf("a second refusal is the answer: err=%v calls=%d", err, calls)
	}
}
