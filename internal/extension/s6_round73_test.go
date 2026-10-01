// SPDX-License-Identifier: AGPL-3.0-only

package extension

import (
	"context"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/runtime"
)

// Review round 73: a schema-valid exec spec may repeat a grant —
// `secrets: [tok, tok]` — and the runner appended one SecretFile per
// entry. Podman derives the object's name from the secret's name and the
// run's id, so the second `secret create` is a name already in use: the
// run is refused before the extension is ever started. A grant is a
// grant; naming it twice grants it once.

type recordingRuntime struct {
	*runtime.Fake
	last runtime.RunSpec
}

func (r *recordingRuntime) Run(ctx context.Context, spec runtime.RunSpec) (*runtime.RunResult, error) {
	r.last = spec
	return r.Fake.Run(ctx, spec)
}

func TestARepeatedGrantIsOneGrant(t *testing.T) {
	r, f := newRunner(t)
	rec := &recordingRuntime{Fake: f}
	r.Runtime = rec
	input := checkpointInput(map[string]any{"ok": true})
	_, _, perr := r.Run(context.Background(), Spec{
		Image: image, Args: []string{"secret"}, Secrets: []string{"tok", "tok"},
	}, runtime.ImageUser{UID: 1000, GID: 1000}, input, 5*time.Second)
	if perr != nil && perr.Code == "" {
		t.Fatalf("run: %v", perr)
	}
	if n := len(rec.last.Secrets); n != 1 {
		names := []string{}
		for _, s := range rec.last.Secrets {
			names = append(names, s.Name)
		}
		t.Fatalf("a repeated grant produced %d secret objects (%v); Podman names both from the secret and the run id, so the second create is a name already in use", n, names)
	}
}
