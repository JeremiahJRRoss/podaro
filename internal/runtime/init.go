// SPDX-License-Identifier: AGPL-3.0-only

package runtime

// The init helper's request program (spec 0003 §9.1: init jobs are
// metadata, not scripts). The engine renders a module's ordered requests
// — secrets resolved — into this program and copies it into the one-shot
// helper container at InitProgramPath beside one curl option file per
// request and a POSIX shell runner that drives the sequence (the engine
// renders them; see internal/engine/render.go). The fake runtime executes
// the program itself against its loopback products; Podman runs the
// pinned curl image's shell on the runner. Both perform the same sequence
// with the same status semantics and exit codes.

// InitProgramPath is where the program lives inside the helper container.
// InitCurlConfigPath names the directory's option-file convention of the
// first rendering (plan S6) and is kept for callers that reference it;
// the runner reads one `<n>.curl` file per request instead.
const (
	InitProgramPath    = "/run/podaro/init/program.json"
	InitCurlConfigPath = "/run/podaro/init/requests.curl"
)

// BodyDeclared reports whether the request carries a body to send: one
// declared empty (HasBody) or one with content.
func (r InitRequest) BodyDeclared() bool { return r.HasBody || r.Body != "" }

// InitProgram is the rendered request sequence.
type InitProgram struct {
	Requests []InitRequest `json:"requests"`
}

// InitRequest is one ordered request with its poll semantics: Until is
// the status polled for (0: a single attempt that must not be an HTTP
// error), Attempts and BackoffMillis space the polls.
type InitRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	// HasBody records that the request declared a body — an empty one
	// included: `body: ""` is a request with an empty body, sent as such
	// with its content type, not a request without one.
	// Presence is the declaration, never the length;
	// BodyDeclared is the one question the renderers ask.
	HasBody       bool   `json:"has_body,omitempty"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	Until         int    `json:"until,omitempty"`
	Attempts      int    `json:"attempts"`
	BackoffMillis int    `json:"backoff_ms"`
	Insecure      bool   `json:"insecure,omitempty"`
}
