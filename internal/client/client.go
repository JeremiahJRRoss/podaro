// SPDX-License-Identifier: AGPL-3.0-only

// Package client is the CLI's door to the engine: the local Unix socket
// (API §1), speaking the same JSON the network door will serve at S5.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/jeremiahjrross/podaro/internal/api"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/observe"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
	"github.com/jeremiahjrross/podaro/internal/sysinfo"
)

// Client talks to one engine socket.
type Client struct {
	socket string
	http   *http.Client
	// ReadTimeout bounds each read (GET). Mutations — create, destroy —
	// carry no blanket timeout: the engine does not abandon an admission
	// because the caller stopped waiting, so cancelling the request
	// before its 202 would only hide an outcome that still happened
	// (API §4: a job, once admitted, runs; the caller's context is the
	// only bound).
	ReadTimeout time.Duration
}

// New returns a client for the socket path.
func New(socket string) *Client {
	return &Client{
		socket:      socket,
		ReadTimeout: 30 * time.Second,
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	if method == http.MethodGet && c.ReadTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.ReadTimeout)
		defer cancel()
	}
	var buf io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		buf = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://podaro"+api.Prefix+path, buf)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		pe := pdr.New(pdr.CodeEngineUnavailable, "engine not reachable at %s", c.socket)
		pe.Cause = err.Error()
		pe.Next = "systemctl --user status podaro · journalctl --user -u podaro · podaro doctor"
		return pe
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var env struct {
			Error *pdr.Error `json:"error"`
		}
		if json.Unmarshal(raw, &env) == nil && env.Error != nil {
			return env.Error
		}
		return fmt.Errorf("engine returned HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Create is POST /instances (202 + job).
func (c *Client) Create(ctx context.Context, req engine.CreateRequest) (*state.Job, error) {
	var out struct {
		Job *state.Job `json:"job"`
	}
	if err := c.do(ctx, http.MethodPost, "/instances", req, &out); err != nil {
		return nil, err
	}
	return out.Job, nil
}

// Instance is GET /instances/{name}.
func (c *Client) Instance(ctx context.Context, name string) (*engine.InstanceView, error) {
	var out struct {
		Instance *engine.InstanceView `json:"instance"`
	}
	if err := c.do(ctx, http.MethodGet, "/instances/"+url.PathEscape(name), nil, &out); err != nil {
		return nil, err
	}
	return out.Instance, nil
}

// Instances is GET /instances.
func (c *Client) Instances(ctx context.Context) ([]engine.InstanceView, error) {
	var out struct {
		Instances []engine.InstanceView `json:"instances"`
	}
	if err := c.do(ctx, http.MethodGet, "/instances", nil, &out); err != nil {
		return nil, err
	}
	return out.Instances, nil
}

// Destroy is DELETE /instances/{name}?confirm=.
func (c *Client) Destroy(ctx context.Context, name, confirm string) (*state.Job, error) {
	var out struct {
		Job *state.Job `json:"job"`
	}
	path := "/instances/" + url.PathEscape(name) + "?confirm=" + url.QueryEscape(confirm)
	if err := c.do(ctx, http.MethodDelete, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Job, nil
}

// Job is GET /jobs/{id}.
func (c *Client) Job(ctx context.Context, id string) (*state.Job, []state.Event, error) {
	var out struct {
		Job    *state.Job    `json:"job"`
		Events []state.Event `json:"events"`
	}
	if err := c.do(ctx, http.MethodGet, "/jobs/"+url.PathEscape(id), nil, &out); err != nil {
		return nil, nil, err
	}
	return out.Job, out.Events, nil
}

// Reload is POST /system/reload (socket only): the engine re-reads
// config.yaml and (re)opens the gateway.
func (c *Client) Reload(ctx context.Context) (sysinfo.Gateway, error) {
	var out struct {
		Gateway sysinfo.Gateway `json:"gateway"`
	}
	if err := c.do(ctx, http.MethodPost, "/system/reload", map[string]any{}, &out); err != nil {
		return sysinfo.Gateway{}, err
	}
	return out.Gateway, nil
}

// SetOperator is POST /auth/operator (socket only): create the operator
// account, or replace it with replace=true (podaro auth reset).
func (c *Client) SetOperator(ctx context.Context, username, password string, replace bool) error {
	return c.do(ctx, http.MethodPost, "/auth/operator", map[string]any{"username": username, "password": password, "replace": replace}, nil)
}

// CreateToken is POST /auth/tokens; the secret is returned once.
func (c *Client) CreateToken(ctx context.Context, name, scope string) (secret string, tok *state.Token, err error) {
	var out struct {
		Token  *state.Token `json:"token"`
		Secret string       `json:"secret"`
	}
	if err := c.do(ctx, http.MethodPost, "/auth/tokens", map[string]any{"name": name, "scope": scope}, &out); err != nil {
		return "", nil, err
	}
	return out.Secret, out.Token, nil
}

// CreateTokenWithSecret is POST /auth/tokens with a secret the caller
// made and already holds (API §2.3); the response carries no secret.
func (c *Client) CreateTokenWithSecret(ctx context.Context, name, scope, secret string) (*state.Token, error) {
	var out struct {
		Token *state.Token `json:"token"`
	}
	if err := c.do(ctx, http.MethodPost, "/auth/tokens", map[string]any{"name": name, "scope": scope, "secret": secret}, &out); err != nil {
		return nil, err
	}
	return out.Token, nil
}

// Tokens is GET /auth/tokens.
func (c *Client) Tokens(ctx context.Context) ([]state.Token, error) {
	var out struct {
		Tokens []state.Token `json:"tokens"`
	}
	if err := c.do(ctx, http.MethodGet, "/auth/tokens", nil, &out); err != nil {
		return nil, err
	}
	return out.Tokens, nil
}

// RevokeToken is DELETE /auth/tokens/{name|id}.
func (c *Client) RevokeToken(ctx context.Context, nameOrID string) error {
	return c.do(ctx, http.MethodDelete, "/auth/tokens/"+url.PathEscape(nameOrID), nil, nil)
}

// Audit is GET /system/audit (socket only): the system audit stream, or
// an instance's with instance set.
func (c *Client) Audit(ctx context.Context, instance string) ([]state.Audit, error) {
	var out struct {
		Audit []state.Audit `json:"audit"`
	}
	path := "/system/audit"
	if instance != "" {
		path += "?instance=" + url.QueryEscape(instance)
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Audit, nil
}

// System is GET /system.
func (c *Client) System(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.do(ctx, http.MethodGet, "/system", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// WaitJob polls until the job ends, calling tick after each poll with the
// job and the instance view (nil when the instance no longer exists).
func (c *Client) WaitJob(ctx context.Context, id, instance string, every time.Duration, tick func(*state.Job, *engine.InstanceView)) (*state.Job, error) {
	for {
		job, _, err := c.Job(ctx, id)
		if err != nil {
			return nil, err
		}
		var view *engine.InstanceView
		if instance != "" {
			if v, err := c.Instance(ctx, instance); err == nil {
				view = v
			} else {
				var pe *pdr.Error
				if !errors.As(err, &pe) || pe.Code != pdr.CodeInstanceNotFound {
					return nil, err
				}
			}
		}
		if tick != nil {
			tick(job, view)
		}
		if !job.Active() {
			return job, nil
		}
		select {
		case <-ctx.Done():
			return job, ctx.Err()
		case <-time.After(every):
		}
	}
}

// --- the lab surface (API §7–§10, plan S6) ------------------------------

// Seed is POST /instances/{name}/seeds/{seed} (202 + job).
func (c *Client) Seed(ctx context.Context, name, seed string) (*state.Job, error) {
	var out struct {
		Job *state.Job `json:"job"`
	}
	if err := c.do(ctx, http.MethodPost, "/instances/"+url.PathEscape(name)+"/seeds/"+url.PathEscape(seed), map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out.Job, nil
}

// Verify is POST /instances/{name}/verify (202 + job); playbook narrows
// the objectives to one playbook's, beside every baseline.
func (c *Client) Verify(ctx context.Context, name, playbook string) (*state.Job, error) {
	var out struct {
		Job *state.Job `json:"job"`
	}
	body := map[string]any{}
	if playbook != "" {
		body["playbook"] = playbook
	}
	if err := c.do(ctx, http.MethodPost, "/instances/"+url.PathEscape(name)+"/verify", body, &out); err != nil {
		return nil, err
	}
	return out.Job, nil
}

// ResetPlan is GET /instances/{name}/reset-plan: the impact preview.
func (c *Client) ResetPlan(ctx context.Context, name string) (*engine.ResetPlan, error) {
	var out struct {
		Plan *engine.ResetPlan `json:"reset_plan"`
	}
	if err := c.do(ctx, http.MethodGet, "/instances/"+url.PathEscape(name)+"/reset-plan", nil, &out); err != nil {
		return nil, err
	}
	return out.Plan, nil
}

// Reset is POST /instances/{name}/reset (202 + job).
func (c *Client) Reset(ctx context.Context, name string) (*state.Job, error) {
	var out struct {
		Job *state.Job `json:"job"`
	}
	if err := c.do(ctx, http.MethodPost, "/instances/"+url.PathEscape(name)+"/reset", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out.Job, nil
}

// Checkpoints is GET /instances/{name}/checkpoints.
func (c *Client) Checkpoints(ctx context.Context, name string) ([]engine.CheckpointView, error) {
	var out struct {
		Checkpoints []engine.CheckpointView `json:"checkpoints"`
	}
	if err := c.do(ctx, http.MethodGet, "/instances/"+url.PathEscape(name)+"/checkpoints", nil, &out); err != nil {
		return nil, err
	}
	return out.Checkpoints, nil
}

// RunCheckpoint is POST /instances/{name}/checkpoints/{id}/run: one
// synchronous evaluation, 200 whether it passed or failed. No read
// timeout applies: the checkpoint carries its own.
func (c *Client) RunCheckpoint(ctx context.Context, name, id string) (*state.CheckpointResult, error) {
	var out struct {
		Result *state.CheckpointResult `json:"result"`
	}
	if err := c.do(ctx, http.MethodPost, "/instances/"+url.PathEscape(name)+"/checkpoints/"+url.PathEscape(id)+"/run", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

// Attest is POST /instances/{name}/checkpoints/{id}/attest.
func (c *Client) Attest(ctx context.Context, name, id, note string) (*state.CheckpointResult, error) {
	var out struct {
		Result *state.CheckpointResult `json:"result"`
	}
	if err := c.do(ctx, http.MethodPost, "/instances/"+url.PathEscape(name)+"/checkpoints/"+url.PathEscape(id)+"/attest", map[string]any{"note": note}, &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

// Playbooks is GET /instances/{name}/playbooks.
func (c *Client) Playbooks(ctx context.Context, name string) ([]engine.PlaybookSummary, error) {
	var out struct {
		Playbooks []engine.PlaybookSummary `json:"playbooks"`
	}
	if err := c.do(ctx, http.MethodGet, "/instances/"+url.PathEscape(name)+"/playbooks", nil, &out); err != nil {
		return nil, err
	}
	return out.Playbooks, nil
}

// Playbook is GET /instances/{name}/playbooks/{id}.
func (c *Client) Playbook(ctx context.Context, name, id string) (*engine.PlaybookView, error) {
	var out struct {
		Playbook *engine.PlaybookView `json:"playbook"`
	}
	if err := c.do(ctx, http.MethodGet, "/instances/"+url.PathEscape(name)+"/playbooks/"+url.PathEscape(id), nil, &out); err != nil {
		return nil, err
	}
	return out.Playbook, nil
}

// Progress is GET /instances/{name}/playbooks/{id}/progress (the bare
// progress object, API §8).
func (c *Client) Progress(ctx context.Context, name, id string) (*state.Progress, error) {
	var out state.Progress
	if err := c.do(ctx, http.MethodGet, "/instances/"+url.PathEscape(name)+"/playbooks/"+url.PathEscape(id)+"/progress", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PutProgress is PUT /instances/{name}/playbooks/{id}/progress.
func (c *Client) PutProgress(ctx context.Context, name, id string, p state.Progress) (*state.Progress, error) {
	var out state.Progress
	if err := c.do(ctx, http.MethodPut, "/instances/"+url.PathEscape(name)+"/playbooks/"+url.PathEscape(id)+"/progress", p, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Secrets is GET /instances/{name}/secrets: names and metadata, never values.
func (c *Client) Secrets(ctx context.Context, name string) ([]engine.SecretView, error) {
	var out struct {
		Secrets []engine.SecretView `json:"secrets"`
	}
	if err := c.do(ctx, http.MethodGet, "/instances/"+url.PathEscape(name)+"/secrets", nil, &out); err != nil {
		return nil, err
	}
	return out.Secrets, nil
}

// Reveal is POST /instances/{name}/secrets/{secret}/reveal: the audited
// value, and how long a client should show it.
func (c *Client) Reveal(ctx context.Context, name, secret string) (value string, remaskAfter time.Duration, err error) {
	var out struct {
		Value       string `json:"value"`
		RemaskAfter string `json:"remask_after"`
	}
	if err := c.do(ctx, http.MethodPost, "/instances/"+url.PathEscape(name)+"/secrets/"+url.PathEscape(secret)+"/reveal", map[string]any{}, &out); err != nil {
		return "", 0, err
	}
	d, _ := time.ParseDuration(out.RemaskAfter)
	return out.Value, d, nil
}

// Evidence is GET /instances/{name}/evidence with the §10 filters.
func (c *Client) Evidence(ctx context.Context, name string, f engine.EvidenceFilter) ([]evidence.Entry, error) {
	var out struct {
		Evidence []evidence.Entry `json:"evidence"`
	}
	q := url.Values{}
	if f.Type != "" {
		q.Set("type", f.Type)
	}
	if f.Job != "" {
		q.Set("job", f.Job)
	}
	if !f.Since.IsZero() {
		// RFC3339Nano, not RFC3339: the cutoff is a boundary, and dropping
		// its fractional seconds moves it back by up to a second, so the
		// caller is handed entries from before the instant it asked about.
		// The server parses fractional timestamps already.
		q.Set("since", f.Since.UTC().Format(time.RFC3339Nano))
	}
	path := "/instances/" + url.PathEscape(name) + "/evidence"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Evidence, nil
}

// EvidenceEntry is GET /instances/{name}/evidence/{id}.
func (c *Client) EvidenceEntry(ctx context.Context, name, id string) (*evidence.Entry, error) {
	var out struct {
		Entry *evidence.Entry `json:"entry"`
	}
	if err := c.do(ctx, http.MethodGet, "/instances/"+url.PathEscape(name)+"/evidence/"+url.PathEscape(id), nil, &out); err != nil {
		return nil, err
	}
	return out.Entry, nil
}

// maxJUnit is the largest JUnit report the client reads whole; a larger
// one is reported as such, never cut.
const maxJUnit = 8 << 20

// JUnit is GET /instances/{name}/evidence/report.junit.xml: the raw XML.
func (c *Client) JUnit(ctx context.Context, name string) ([]byte, error) {
	// A read timeout of zero disables the deadline, as it does for every
	// other read (do): a zero-length timeout would expire before the
	// request left.
	if c.ReadTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.ReadTimeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://podaro"+api.Prefix+"/instances/"+url.PathEscape(name)+"/evidence/report.junit.xml", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		pe := pdr.New(pdr.CodeEngineUnavailable, "engine not reachable at %s", c.socket)
		pe.Cause = err.Error()
		pe.Next = "systemctl --user status podaro · journalctl --user -u podaro · podaro doctor"
		return nil, pe
	}
	defer resp.Body.Close()
	// One byte past the cap tells a report too large apart from one that
	// fits: a cut at the cap would hand the caller well-formed-looking,
	// truncated XML as a success.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJUnit+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxJUnit {
		return nil, fmt.Errorf("the JUnit report of %s is larger than %d MiB, the most this client reads; fetch it over the socket with curl --unix-socket %s http://podaro%s/instances/%s/evidence/report.junit.xml", name, maxJUnit>>20, c.socket, api.Prefix, url.PathEscape(name))
	}
	if resp.StatusCode >= 400 {
		var env struct {
			Error *pdr.Error `json:"error"`
		}
		if json.Unmarshal(raw, &env) == nil && env.Error != nil {
			return nil, env.Error
		}
		return nil, fmt.Errorf("engine returned HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}
	return raw, nil
}

// AccessGrant is what POST /instances/{name}/access answers: the record,
// the secret (once), and the join link (API §2.4, plan S9).
type AccessGrant struct {
	Access state.Access `json:"access"`
	Token  string       `json:"token"`
	Join   string       `json:"join"`
}

// IssueAccess is POST /instances/{name}/access.
func (c *Client) IssueAccess(ctx context.Context, instance, name, expires string) (*AccessGrant, error) {
	body := map[string]string{"name": name}
	if expires != "" {
		body["expires"] = expires
	}
	var out AccessGrant
	if err := c.do(ctx, http.MethodPost, "/instances/"+url.PathEscape(instance)+"/access", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListAccess is GET /instances/{name}/access.
func (c *Client) ListAccess(ctx context.Context, instance string) ([]state.Access, error) {
	var out struct {
		Access []state.Access `json:"access"`
	}
	if err := c.do(ctx, http.MethodGet, "/instances/"+url.PathEscape(instance)+"/access", nil, &out); err != nil {
		return nil, err
	}
	return out.Access, nil
}

// RevokeAccess is DELETE /instances/{name}/access/{id}.
func (c *Client) RevokeAccess(ctx context.Context, instance, id string) error {
	return c.do(ctx, http.MethodDelete, "/instances/"+url.PathEscape(instance)+"/access/"+url.PathEscape(id), nil, nil)
}

// ObservePosture is GET /system/observe (plan S9): what the
// observability export is configured to do and what has happened to it.
func (c *Client) ObservePosture(ctx context.Context) (observe.Posture, error) {
	var out observe.Posture
	if err := c.do(ctx, http.MethodGet, "/system/observe", nil, &out); err != nil {
		return observe.Posture{}, err
	}
	return out, nil
}

// ObserveTest is POST /system/observe/test: one probe through each
// configured signal, and what the destination answered.
func (c *Client) ObserveTest(ctx context.Context) ([]observe.Probe, error) {
	var out struct {
		Probes []observe.Probe `json:"probes"`
	}
	if err := c.do(ctx, http.MethodPost, "/system/observe/test", nil, &out); err != nil {
		return nil, err
	}
	return out.Probes, nil
}

// Logs is GET /instances/{name}/services/{svc}/logs (plan S9). It
// returns the stream, which the caller closes; the engine has already
// filtered every byte of it. A refusal arrives as an envelope before any
// of the body, so an error is never an empty log.
// LogStream is a log answer: the bytes, and whether they are the whole
// of what was asked for. Truncated is the engine's own header — a
// non-following read is capped, and a cap the reader cannot see is a
// prefix mistaken for the log.
type LogStream struct {
	io.ReadCloser
	Truncated bool
}

func (c *Client) Logs(ctx context.Context, instance, service string, since string, tail int, follow bool) (*LogStream, error) {
	q := url.Values{}
	if since != "" {
		q.Set("since", since)
	}
	if tail > 0 {
		q.Set("tail", strconv.Itoa(tail))
	}
	if follow {
		q.Set("follow", "true")
	}
	path := "/instances/" + url.PathEscape(instance) + "/services/" + url.PathEscape(service) + "/logs"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://podaro"+api.Prefix+path, nil)
	if err != nil {
		return nil, err
	}
	// No read timeout: a follow is meant to stay open, and a plain read
	// of a long log is the engine's to bound (MaxLogRead), not a clock's.
	resp, err := c.http.Do(req)
	if err != nil {
		pe := pdr.New(pdr.CodeEngineUnavailable, "engine not reachable at %s", c.socket)
		pe.Cause = err.Error()
		pe.Next = "systemctl --user status podaro · journalctl --user -u podaro · podaro doctor"
		return nil, pe
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var env struct {
			Error *pdr.Error `json:"error"`
		}
		if json.Unmarshal(raw, &env) == nil && env.Error != nil {
			return nil, env.Error
		}
		return nil, fmt.Errorf("engine returned HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}
	return &LogStream{ReadCloser: resp.Body, Truncated: resp.Header.Get(api.HeaderTruncated) == "true"}, nil
}
