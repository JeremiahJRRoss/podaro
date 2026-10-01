// SPDX-License-Identifier: AGPL-3.0-only

// Package config loads and validates ~/.config/podaro/config.yaml — the
// exact surface User Manual §4 documents, nothing more. Unknown keys fail
// loudly with file:line (a typo must never silently disable intent), and
// the observability block is validated here at S1 even though exporters
// are wired at S9.
package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// DefaultGatewayPort is the documented default (User Manual §3): 7777,
// an unprivileged port the podaro account can bind without a capability.
const DefaultGatewayPort = 7777

// Config is the full configuration surface (User Manual §4).
type Config struct {
	Domain        string         `yaml:"domain"`
	Gateway       Gateway        `yaml:"gateway"`
	TLS           *TLS           `yaml:"tls"`
	Observability *Observability `yaml:"observability"`
	Legal         *Legal         `yaml:"legal"`

	// Exists reports whether a config file was present at load.
	Exists bool `yaml:"-"`
}

// Legal is the operator's statement about the build they run (User Manual
// §4; the reconciliation plan's R5): where its source is published, when
// that is not the tag of the repository the build names — a modified or
// downstream build. `podaro legal` and the /legal page print it beside the
// build's own source offer, never in place of it.
type Legal struct {
	SourceURL string `yaml:"source_url"`
}

type Gateway struct {
	Port int `yaml:"port"`
}

type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type Observability struct {
	Logs       *Signal           `yaml:"logs"`
	Metrics    *Signal           `yaml:"metrics"`
	Traces     *Signal           `yaml:"traces"`
	Attributes map[string]string `yaml:"attributes"`
}

type Signal struct {
	Exporter  string `yaml:"exporter"`
	Endpoint  string `yaml:"endpoint"`
	TokenFile string `yaml:"token_file"`
	// Insecure turns off certificate verification toward this
	// destination — the explicit, warned escape hatch the threat model
	// names (B10, destination impersonation). It is never implied: the
	// operator writes it, and every posture that shows the signal shows
	// that it is set.
	Insecure bool `yaml:"insecure"`
}

// Dir returns the XDG config directory for podaro.
func Dir() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "podaro")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "podaro")
}

// Path returns the config file path.
func Path() string { return filepath.Join(Dir(), "config.yaml") }

// StateDir returns the XDG state directory for podaro.
func StateDir() string {
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "podaro")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "podaro")
}

// RuntimeDir returns the runtime directory holding the API socket.
func RuntimeDir() string {
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		return filepath.Join(x, "podaro")
	}
	return filepath.Join(fmt.Sprintf("/run/user/%d", os.Getuid()), "podaro")
}

// Load reads and validates the config file at path. A missing file is not
// an error — it returns defaults with Exists=false (setup has simply not
// run yet). Every failure is a *pdr.Error with the documented code.
func Load(path string) (*Config, error) {
	// -1 marks "port not provided": an explicit `port: 0` must reach
	// validation and fail its 1–65535 range, never silently become the default.
	cfg := &Config{Gateway: Gateway{Port: -1}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		cfg.Gateway.Port = DefaultGatewayPort
		return cfg, nil
	}
	if err != nil {
		e := pdr.New(pdr.CodeConfigUnreadable, "cannot read %s", path)
		e.Cause = err.Error()
		e.Next = "check the file's permissions, or remove it and re-run podaro setup"
		return nil, e
	}
	cfg.Exists = true

	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, decodeError(path, err)
	}
	// Strictness covers the whole file: a second YAML document would
	// otherwise be ignored wholesale, typos included.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		e := pdr.New(pdr.CodeConfigUnreadable, "config invalid: %s: multiple YAML documents — config.yaml is one document", path)
		e.Cause = "content after a '---' separator would be silently ignored"
		e.Next = "merge the documents and remove the separator"
		return nil, e
	}
	if cfg.Gateway.Port == -1 {
		cfg.Gateway.Port = DefaultGatewayPort
	}
	if err := validate(cfg, path); err != nil {
		return nil, err
	}
	return cfg, nil
}

var unknownField = regexp.MustCompile(`line (\d+): field (\S+) not found in type`)
var lineErr = regexp.MustCompile(`line (\d+):`)

// decodeError maps yaml.v3 failures to the documented codes, always with
// file:line where the parser provides one.
func decodeError(path string, err error) *pdr.Error {
	var typeErr *yaml.TypeError
	if errors.As(err, &typeErr) {
		var unknown, invalid []pdr.Detail
		for _, msg := range typeErr.Errors {
			if m := unknownField.FindStringSubmatch(msg); m != nil {
				unknown = append(unknown, pdr.Detail{
					Path: fmt.Sprintf("%s:%s", path, m[1]),
					Hint: fmt.Sprintf("unknown key %q", m[2]),
				})
				continue
			}
			loc := path
			if m := lineErr.FindStringSubmatch(msg); m != nil {
				loc = fmt.Sprintf("%s:%s", path, m[1])
			}
			invalid = append(invalid, pdr.Detail{Path: loc, Hint: msg})
		}
		if len(unknown) > 0 {
			e := pdr.New(pdr.CodeConfigUnknownKey, "config invalid: %s: %s", unknown[0].Path, unknown[0].Hint)
			e.Cause = "the key is not part of the configuration surface (User Manual §4)"
			e.Next = "fix or remove the key, then re-run the command"
			// The message owns the first fault; details carry the rest.
			e.Details = append(unknown[1:], invalid...)
			return e
		}
		e := pdr.New(pdr.CodeConfigInvalid, "config invalid: %s: %s", invalid[0].Path, invalid[0].Hint)
		e.Next = "correct the value per User Manual §4"
		e.Details = invalid[1:]
		return e
	}
	loc := path
	if m := lineErr.FindStringSubmatch(err.Error()); m != nil {
		loc = fmt.Sprintf("%s:%s", path, m[1])
	}
	e := pdr.New(pdr.CodeConfigUnreadable, "config is not valid YAML: %s", loc)
	e.Cause = err.Error()
	e.Next = "fix the YAML syntax, or remove the file and re-run podaro setup"
	return e
}

var hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// validate applies the semantic rules of User Manual §4. It collects every
// violation, reporting the first in the message and the rest as details.
// Validate checks a configuration that is not (yet) on disk — the
// candidate `podaro setup` builds — against the same rules Load applies,
// so a bad value is refused before it replaces a working file.
// WithoutUserinfo is a URL as it may be printed: whatever stands in
// front of the `@` removed. An endpoint that carries userinfo is refused
// above, so nothing in a valid config reaches this — it is here because
// every place that shows an endpoint goes through it, and a value that
// arrived some other way must not be the print that leaks it. A string
// that will not parse comes back empty rather than as itself: it cannot
// be shown to hold no credential.
func WithoutUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}

func Validate(c *Config) error {
	if e := validate(c, Path()); e != nil {
		return e
	}
	return nil
}

func validate(c *Config, path string) *pdr.Error {
	var faults []pdr.Detail
	fault := func(key, hint string) {
		faults = append(faults, pdr.Detail{Path: key, Hint: hint})
	}

	if c.Domain != "" && !hostnameRe.MatchString(c.Domain) {
		fault("domain", fmt.Sprintf("%q is not a lowercase DNS domain", c.Domain))
	}
	if c.Gateway.Port < 1 || c.Gateway.Port > 65535 {
		fault("gateway.port", fmt.Sprintf("%d is outside 1–65535", c.Gateway.Port))
	}
	if c.TLS != nil {
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			fault("tls", "cert_file and key_file must be set together")
		}
		for key, f := range map[string]string{"tls.cert_file": c.TLS.CertFile, "tls.key_file": c.TLS.KeyFile} {
			if f == "" {
				continue
			}
			if _, err := os.Stat(f); err != nil {
				fault(key, fmt.Sprintf("%s: %v", f, err))
			}
		}
	}
	if o := c.Observability; o != nil {
		signal := func(name string, s *Signal) {
			if s == nil {
				return
			}
			key := "observability." + name
			switch s.Exporter {
			case "":
				fault(key+".exporter", "required: one of otlp · http · hec")
			case "otlp", "http", "hec":
				if name == "traces" && s.Exporter != "otlp" {
					fault(key+".exporter", fmt.Sprintf("%q — traces are OTLP-only in this release", s.Exporter))
				}
			default:
				fault(key+".exporter", fmt.Sprintf("%q is not one of otlp · http · hec", s.Exporter))
			}
			if s.Endpoint == "" {
				fault(key+".endpoint", "required")
			} else if u, err := url.Parse(s.Endpoint); err != nil {
				// Not printed back: a string this package could not
				// parse is a string it cannot say holds no credential.
				fault(key+".endpoint", "is not a URL")
			} else if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				fault(key+".endpoint", fmt.Sprintf("%q is not an http(s) URL", WithoutUserinfo(s.Endpoint)))
			} else if u.User != nil {
				// The same rule `token_file` below enforces, at the
				// other end of the same config: a destination credential
				// belongs in a 0600 file. In the URL it would sit in the
				// config file, in the posture `GET /system/observe`
				// returns, and in the line printed at every start.
				// The refusal does not repeat it.
				fault(key+".endpoint", "carries userinfo — a destination credential belongs in token_file (0600), never in the URL")
			}
			if s.Insecure && s.Endpoint != "" && strings.HasPrefix(s.Endpoint, "http://") {
				fault(key+".insecure", "meaningless on an http:// endpoint — there is no certificate to skip")
			}
			if s.Exporter == "hec" && s.TokenFile == "" {
				fault(key+".token_file", "required for the hec exporter (0600 file; never inline)")
			}
			if s.TokenFile != "" {
				fi, err := os.Stat(s.TokenFile)
				switch {
				case err != nil:
					fault(key+".token_file", fmt.Sprintf("%s: %v", s.TokenFile, err))
				case fi.Mode().Perm() != 0o600:
					fault(key+".token_file", fmt.Sprintf("%s is mode %04o — destination credentials must be 0600", s.TokenFile, fi.Mode().Perm()))
				}
			}
		}
		signal("logs", o.Logs)
		signal("metrics", o.Metrics)
		signal("traces", o.Traces)
	}
	if l := c.Legal; l != nil {
		// Printed on a page anyone who can reach the console reads, so
		// it is a plain http(s) location and nothing else: a credential,
		// a query or a fragment in it would be published with it.
		switch u, err := url.Parse(l.SourceURL); {
		case l.SourceURL == "":
			fault("legal.source_url", "required when legal is set: where the source of the build you run is published")
		case err != nil:
			fault("legal.source_url", "is not a URL")
		case (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
			fault("legal.source_url", fmt.Sprintf("%q is not an http(s) URL", WithoutUserinfo(l.SourceURL)))
		case u.User != nil:
			fault("legal.source_url", "carries userinfo — it is printed on the public /legal page, and a credential does not belong there")
		case u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(l.SourceURL, " \t\n\r"):
			fault("legal.source_url", "a source location has no query, fragment or whitespace")
		}
	}

	if len(faults) == 0 {
		return nil
	}
	e := pdr.New(pdr.CodeConfigInvalid, "config invalid: %s: %s: %s", path, faults[0].Path, faults[0].Hint)
	e.Next = "correct the named keys per User Manual §4"
	e.Details = faults[1:]
	return e
}
