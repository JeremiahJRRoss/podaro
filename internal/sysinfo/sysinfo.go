// SPDX-License-Identifier: AGPL-3.0-only

// Package sysinfo is the GET /system shape (API §5): engine and API
// versions plus host facts. A leaf package so the API, the console, and
// the system package share one struct without an import cycle.
package sysinfo

import (
	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/config"
)

// Info is the /system body.
type Info struct {
	Engine  EngineInfo `json:"engine"`
	Host    HostInfo   `json:"host"`
	Runtime string     `json:"runtime,omitempty"`
}

// EngineInfo names the engine and API versions.
type EngineInfo struct {
	Version    string `json:"version"`
	APIVersion string `json:"api_version"`
}

// HostInfo carries the host facts /system reports.
type HostInfo struct {
	PodmanVersion string  `json:"podman_version,omitempty"`
	Rootless      *bool   `json:"rootless,omitempty"`
	Domain        string  `json:"domain,omitempty"`
	GatewayPort   int     `json:"gateway_port"`
	Gateway       Gateway `json:"gateway"`
	Observability Posture `json:"observability"`
}

// Gateway is the network door's posture (plan S5): listening once
// `podaro setup` has given it a domain and certificates.
type Gateway struct {
	Listening bool   `json:"listening"`
	Address   string `json:"address,omitempty"`
	Domain    string `json:"domain,omitempty"`
	// Certificate says where TLS comes from: "local-ca" (managed, auto-
	// renewing) or "bring-your-own"; empty when not listening.
	Certificate string `json:"certificate,omitempty"`
	// Expires is the leaf's not-after (RFC 3339) when listening.
	Expires string `json:"expires,omitempty"`
	// Fingerprint identifies the leaf served: "sha256:" + the hex SHA-256
	// of its DER encoding. What setup settles a lost reload answer by —
	// an expiry is shared by leaves issued in the same second, and a
	// replacement can carry the old one; a fingerprint is one leaf's.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Posture reports each observability signal as "off" or its exporter —
// export is off by default, and /system says so honestly.
type Posture struct {
	Logs    string `json:"logs"`
	Metrics string `json:"metrics"`
	Traces  string `json:"traces"`
}

// PodmanFacts is the runtime slice of the host facts.
type PodmanFacts struct {
	Version  string
	Rootless bool
}

// Build assembles the shape from configuration and podman facts (nil
// when podman is unavailable).
func Build(cfg *config.Config, pf *PodmanFacts) Info {
	info := Info{
		Engine: EngineInfo{Version: podaro.Version(), APIVersion: "v1alpha1"},
		Host: HostInfo{
			GatewayPort:   config.DefaultGatewayPort,
			Observability: Posture{Logs: "off", Metrics: "off", Traces: "off"},
		},
	}
	if cfg != nil {
		info.Host.Domain = cfg.Domain
		info.Host.GatewayPort = cfg.Gateway.Port
		if o := cfg.Observability; o != nil {
			if o.Logs != nil {
				info.Host.Observability.Logs = o.Logs.Exporter
			}
			if o.Metrics != nil {
				info.Host.Observability.Metrics = o.Metrics.Exporter
			}
			if o.Traces != nil {
				info.Host.Observability.Traces = o.Traces.Exporter
			}
		}
	}
	if pf != nil {
		info.Host.PodmanVersion = pf.Version
		rootless := pf.Rootless
		info.Host.Rootless = &rootless
	}
	return info
}
