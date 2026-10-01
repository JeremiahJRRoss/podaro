// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/doctor"
	"github.com/jeremiahjrross/podaro/internal/sysinfo"
)

// Info is the GET /system shape (API §5); the struct lives in sysinfo.
type Info = sysinfo.Info

// BuildInfo assembles the /system shape from configuration and podman
// facts (nil when podman is unavailable).
func BuildInfo(cfg *config.Config, pf *doctor.PodmanFacts) Info {
	var facts *sysinfo.PodmanFacts
	if pf != nil {
		facts = &sysinfo.PodmanFacts{Version: pf.Version, Rootless: pf.Rootless}
	}
	return sysinfo.Build(cfg, facts)
}
