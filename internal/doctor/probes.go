// SPDX-License-Identifier: AGPL-3.0-only

package doctor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremiahjrross/podaro/internal/config"
)

// Probes is the read-only host surface doctor consults. An interface so
// tests can replay any host — including the INSTALL manual's broken one.
type Probes interface {
	Username() string
	PodmanInfo() (PodmanFacts, error)
	SubIDs(user string) (idRange IDRange, gidRange IDRange, err error)
	Linger(user string) (bool, error)
	MaxMapCount() (int, error)
	PortFree(port int) (bool, error)
	DiskFree(path string) (uint64, error)
	LookupHost(domain string) ([]string, error)
}

// PodmanFacts is what `podman info` yields for the checks.
type PodmanFacts struct {
	Version       string
	Rootless      bool
	CgroupVersion string
}

// IDRange is one /etc/subuid–style range.
type IDRange struct {
	Start int
	Count int
}

// Host is the real probe set.
type Host struct{}

func (Host) Username() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}

func (Host) PodmanInfo() (PodmanFacts, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "podman", "info", "--format", "json").Output()
	if err != nil {
		return PodmanFacts{}, fmt.Errorf("podman info: %w", err)
	}
	var info struct {
		Host struct {
			CgroupVersion string `json:"cgroupVersion"`
			Security      struct {
				Rootless bool `json:"rootless"`
			} `json:"security"`
		} `json:"host"`
		Version struct {
			Version string `json:"Version"`
		} `json:"version"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return PodmanFacts{}, fmt.Errorf("podman info parse: %w", err)
	}
	return PodmanFacts{
		Version:       info.Version.Version,
		Rootless:      info.Host.Security.Rootless,
		CgroupVersion: info.Host.CgroupVersion,
	}, nil
}

func (Host) SubIDs(username string) (IDRange, IDRange, error) {
	uid, err := readSubIDs("/etc/subuid", username)
	if err != nil {
		return IDRange{}, IDRange{}, err
	}
	gid, err := readSubIDs("/etc/subgid", username)
	if err != nil {
		return IDRange{}, IDRange{}, err
	}
	return uid, gid, nil
}

func readSubIDs(path, username string) (IDRange, error) {
	f, err := os.Open(path)
	if err != nil {
		return IDRange{}, err
	}
	defer f.Close()
	uid := ""
	if u, err := user.Lookup(username); err == nil {
		uid = u.Uid
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(strings.TrimSpace(sc.Text()), ":")
		if len(parts) != 3 || (parts[0] != username && parts[0] != uid) {
			continue
		}
		start, err1 := strconv.Atoi(parts[1])
		count, err2 := strconv.Atoi(parts[2])
		if err1 != nil || err2 != nil {
			continue
		}
		return IDRange{Start: start, Count: count}, nil
	}
	return IDRange{}, fmt.Errorf("no entry for %s in %s", username, path)
}

func (Host) Linger(username string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "loginctl", "show-user", username, "--property=Linger").Output()
	if err != nil {
		return false, fmt.Errorf("loginctl: %w", err)
	}
	return strings.TrimSpace(string(out)) == "Linger=yes", nil
}

func (Host) MaxMapCount() (int, error) {
	raw, err := os.ReadFile("/proc/sys/vm/max_map_count")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(raw)))
}

func (Host) PortFree(port int) (bool, error) {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false, nil
	}
	_ = l.Close()
	return true, nil
}

func (Host) DiskFree(path string) (uint64, error) {
	// The state dir may not exist yet — statfs the deepest existing parent.
	for p := path; ; p = filepath.Dir(p) {
		var st unix.Statfs_t
		if err := unix.Statfs(p, &st); err == nil {
			return st.Bavail * uint64(st.Bsize), nil
		} else if p == filepath.Dir(p) {
			return 0, err
		}
	}
}

// LegalNotices reports <state>/legal/ — where `podaro system install`
// writes the licence and the notices — and whether it holds them. It is
// an optional probe (doctor asks for it by interface), so the fixtures
// that pin the documented boards need not know about it.
func (Host) LegalNotices() (string, bool) {
	dir := filepath.Join(config.StateDir(), "legal")
	shown := dir
	if home, err := os.UserHomeDir(); err == nil && home != "" && strings.HasPrefix(dir, home+string(filepath.Separator)) {
		shown = "~" + strings.TrimPrefix(dir, home)
	}
	_, err := os.Stat(filepath.Join(dir, "LICENSE"))
	return shown + "/", err == nil
}

func (Host) LookupHost(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return (&net.Resolver{}).LookupHost(ctx, domain)
}
