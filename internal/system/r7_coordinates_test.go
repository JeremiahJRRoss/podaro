// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// The reconciliation plan's R7: the technical coordinates moved to the
// destination the owner gave on 2026-09-23, as a tested change. The release
// location `system upgrade` asks and the one `podaro legal` names are one
// coordinate, read from the root SOURCE file; and an upgrade given no
// location asks that one, in the shape GitHub answers it, and nothing else.

// TestTheReleaseLocationIsTheSourcesReleases: DefaultReleaseBase is the
// releases of the repository SOURCE names — what `podaro legal` and the
// /legal page print as where official releases are published
// (internal/legal) — so the two cannot drift apart.
func TestTheReleaseLocationIsTheSourcesReleases(t *testing.T) {
	if want := podaro.SourceURL() + "/releases"; DefaultReleaseBase != want {
		t.Fatalf("DefaultReleaseBase = %q; the releases of the repository SOURCE names are %q", DefaultReleaseBase, want)
	}
}

// githubReleases answers as GitHub answers a repository's releases:
// `latest` redirects to the tag's page, and a release's assets are served
// under /download/<tag>/. It is the client's transport, so nothing leaves
// the process, and it records every request.
type githubReleases struct {
	version string
	binary  []byte
	asked   []string
}

func (g *githubReleases) RoundTrip(req *http.Request) (*http.Response, error) {
	g.asked = append(g.asked, req.Method+" "+req.URL.String())
	resp := &http.Response{Request: req, Header: http.Header{}, Body: http.NoBody, StatusCode: http.StatusNotFound}
	tag := "v" + g.version
	switch req.URL.String() {
	case DefaultReleaseBase + "/latest":
		resp.StatusCode = http.StatusFound
		resp.Header.Set("Location", DefaultReleaseBase+"/tag/"+tag)
	case DefaultReleaseBase + "/download/" + tag + "/" + AssetName(g.version):
		resp.StatusCode = http.StatusOK
		resp.Body, resp.ContentLength = io.NopCloser(bytes.NewReader(g.binary)), int64(len(g.binary))
	case DefaultReleaseBase + "/download/" + tag + "/SHA256SUMS":
		sum := sha256.Sum256(g.binary)
		sums := hex.EncodeToString(sum[:]) + "  " + AssetName(g.version) + "\n"
		resp.StatusCode = http.StatusOK
		resp.Body, resp.ContentLength = io.NopCloser(strings.NewReader(sums)), int64(len(sums))
	}
	resp.Status = fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	return resp, nil
}

// TestAnUpgradeGivenNoLocationAsksTheDestination: with no --from, the
// upgrade asks DefaultReleaseBase what it calls latest, reads the tag from
// GitHub's redirect without following it, and fetches that release's
// binary and SHA256SUMS from under the same location — three requests, all
// at the destination — and the binary it verified is the one in place.
func TestAnUpgradeGivenNoLocationAsksTheDestination(t *testing.T) {
	exe, _ := upgradeEnv(t)
	rel := &githubReleases{version: "9.9.9", binary: []byte("the release published at the destination")}
	var out strings.Builder
	if err := Upgrade(render.New(&out, false, false), UpgradeOptions{
		Exe: exe, Client: &http.Client{Transport: rel}, Restart: func() error { return nil },
	}); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, out.String())
	}
	want := []string{
		"GET " + DefaultReleaseBase + "/latest",
		"GET " + DefaultReleaseBase + "/download/v9.9.9/" + AssetName("9.9.9"),
		"GET " + DefaultReleaseBase + "/download/v9.9.9/SHA256SUMS",
	}
	if !reflect.DeepEqual(rel.asked, want) {
		t.Errorf("the upgrade asked:\n  %s\nwant:\n  %s", strings.Join(rel.asked, "\n  "), strings.Join(want, "\n  "))
	}
	if got, _ := os.ReadFile(exe); string(got) != "the release published at the destination" {
		t.Errorf("the binary in place is %q, not the release that was verified", got)
	}
	if !strings.Contains(out.String(), "checksum verified") {
		t.Errorf("the board does not say the checksum was verified:\n%s", out.String())
	}
}
