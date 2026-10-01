<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Podaro console

The console's static assets, embedded into the binary (`embed.go`) and served
by the gateway at `/assets/…` on every console hostname. Pages and fragments
are Go `html/template`s in `internal/console` — server-rendered, content-
negotiated from the same handlers that serve JSON. Nothing here is
fetched from anywhere at runtime: fonts, htmx, and Alpine are vendored and
pinned in `VENDOR.md`; the console makes zero external requests.
`podaro system install` extracts this directory into the state
directory for inspection; the gateway serves the embedded bytes.
