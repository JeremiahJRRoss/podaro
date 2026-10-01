<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Vendored console assets

The console's third-party assets are **vendored and version-pinned
in-repo** — no CDN, no external request, ever. This file is the pin. Every asset below was fetched from the
npm registry tarball named, the tarball verified against the registry's
`integrity` digest, and the file copied unmodified. Update an asset by
updating this table in the same commit; CI (`TestVendoredAssetsMatchManifest`)
refuses a file whose digest differs from its row.

| File (`console/assets/…`) | Package · version | License | Tarball integrity (sha512, base64) | File sha256 |
|---|---|---|---|---|
| `htmx.min.js` | `htmx.org` 2.0.10 (`dist/htmx.min.js`) | 0BSD | `kdeJe7ZVwaS6QMz/ebBIVtZdpwen6L0OQ5GOhPV9MKBb196TCZeZu4yA7ZIQsaLKv7EpXz+So7KSXNuHXhj7Cw==` | `71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de` |
| `alpine-csp.min.js` | `@alpinejs/csp` 3.17.1 (`dist/cdn.min.js`) | MIT | `HDrY0ZxvJWSmeUYqtHVSsitaqy1es3VDCNodPpdQRX4nHhHiRoeib+rOzRFFStFRD/6x0KmQzJVJ4FCLAI/DUQ==` | `dd45019f9fba2b5edd4cfdc5870df1acb22d918a0ede0d0a0699ae0c866049bf` |
| `sse.min.js` | `htmx-ext-sse` 2.2.4 (`dist/sse.min.js`) | 0BSD | `LJmxVhykyflBWgh5PvbRidcyuqMHlgfajmmzumvKctv9puvsufeH6OaejSMZTNTnEI8O2wXXn4ZZtBdpEMqmEQ==` | `98a46496de0c3605fbffdce9167ba427bdd9553184f83f149c261891a92c0136` |
| `fonts/poppins-latin-600-normal.woff2` | `@fontsource/poppins` 5.3.0 (`files/poppins-latin-600-normal.woff2`) | OFL-1.1 | `cms1nM7U6SN8epIV1WMVOV8VsA645aSm3wHfzIQnkk188U341ThbJGSl2Sv54V29gnDbT2arMPfLzvVIIVCceQ==` | `f4e80d9dfd374d02989b87a27b5ed4cb78fbb177c27f1478e9a8b0afb7513149` |
| `fonts/inter-latin-400-normal.woff2` | `@fontsource/inter` 5.3.0 (`files/inter-latin-400-normal.woff2`) | OFL-1.1 | `RofMylZmjlJEfELXeNHFWBRcSs75rGU/6bV2S2jfnvv/3rPXPGe0LgUJTklcHZ9lM4OZmAVFhcJPnACfb91A3g==` | `8909904ab6c872eb994093482a88a28eca2cd95912d7b6fecd72103b0dc07edc` |
| `fonts/inter-latin-500-normal.woff2` | `@fontsource/inter` 5.3.0 | OFL-1.1 | (same) | `f3779f1efccc4bdcdf9c0a02ab95bf6bd092ed09c48c08cedc725889edd1d19f` |
| `fonts/inter-latin-600-normal.woff2` | `@fontsource/inter` 5.3.0 | OFL-1.1 | (same) | `f9a06e79cd3a2a20951c0f0e28f66dd0e6d3fda73911d640a2125c8fcb78f21a` |
| `fonts/IBMPlexMono-Regular-Latin1.woff2` | `@ibm/plex-mono` 2.5.0 | OFL-1.1 | `STBJIPxPomOYPmBMO7z5TKPJUotAF9u3gAUumTqVgwgrAO+K4FRNh0MlhsoJjKhJKsMbBJR10/bk4inkj/wc1w==` | `e8993d946649b9d01abb1ed06d574b19d8ea3e66b5c3948602db335c44c18e56` |
| `fonts/IBMPlexMono-Medium-Latin1.woff2` | `@ibm/plex-mono` 2.5.0 | OFL-1.1 | (same) | `41201b658a328b9d00368215c2f1102770f80b15952ab82631e4006255e6365d` |
| `fonts/IBMPlexMono-SemiBold-Latin1.woff2` | `@ibm/plex-mono` 2.5.0 | OFL-1.1 | (same) | `b7acd05041ab65f3b7039e218ddd893065e11a07e85ea85019473152a51b6b7d` |

**Code a vendored file bundles.** `@alpinejs/csp` builds `dist/cdn.min.js`
with Vue's reactivity system compiled in: the registry's metadata for 3.17.1
requires `@vue/reactivity` `~3.5.40`, which requires `@vue/shared` at its own
version, and the bundle's closing licence comment names the versions it
carries — 3.5.41 of both, inside that range. Both are MIT, with the same
licence text in the two tarballs, reproduced at `assets/LICENSES/vue.txt`;
`NOTICE` credits them beside Alpine. Read from the registry on 2026-09-28,
each tarball verified against its `integrity` digest. A row here pins no file
of its own: the file it names is pinned above.

| Bundled in (`console/assets/…`) | Package · version | License | Tarball integrity (sha512, base64) | License text |
|---|---|---|---|---|
| `alpine-csp.min.js` | `@vue/reactivity` 3.5.41 | MIT | `rznsqKM0np0x18EjzF8x88MpEhdNsffbvFbckLL5+oUKz1BxAImEmO7J1ArRYSyo6aQaVoBDp7jEkT91OOxydA==` | `assets/LICENSES/vue.txt` |
| `alpine-csp.min.js` | `@vue/shared` 3.5.41 | MIT | `IOnwSCma8j+9xJT6b8H0dEYidC80NsYmNMlZxRsukYcSoGaDBohog5hDxzeUXdFeGWFA++vWvxqOmrr96VlqMA==` | `assets/LICENSES/vue.txt` |

**The SSE extension's license.** `htmx-ext-sse`'s npm metadata carries no
`license` field; the tarball's own `LICENSE` file is the BSD Zero Clause
License, the same licence htmx itself ships under, and it is reproduced at
`assets/LICENSES/htmx-ext-sse.txt`. This extension is how SSE drives the
console's live regions.

**Why the CSP build of Alpine.** The console ships with a strict
`Content-Security-Policy` (`script-src 'self'`, no `unsafe-eval`); Alpine's
standard build evaluates expressions with `new Function`, which that policy
forbids. `@alpinejs/csp` is Alpine's own CSP-compatible build (expressions are
limited to property and method references) — enough for the purely local state
the console keeps in Alpine. htmx runs with `allowEval: false` for the same
reason — the shell's `<meta name="htmx-config">` carries it, so the setting is
read before htmx loads.

**Fonts.** The console uses three faces: **Poppins** 600 for display,
**Inter** 400/500/600 for reading and UI, and **IBM Plex Mono** 400/500/600
for the status grammar — the only weights it ships. Latin subsets
only, ~140 KB in total. Poppins and Inter come from `@fontsource/*`, which
publishes the Google Fonts builds as npm packages with the licence in the
tarball; the kit that inspired the type ships font binaries with no
provenance, so they are not the source. IBM Plex Sans is not shipped —
Plex Mono stays because Podaro's mono is load-bearing, and its glyph set
must render identically on every machine.

All three are licensed under the SIL Open Font License 1.1. Plex reserves the
font name "Plex"; the Poppins and Inter texts as published declare **no**
Reserved Font Name, so the files are shipped under their own names, which is
what the OFL asks in either case. License texts: `assets/LICENSES/htmx.txt`,
`assets/LICENSES/ibm-plex-mono.txt`, `assets/LICENSES/poppins.txt`,
`assets/LICENSES/inter.txt`, and `assets/LICENSES/vue.txt` for the Vue code
Alpine's build bundles; Alpine's MIT notice is reproduced in `NOTICE`.
The fonts are content embedded in the binary, not code compiled into it,
so the `go-licenses` gate does not see them.
