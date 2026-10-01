// SPDX-License-Identifier: AGPL-3.0-only
//
// The theme, before first paint (UX §4, plan S12). The console's shell
// loads this synchronously, ahead of its stylesheet, so the page's first
// paint already wears the theme this browser chose: a page that painted
// light and then turned dark would be the flash the rule against
// unbidden motion forbids. The choice is the browser's alone — held in
// localStorage, never sent to the engine, never a cookie — and it is
// read here and nowhere earlier. Nothing stored means System: the
// stylesheet follows the OS through prefers-color-scheme. A browser
// that refuses storage is left on System, which is correct.
//
// First-party, not vendored (console/VENDOR.md pins vendored assets);
// an external file under the console's `script-src 'self'`, never an
// inline script.
(function () {
  try {
    var choice = window.localStorage.getItem("podaro.theme");
    if (choice === "light" || choice === "dark") {
      document.documentElement.dataset.theme = choice;
    }
  } catch (_) {
    // Storage refused: the page is System-themed, as a page with no
    // choice is.
  }
})();
