// SPDX-License-Identifier: AGPL-3.0-only
//
// Plan S7 acceptance: the console walked in a real browser, keyboard
// only. Chromium is driven over the DevTools protocol directly — Node's
// own WebSocket, no npm dependency — so this script adds nothing to the
// repository's supply chain (ADR-0003's spirit: the console ships what
// it ships, and its test does not drag a toolchain behind it).
//
// It asserts the things a golden cannot: that the page loads and runs,
// that the keyboard map moves the rail, that Verify reports a result,
// and — the one UX §2 principle a unit test cannot check — that the
// browser makes no request off this origin.

const [, , base, instance, user, pass, outDir, fallen] = process.argv;
if (!outDir) {
  console.error("usage: console_walk.mjs <base-url> <instance> <user> <pass> <out-dir> [regressed-instance]");
  process.exit(2);
}
const fs = await import("node:fs/promises");
const CDP_PORT = process.env.CDP_PORT || "9333";

let nextId = 0;
const pending = new Map();
const events = [];

function send(ws, method, params, sessionId) {
  const id = ++nextId;
  ws.send(JSON.stringify({ id, method, params: params || {}, sessionId }));
  return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
}

async function main() {
  const version = await (await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`)).json();
  const ws = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise((r) => (ws.onopen = r));
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) {
      const p = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? p.reject(new Error(JSON.stringify(msg.error))) : p.resolve(msg.result);
    } else if (msg.method) {
      events.push(msg);
    }
  };

  const { targetId } = await send(ws, "Target.createTarget", { url: "about:blank" });
  const { sessionId } = await send(ws, "Target.attachToTarget", { targetId, flatten: true });
  const S = sessionId;
  await send(ws, "Page.enable", {}, S);
  await send(ws, "Runtime.enable", {}, S);
  await send(ws, "Network.enable", {}, S);
  await send(ws, "Security.setIgnoreCertificateErrors", { ignore: true }, S);

  const failures = [];
  const check = (ok, what) => {
    console.log(`${ok ? "✓" : "✗"} ${what}`);
    if (!ok) failures.push(what);
  };

  async function goto(url) {
    await send(ws, "Page.navigate", { url }, S);
    await settle();
    await pageText(url);
  }
  // The text of every page the walk visits, as a person reads it — the
  // title, the address and the rendered text, taken on each navigation and
  // with each screenshot — dumped to page-text.txt at the end, beside the
  // DOM dumps. The identity guard (the reconciliation plan's R6,
  // hack/identity_guard.sh) scans it: a name in the rendered console is
  // what a clean source scan alone cannot see.
  const pageTexts = [];
  async function pageText(label) {
    let text;
    try {
      text = await evaluate(`["title: " + document.title, "address: " + location.href, document.body ? document.body.innerText : ""].join("\\n")`);
    } catch (e) {
      text = `(no text: ${e.message.split(" :: ")[0]})`;
    }
    pageTexts.push(`==> ${label} <==\n${text}\n`);
  }
  async function settle(ms = 900) {
    await new Promise((r) => setTimeout(r, ms));
  }
  async function evaluate(expr) {
    const r = await send(ws, "Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true }, S);
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text + " :: " + expr);
    return r.result.value;
  }
  async function key(text) {
    for (const type of ["keyDown", "char", "keyUp"]) {
      await send(ws, "Input.dispatchKeyEvent", { type, text, key: text, unmodifiedText: text }, S);
    }
    await settle(400);
  }
  // A key that types nothing. `key` above sends `text`, which is what a
  // printing key does; a keyDown carrying text is not how Chromium
  // delivers Arrow or Enter, and the page never sees them.
  async function press(name) {
    const codes = { ArrowLeft: 37, ArrowUp: 38, ArrowRight: 39, ArrowDown: 40, Home: 36, End: 35, Enter: 13, Tab: 9 };
    // Enter is the exception: a focused button activates on the key's
    // own default action, and Chromium runs that only for a keyDown
    // carrying the carriage return. A rawKeyDown Enter arrives at the
    // page and presses nothing.
    const text = name === "Enter" ? { text: "\r", unmodifiedText: "\r" } : {};
    for (const type of [name === "Enter" ? "keyDown" : "rawKeyDown", "keyUp"]) {
      await send(ws, "Input.dispatchKeyEvent",
        { type, key: name, code: name, windowsVirtualKeyCode: codes[name], nativeVirtualKeyCode: codes[name], ...text }, S);
    }
    await settle(300);
  }
  async function shot(name, size) {
    const params = size
      ? { format: "png", captureBeyondViewport: true, clip: { x: 0, y: 0, width: size.width, height: size.height, scale: 1 } }
      : { format: "png" };
    const { data } = await send(ws, "Page.captureScreenshot", params, S);
    await fs.writeFile(`${outDir}/${name}.png`, Buffer.from(data, "base64"));
    const html = await evaluate("document.documentElement.outerHTML");
    await fs.writeFile(`${outDir}/${name}.html`, html);
    await pageText(name);
  }

  // 1. Sign in through the form, as a person does.
  await goto(`${base}/login`);
  check(await evaluate(`!!document.querySelector('form input[name="username"]')`), "the login page renders its form");
  // The sign-in page starts with focus in its form and offers no skip
  // link: there is nothing before the form to skip, and a link rendered
  // there came after the autofocus and was never the first tab stop it
  // claimed to be.
  const signIn = await evaluate(`(() => {
    const focus = document.activeElement === document.querySelector('form input[name="username"]');
    const skip = !!document.querySelector('.skip-link');
    return (focus ? "focus-in-form" : "focus-on:" + (document.activeElement?.tagName || "none")) + (skip ? ",skip-link-present" : ",no-skip-link");
  })()`);
  check(signIn === "focus-in-form,no-skip-link", `the sign-in page starts in its form and has nothing to skip (${signIn})`);
  await evaluate(`(() => {
    const f = document.querySelector('form');
    f.querySelector('[name=username]').value = ${JSON.stringify(user)};
    f.querySelector('[name=password]').value = ${JSON.stringify(pass)};
    f.submit();
  })()`);
  await settle(1200);
  await shot("01-signed-in");

  // 2. The instance console: the lab surface, assembled.
  const instURL = base.replace("https://", `https://${instance}.`);
  await goto(`${instURL}/`);
  await settle(1200);
  await shot("02-lab-surface");
  check(await evaluate(`!!document.querySelector('.start-here')`), "the start-here card is present");
  check(await evaluate(`document.querySelectorAll('.start-here').length === 1`), "exactly one start-here card");
  check(await evaluate(`!!document.querySelector('#tab-overview') && !!document.querySelector('#tab-evidence')`), "the tab strip has Overview and Evidence");
  check(await evaluate(`!!document.querySelector('.ladder-rows')`), "the ladder renders its rows");
  check(await evaluate(`!!document.querySelector('#rail')`), "the rail region is present");

  // 2b. Manual §7's Overview: the instance facts and the credentials,
  // the latter fetched when the Overview is first shown. Values are
  // never present — the twin has none — so the mask is what stands.
  check(await evaluate(`!!document.querySelector('.facts')`), "the Overview carries the instance facts");
  check(await evaluate(`!!document.querySelector('.credentials table, .credentials .empty')`), "the credentials list loaded on the Overview");
  check(await evaluate(`!document.querySelector('.credentials') || !!document.querySelector('.credentials .masked') || !!document.querySelector('.credentials .empty')`), "credentials are masked, never values");
  check(await evaluate(`!!document.querySelector('.statusbar [data-tab-link="evidence"]')`), "the status bar offers Evidence");
  check(await evaluate(`[...document.querySelectorAll('.statusbar .button')].some(b => /Reset/.test(b.textContent))`), "the status bar offers Reset");
  check(await evaluate(`![...document.querySelectorAll('.statusbar .button')].some(b => /Destroy/i.test(b.textContent))`), "destroy stays on the command line");

  // 2c. The console uses the browser (plan S11, treatment 0006 §1–§2):
  // the rail is the left column, the surface is 95vw — a 2.5vw gutter
  // each side, no maximum — and a product panel is as tall as the
  // window. Measured with boxes at the desktop width the walk already
  // uses, not read back from the stylesheet.
  await send(ws, "Emulation.setDeviceMetricsOverride",
    { width: 1600, height: 900, deviceScaleFactor: 1, mobile: false }, S);
  await settle(300);
  const columns = await evaluate(`(() => {
    const w = window.innerWidth;
    if (w <= 1200) return "viewport-too-narrow:" + w;
    const rail = document.querySelector('.rail-region');
    const workspace = document.querySelector('#workspace');
    if (!rail || !workspace) return "missing-region";
    const r = rail.getBoundingClientRect(), s = workspace.getBoundingClientRect();
    const gutter = Math.max(w * 0.025, 16);
    const out = [];
    if (r.right > s.left) out.push("rail-not-left:" + Math.round(r.right) + ">" + Math.round(s.left));
    if (Math.abs(r.left - gutter) > 1) out.push("left-gutter:" + r.left.toFixed(1) + "/" + gutter.toFixed(1));
    if (Math.abs((w - s.right) - gutter) > 1) out.push("right-gutter:" + (w - s.right).toFixed(1) + "/" + gutter.toFixed(1));
    if (!(rail.compareDocumentPosition(workspace) & Node.DOCUMENT_POSITION_FOLLOWING)) out.push("rail-after-workspace-in-dom");
    return out.length ? out.join(",") : "left-column,gutter:" + Math.round(gutter) + ",rail:" + Math.round(r.width) + ",workspace:" + Math.round(s.width);
  })()`);
  check(columns.startsWith("left-column"), `the rail is the left column, first in the document, and the surface is 95vw (${columns})`);
  const tall = await evaluate(`(() => {
    const w = window.innerWidth;
    const product = [...document.querySelectorAll('.tabs [data-tab]')].find((t) => t.dataset.kind === 'iframe');
    if (!product) return "no-iframe-tab";
    product.click();
    const panel = document.getElementById('panel-' + product.dataset.tab);
    if (!panel || panel.hidden) return "panel-not-shown";
    const main = document.querySelector('main');
    const m = main.getBoundingClientRect();
    const floor = m.bottom - parseFloat(getComputedStyle(main).paddingBottom);
    const p = panel.getBoundingClientRect();
    const frame = panel.querySelector('iframe');
    const f = frame ? frame.getBoundingClientRect() : p;
    const out = [];
    if (Math.abs(p.bottom - floor) > 4) out.push("panel-bottom:" + Math.round(p.bottom) + "/" + Math.round(floor));
    if (Math.abs(f.bottom - floor) > 4) out.push("frame-bottom:" + Math.round(f.bottom) + "/" + Math.round(floor));
    if (p.width < w * 0.6) out.push("panel-width:" + Math.round(p.width) + "<" + Math.round(w * 0.6));
    return out.length ? out.join(",") : "window-tall:" + Math.round(p.width) + "x" + Math.round(p.height) + " of " + w + "x" + window.innerHeight;
  })()`);
  check(tall.startsWith("window-tall:"), `a product panel is as tall as the window and at least 60% of it wide (${tall})`);
  await key("1");
  // The skip link (UX §9): the first tab stop on the page, and Enter on
  // it puts the next Tab inside the workspace — past the status bar and
  // the whole rail. Walked with the keys, not with focus() alone.
  const skipFirst = await evaluate(`(() => {
    const a = document.querySelector('.skip-link');
    if (!a) return "no-skip-link";
    const stops = [...document.querySelectorAll('a[href], button, input, select, textarea, [tabindex]')]
      .filter((el) => !el.disabled && el.tabIndex >= 0 && (el === a || el.getClientRects().length > 0));
    if (stops[0] !== a) return "first-stop-is:" + (stops[0] ? stops[0].tagName + "." + stops[0].className : "none");
    if (a.hash !== '#workspace') return "targets:" + a.hash;
    a.focus();
    return a.getBoundingClientRect().top >= 0 ? "first-stop,shown-when-focused" : "first-stop,hidden-when-focused";
  })()`);
  await press("Enter");
  await press("Tab");
  const skipLands = await evaluate(`(() => {
    const el = document.activeElement;
    if (!el || el === document.body) return "focus-on-body";
    return el.closest('#workspace') ? "lands-in-workspace:" + el.tagName + (el.id ? "#" + el.id : "") : "lands-on:" + el.tagName + "." + el.className;
  })()`);
  check(skipFirst === "first-stop,shown-when-focused" && skipLands.startsWith("lands-in-workspace:"),
    `the skip link is the first tab stop and lands in the workspace (${skipFirst}; ${skipLands})`);
  await send(ws, "Emulation.clearDeviceMetricsOverride", {}, S);
  await settle(200);

  // 2c-type. The three faces (UX §4, plan S13). A stylesheet can name a
  // font that never arrives; only the browser knows whether it loaded
  // and is being used. The kit's own mechanics are measured here too —
  // a learner's control is 44 px, the current step's index is the
  // list's counter rendered as two digits, and the selected tab is an
  // ink rule rather than a box.
  await send(ws, "Emulation.setDeviceMetricsOverride",
    { width: 1600, height: 900, deviceScaleFactor: 1, mobile: false }, S);
  await goto(`${instURL}/`);
  await settle(900);
  const faces = await evaluate(`(async () => {
    await document.fonts.ready;
    const has = (spec) => document.fonts.check(spec);
    return ['600 16px Poppins:' + has('600 16px Poppins'), '400 16px Inter:' + has('400 16px Inter'),
            '400 16px "IBM Plex Mono":' + has('400 16px "IBM Plex Mono"')].join(', ');
  })()`);
  check(!faces.includes(":false"), `the three faces load and are used (${faces})`);
  const facesUsed = await evaluate(`(() => {
    const fam = (el) => el ? getComputedStyle(el).fontFamily.split(',')[0].replace(/"/g, '') : 'missing';
    return fam(document.querySelector('.statusbar .brand')) + '/' + fam(document.body) + '/' + fam(document.querySelector('.ladder-bar')) + '/' + fam(document.querySelector('.instance-name'));
  })()`);
  check(facesUsed === "Poppins/Inter/IBM Plex Mono/IBM Plex Mono",
    `display is Poppins, reading is Inter, the ladder and the instance name are Plex Mono (${facesUsed})`);

  // A scroll container clips what leaves it, a focus ring included — so
  // a control at the edge of one can lose the ring UX §9 promises. The
  // ring is read as the browser resolves it, with `:focus-visible`
  // forced through the protocol, and then either it is inset (nothing
  // can clip it) or it must fit the scrollport across the axis that
  // does not scroll.
  await send(ws, "DOM.enable", {}, S);
  await send(ws, "CSS.enable", {}, S);
  const ringRoomOf = async (cases) => {
    const doc = await send(ws, "DOM.getDocument", { depth: 1 }, S);
    const out = [];
    for (const [name, boxSel, ctlSel, axis] of cases) {
      const hit = await send(ws, "DOM.querySelector", { nodeId: doc.root.nodeId, selector: ctlSel }, S);
      if (!hit.nodeId) { out.push(name + ":missing"); continue; }
      await send(ws, "CSS.forcePseudoState", { nodeId: hit.nodeId, forcedPseudoClasses: ["focus-visible"] }, S);
      out.push(await evaluate(`(() => {
        const box = document.querySelector(${JSON.stringify(boxSel)}), ctl = document.querySelector(${JSON.stringify(ctlSel)});
        const s = getComputedStyle(ctl);
        const off = parseFloat(s.outlineOffset) || 0, w = parseFloat(s.outlineWidth) || 0;
        if (w === 0 || s.outlineStyle === 'none') return ${JSON.stringify(name)} + ':no-ring';
        if (off < 0) return ${JSON.stringify(name)} + ':inset';
        const b = box.getBoundingClientRect(), c = ctl.getBoundingClientRect();
        const room = ${JSON.stringify(axis)} === 'x'
          ? Math.min(c.left - b.left, b.right - c.right)
          : Math.min(c.top - b.top, b.bottom - c.bottom);
        return ${JSON.stringify(name)} + ':' + Math.round(room - off - w);
      })()`));
      await send(ws, "CSS.forcePseudoState", { nodeId: hit.nodeId, forcedPseudoClasses: [] }, S);
    }
    return out.join(",");
  };
  const ringFits = (room) => room.split(",").every((r) => { const v = r.split(":")[1]; return v === "inset" || Number(v) >= 0; });
  const ringRoom = await ringRoomOf([
    // The chooser's own action, which starts at the rail column's
    // content edge. Not a step's button, which is indented into the
    // grid's second column, and not the dismiss button, whose float
    // sits inside the scrollbar's gutter — either would have had
    // room to spare and passed whatever the inset was.
    ["rail", ".rail-region", ".playbook-actions .button", "x"],
    ["tabs", ".tabs", '.tabs [role="tab"]', "y"],
  ]);
  check(ringFits(ringRoom),
    `every focused control keeps its whole ring inside its scrollport (${ringRoom})`);

  // 2c-kit. The kit's mechanics, measured: a learner's control at 44 px,
  // the numbered step, the underlined tab.
  await evaluate(`(() => { const b = [...document.querySelectorAll('.playbook-actions a')].find((a) => a.textContent.trim() === 'Open'); if (b) b.click(); return !!b; })()`);
  await settle(900);
  const controlHeight = await evaluate(`(() => {
    const b = document.querySelector('.rail .button.primary, .rail .button');
    return b ? Math.round(b.getBoundingClientRect().height) : 0;
  })()`);
  check(controlHeight >= 44, `a control in the rail is at least 44px tall (${controlHeight}px)`);
  // The index is generated content, and Chromium does not resolve a
  // counter in `getComputedStyle(el, '::before').content` — it hands
  // back the `counter()` expression, which says the stylesheet asked
  // and not that the browser drew. The rendered digits are in the
  // accessibility tree, which is also where a screen reader finds them,
  // so that is what the walk reads. The tile's geometry is measured
  // beside it: a 44 px square in the gutter.
  await send(ws, "DOM.enable", {}, S);
  await send(ws, "Accessibility.enable", {}, S);
  const numeral = await (async () => {
    const doc = await send(ws, "DOM.getDocument", { depth: 1 }, S);
    const hit = await send(ws, "DOM.querySelector", { nodeId: doc.root.nodeId, selector: ".step.current" }, S);
    if (!hit.nodeId) return "no-step";
    const ax = await send(ws, "Accessibility.getPartialAXTree", { nodeId: hit.nodeId, fetchRelatives: true }, S);
    const names = (ax.nodes || []).map((n) => n.name && n.name.value).filter((v) => typeof v === "string").map((v) => v.trim());
    const two = names.find((v) => /^\d{2}$/.test(v));
    return two || "names:" + names.slice(0, 8).join("|");
  })();
  check(/^\d{2}$/.test(numeral), `the step's index is drawn in the gutter as two digits (${numeral})`);
  const tile = await evaluate(`(() => {
    const step = document.querySelector('.step.current') || document.querySelector('.step');
    if (!step) return 'no-step';
    const b = getComputedStyle(step, '::before');
    const col = getComputedStyle(step).gridTemplateColumns.split(' ')[0];
    return b.width + 'x' + b.height + ' in ' + col;
  })()`);
  check(tile === "44px x 44px in 44px".replace(/ x /, "x"), `the index sits in a 44px gutter tile (${tile})`);
  const tabRule = await evaluate(`(() => {
    const tab = document.querySelector('.tabs [aria-selected="true"]');
    if (!tab) return 'no-tab';
    const s = getComputedStyle(tab);
    return s.borderBottomWidth + '/' + s.borderBottomStyle + '/' + (s.borderTopWidth === '0px' && s.borderLeftWidth === '0px' ? 'no-box' : 'boxed');
  })()`);
  check(tabRule === "2px/solid/no-box", `the selected tab is a 2px rule, not a box (${tabRule})`);
  await send(ws, "Emulation.clearDeviceMetricsOverride", {}, S);
  await settle(200);

  // 2d. Themes (UX §4, plan S12). Three things a golden cannot say:
  // that a choice made on the control is the page's theme and survives
  // a reload and a change of page; that nothing is stored until a
  // choice is made; and that every pair of colours the console draws
  // clears its ratio in a real browser, in both themes. The ratios are
  // WCAG's own formula, computed here on getComputedStyle — no
  // dependency, and the treatment's numbers measured rather than
  // asserted. The plate is dark in both themes, so its pairs are held
  // to 6:1; text and the status tokens on the page to AA's 4.5:1.
  const colourLib = `
    const parse = (s) => {
      s = (s || '').trim();
      let m = s.match(/^rgba?\\(([^)]+)\\)$/);
      if (m) { const p = m[1].split(',').map(Number); return p.length >= 4 && p[3] === 0 ? null : p.slice(0, 3); }
      m = s.match(/^#([0-9a-f]{6})$/i);
      if (m) return [0, 2, 4].map((i) => parseInt(m[1].slice(i, i + 2), 16));
      return null;
    };
    const lum = ([r, g, b]) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
    const ratio = (a, b) => { const la = lum(a), lb = lum(b); return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05); };
    const bgOf = (el) => { for (let e = el; e; e = e.parentElement) { const c = parse(getComputedStyle(e).backgroundColor); if (c) return c; } return [255, 255, 255]; };
    const fg = (el) => parse(getComputedStyle(el).color);
    const token = (el, name) => parse(getComputedStyle(el).getPropertyValue(name));
  `;
  const themeState = () => evaluate(`(() => {
    let stored = null;
    try { stored = localStorage.getItem('podaro.theme'); } catch (_) {}
    const pressed = document.querySelector('.theme [aria-pressed="true"]');
    return (document.documentElement.dataset.theme || 'system') + '/' + (stored || 'none') + '/' + (pressed ? pressed.dataset.themeChoice : 'none');
  })()`);
  const chooseTheme = async (choice) => {
    await evaluate(`(() => { const b = document.querySelector('.theme [data-theme-choice="${choice}"]'); if (b) b.click(); return !!b; })()`);
    await settle(300);
  };
  // The primary action is the plate in light and the inverted ink in
  // dark (plan S13 task 3, treatment §3). A ratio cannot tell those
  // apart from the ink pair, which also clears AA — so the fill itself
  // is read.
  const primaryFill = () => evaluate(`(() => {
    const b = document.querySelector('.button.primary');
    return b ? getComputedStyle(b).backgroundColor : 'no-primary-action';
  })()`);
  const contrast = () => evaluate(`(() => {
    ${colourLib}
    const out = [];
    const need = (name, f, b, min) => { if (!f || !b) { out.push(name + ':unreadable'); return; } const r = ratio(f, b); if (r < min) out.push(name + ':' + r.toFixed(2) + '<' + min); };
    const main = document.querySelector('main');
    const bar = document.querySelector('.statusbar');
    need('text', fg(main), bgOf(main), 4.5);
    const muted = main.querySelector('.muted');
    if (muted) need('muted', fg(muted), bgOf(muted), 4.5);
    need('plate-text', fg(bar), bgOf(bar), 6);
    const who = bar.querySelector('.who');
    if (who) need('plate-muted', fg(who), bgOf(who), 6);
    const pressed = bar.querySelector('.theme [aria-pressed="true"]');
    if (pressed) need('control', fg(pressed), bgOf(pressed), 4.5);
    // The primary action is the plate in light and the inverted ink in
    // dark (plan S13 task 3), so its own pair is sampled in both.
    const primary = document.querySelector('.button.primary');
    if (primary) need('primary-action', fg(primary), bgOf(primary), 4.5);
    for (const t of ['ready', 'progress', 'pending', 'warn', 'fail', 'attest']) {
      need('status-' + t, token(document.documentElement, '--status-' + t), bgOf(main), 4.5);
      need('plate-status-' + t, token(bar, '--status-' + t), bgOf(bar), 6);
    }
    return out.length ? out.join(',') : 'all-clear';
  })()`);
  await send(ws, "Emulation.setDeviceMetricsOverride",
    { width: 1600, height: 900, deviceScaleFactor: 1, mobile: false }, S);
  await evaluate(`(() => { try { localStorage.removeItem('podaro.theme'); } catch (_) {} return true; })()`);
  await goto(`${instURL}/`);
  await settle(800);
  const fresh = await themeState();
  check(fresh === "system/none/system", `a fresh page is System, with nothing stored and System pressed (${fresh})`);
  await chooseTheme("light");
  const lightNow = await themeState();
  const lightContrast = await contrast();
  check(lightNow === "light/light/light", `Light pressed is the page's theme, stored and pressed (${lightNow})`);
  check(lightContrast === "all-clear", `every sampled pair clears its ratio in Light (${lightContrast})`);
  const lightPrimary = await primaryFill();
  check(lightPrimary === "rgb(17, 17, 15)", `Light fills the primary action with the plate (${lightPrimary})`);
  await goto(`${instURL}/`);
  await settle(800);
  const lightKept = await themeState();
  check(lightKept === "light/light/light", `Light survives a reload (${lightKept})`);
  await chooseTheme("dark");
  const darkNow = await themeState();
  const darkContrast = await contrast();
  check(darkNow === "dark/dark/dark", `Dark pressed is the page's theme, stored and pressed (${darkNow})`);
  check(darkContrast === "all-clear", `every sampled pair clears its ratio in Dark (${darkContrast})`);
  const darkPrimary = await primaryFill();
  check(darkPrimary === "rgb(229, 229, 223)", `Dark inverts the primary action to the ink (${darkPrimary})`);
  await goto(`${instURL}/`);
  await settle(800);
  const darkKept = await themeState();
  check(darkKept === "dark/dark/dark", `Dark survives a reload (${darkKept})`);
  // The instance list is its own origin (lab.test beside walk.lab.test)
  // and localStorage is the origin's: a choice made on an instance is
  // that instance's, and the list holds its own. That is D4's price and
  // B3's point — a cookie on the parent domain would be the one thing
  // that crossed the instance boundary — so the walk asserts the truth,
  // not the wish: the list opens System with nothing stored, a choice
  // made there survives its own reload, and the instance keeps the
  // choice made on it.
  await goto(`${base}/`);
  await settle(800);
  const listFresh = await themeState();
  check(listFresh === "system/none/system", `the instance list is its own origin and holds its own choice: none yet (${listFresh})`);
  await chooseTheme("light");
  await goto(`${base}/`);
  await settle(800);
  const listKept = await themeState();
  check(listKept === "light/light/light", `a choice made on the instance list survives its reload (${listKept})`);
  await chooseTheme("system");
  await goto(`${instURL}/`);
  await settle(800);
  const instanceKept = await themeState();
  check(instanceKept === "dark/dark/dark", `the instance keeps the choice made on it (${instanceKept})`);
  await chooseTheme("system");
  const backToSystem = await themeState();
  check(backToSystem === "system/none/system", `System pressed forgets the choice (${backToSystem})`);
  // Storage refused (a private window, blocked site data): the page still
  // switches for its lifetime, and the control presses what was chosen,
  // not what storage holds — which is nothing.
  // The refusal is the page's own setItem throwing; a reload
  // is a fresh page with nothing stored, so it opens System.
  await evaluate(`(() => { Storage.prototype.setItem = function () { throw new Error("storage refused"); }; return true; })()`);
  await chooseTheme("dark");
  const refused = await themeState();
  check(refused === "dark/none/dark", `a refused storage write keeps the page's theme and the pressed choice together (${refused})`);
  await goto(`${instURL}/`);
  await settle(800);
  const afterRefused = await themeState();
  check(afterRefused === "system/none/system", `nothing was stored, so the next page opens System (${afterRefused})`);
  await send(ws, "Emulation.clearDeviceMetricsOverride", {}, S);
  await settle(200);

  // 2e. The regression (UX §5, plan S14). A ladder that has fallen from
  // ready wears `--status-warn` in the condensed bar and says so in
  // words. Four things at once, because the colour must never be the
  // only carrier: the class, the colour actually computed (compared
  // against the token resolved in the bar's own context, so the check
  // survives a change to either value), the accessible name, and the
  // sentence in the live region. The driver has already driven `fallen`
  // to ready and then broken a gate baseline under it; `walk` is the
  // control, and stands where it always did.
  if (fallen) {
    const fallenURL = base.replace("https://", `https://${fallen}.`);
    const barState = () => evaluate(`(() => {
      ${colourLib}
      const bar = document.querySelector('#statusbar-ladder');
      if (!bar) return 'no-bar';
      const warn = token(bar, '--status-warn'), got = fg(bar);
      const region = document.querySelector('#statusbar-regression');
      return [
        bar.classList.contains('regressed') ? 'class' : 'no-class',
        warn && got && warn.join() === got.join() ? 'warn' : 'plain',
        /regressed/.test(bar.getAttribute('aria-label') || '') ? 'named' : 'unnamed',
        region ? (region.textContent.trim() ? 'announced' : 'silent') : 'no-region',
      ].join('/') + ' [' + (got || []).join(',') + ']';
    })()`);
    await goto(`${fallenURL}/`);
    await settle(1200);
    await chooseTheme("light");
    const fallenLight = await barState();
    check(fallenLight.startsWith("class/warn/named/announced"),
      `a ladder that fell from ready is amber and says so, in light (${fallenLight})`);
    await shot("14-regressed-light", { width: 1600, height: 900 });
    await chooseTheme("dark");
    const fallenDark = await barState();
    check(fallenDark.startsWith("class/warn/named/announced"),
      `the same, in dark, where the plate is the ground (${fallenDark})`);
    await shot("15-regressed-dark", { width: 1600, height: 900 });
    // The live region must survive the swap that changes its text. An
    // `hx-swap-oob="true"` swap is outerHTML: the region is replaced by
    // a fresh node that arrives with its sentence already inside, and a
    // node inserted that way is not an update to a live region — many
    // screen readers say nothing, which is the feature lost.
    // This drives the real path: the same GET
    // the page's `sse:ladder` trigger makes, into the same target, with
    // the region marked beforehand so a replacement is visible.
    await evaluate(`(() => {
      const region = document.querySelector('#statusbar-regression');
      if (!region) return false;
      region.dataset.walkMark = 'mounted-before-the-swap';
      return true;
    })()`);
    await evaluate(`htmx.ajax('GET', '/api/v1alpha1/instances/${fallen}', {target: '#ladder-region', swap: 'innerHTML'})`);
    await settle(1200);
    const survived = await evaluate(`(() => {
      const region = document.querySelector('#statusbar-regression');
      if (!region) return 'region-gone';
      return (region.dataset.walkMark === 'mounted-before-the-swap' ? 'same-node' : 'replaced') +
        '/' + (region.textContent.trim() ? 'text' : 'empty') +
        '/' + (region.getAttribute('aria-live') || 'no-aria-live');
    })()`);
    check(survived === "same-node/text/polite",
      `the live region is the same node after the swap that fills it (${survived})`);
    // The instance headline draws the bar too, and has no live region of
    // its own, so it carries the word beside the colour.
    const headline = await evaluate(`(() => {
      ${colourLib}
      const h = document.querySelector('.ladder .headline');
      if (!h) return 'no-headline';
      const bar = h.querySelector('.ladder-bar');
      if (!bar) return 'no-bar';
      const warn = token(bar, '--status-warn'), got = fg(bar);
      return (bar.classList.contains('regressed') ? 'class' : 'no-class') +
        '/' + (warn && got && warn.join() === got.join() ? 'warn' : 'plain') +
        '/' + (/regressed/.test(h.querySelector('.sr-only')?.textContent || '') ? 'said' : 'silent');
    })()`);
    check(headline === "class/warn/said",
      `the instance headline colours the fall and says it in words (${headline})`);
    // The control: a lab that has never fallen carries none of it, and
    // its live region is present and empty — so nothing is announced
    // while a ladder climbs.
    await chooseTheme("system");
    await goto(`${instURL}/`);
    await settle(1200);
    const standing = await barState();
    check(standing.startsWith("no-class/plain/unnamed/silent"),
      `a ladder that has not fallen wears nothing and announces nothing (${standing})`);
    // And the list draws the same bar from the same field: one
    // component, one truth, wherever it is drawn.
    await goto(`${base}/`);
    await settle(1200);
    const rows = await evaluate(`(() => {
      ${colourLib}
      const row = (name) => [...document.querySelectorAll('.instances tbody tr')]
        .find((tr) => (tr.querySelector('a')?.textContent || '').trim() === name);
      const barOf = (name) => {
        const tr = row(name);
        if (!tr) return name + ':no-row';
        const bar = tr.querySelector('.ladder-bar');
        if (!bar) return name + ':no-bar';
        const warn = token(bar, '--status-warn'), got = fg(bar);
        const said = /regressed/.test(tr.querySelector('.sr-only')?.textContent || '');
        return name + ':' + (bar.classList.contains('regressed') ? 'class' : 'no-class') +
          '/' + (warn && got && warn.join() === got.join() ? 'warn' : 'plain') +
          '/' + (said ? 'said' : 'silent');
      };
      return [barOf(${JSON.stringify(fallen)}), barOf(${JSON.stringify(instance)})].join(' ');
    })()`);
    check(rows === `${fallen}:class/warn/said ${instance}:no-class/plain/silent`,
      `the instance list draws the same bar and says the fall in words (${rows})`);
    await goto(`${instURL}/`);
    await settle(1200);
  }

  // 3. Alpine and htmx are alive — the page runs, not merely renders.
  check(await evaluate(`typeof window.Alpine === 'object' && typeof window.htmx === 'object'`), "Alpine and htmx loaded and ran");
  // `?` shows the keyboard map UX §9 advertises. It flipped a property
  // nothing read, and the map was rendered nowhere at all (round 6).
  const mapBefore = await evaluate(`!document.querySelector('#keymap-region') || document.querySelector('#keymap-region').hidden`);
  await key("?");
  await settle(300);
  const mapAfter = await evaluate(`!!document.querySelector('#keymap-region') && !document.querySelector('#keymap-region').hidden`);
  check(mapBefore && mapAfter, `? shows the keyboard map (hidden before: ${mapBefore}, shown after: ${mapAfter})`);
  await key("?");
  await settle(200);

  // 4. Keyboard only: r toggles the rail, ? shows the map.
  const railBefore = await evaluate(`document.querySelector('.lab').dataset.rail`);
  await key("r");
  const railAfter = await evaluate(`document.querySelector('.lab').dataset.rail`);
  check(railBefore !== railAfter, `r toggles the rail (${railBefore} → ${railAfter})`);
  // And closing it actually does something — at the width that matters.
  // The only rule hiding a closed rail lived inside the `max-width:
  // 1200px` block, so on the desktop and projector layout — the one a
  // presenter stands in front of — `r` moved the attribute and nothing
  // else (round 6). The viewport is widened past that breakpoint for
  // this check and put back after, or the media query would hide the
  // rail for us and the check would pass without proving anything.
  //
  // No playbook is open yet, so what the region holds is the chooser,
  // and a chooser has no position to keep: it goes away. The rail's own
  // collapsed form is the spine, and that is checked in the rail leg
  // below, where there is a rail to collapse.
  await send(ws, "Emulation.setDeviceMetricsOverride",
    { width: 1600, height: 900, deviceScaleFactor: 1, mobile: false }, S);
  await settle(200);
  const railWide = await evaluate(`(() => {
    const el = document.querySelector('.rail-region');
    if (!el) return "no-rail";
    if (window.innerWidth <= 1200) return "viewport-too-narrow:" + window.innerWidth;
    const chooser = el.querySelector('.playbooks');
    if (!chooser) return "no-chooser";
    // Boxes, not computed style: an element inside a hidden ancestor
    // still reports its own display value, so reading that would call a
    // region the stylesheet had removed "still shown" (round 18).
    // No backticks in here — this comment is inside a template literal.
    return chooser.getClientRects().length === 0 ? "hidden" : "still-shown";
  })()`);
  check(railWide === "hidden", `a closed rail puts the chooser away on the desktop layout too (${railWide})`);
  await send(ws, "Emulation.clearDeviceMetricsOverride", {}, S);
  await settle(200);
  await key("r");
  // Only the Overview panel is visible at first paint: a browser lays
  // out and loads an iframe as it parses, so a product panel that is
  // hidden only once Alpine runs has already cost the page.
  const visible = await evaluate(`[...document.querySelectorAll('.panels .panel')].filter(p => !p.hidden).map(p => p.id)`);
  check(visible.length === 1 && visible[0] === "panel-overview",
    `only the Overview panel is visible at first paint (${visible.join(", ") || "none"})`);

  // Every tab is reachable from the keyboard, whatever the digits reach.
  // `show` gives the selected tab tabIndex 0 and every other -1, which
  // is the WAI-ARIA roving tabindex, so Tab enters the strip once and
  // lands on the selection; the digits stop at 9 and the template schema
  // puts no maximum on `services`. Without arrow keys a tenth product
  // could not be focused at all.
  //
  // The claim is not about nine: it is that arrowing visits *every* tab
  // the strip offers and comes back round, which does not depend on how
  // many there are.
  const arrowed = await evaluate(`(() => {
    const tabs = [...document.querySelectorAll('.tabs [data-tab]')].filter((t) => t.getClientRects().length > 0);
    if (tabs.length < 2) return "too-few-tabs:" + tabs.length;
    tabs[0].focus();
    window.__walkTabs = tabs.map((t) => t.dataset.tab);
    window.__walkSelected = document.querySelector('.tabs [aria-selected="true"]')?.dataset.tab;
    return "focused:" + document.activeElement.dataset.tab;
  })()`);
  if (arrowed.startsWith("focused:")) {
    const count = await evaluate(`window.__walkTabs.length`);
    const visited = [arrowed.slice("focused:".length)];
    for (let i = 0; i < count; i++) {
      await press("ArrowRight");
      visited.push(await evaluate(`document.activeElement?.dataset?.tab || "elsewhere"`));
    }
    const want = await evaluate(`window.__walkTabs.join(",")`);
    // One lap plus the wrap: every tab, in the strip's order, then the
    // first again.
    const lap = visited.slice(0, count).join(",");
    check(lap === want && visited[count] === visited[0],
      `arrow keys walk the whole tab strip and wrap (${visited.join(" → ")})`);
    // Focus moved and nothing opened: a product panel is an iframe that
    // loads when it is shown, so activation must not follow focus.
    await press("End");
    const held = await evaluate(`(() => {
      const on = document.querySelector('.tabs [aria-selected="true"]')?.dataset.tab;
      const last = window.__walkTabs[window.__walkTabs.length - 1];
      if (on !== window.__walkSelected) return "activated:" + on;
      if (document.activeElement?.dataset?.tab !== last) return "end-went-to:" + document.activeElement?.dataset?.tab;
      return "held:" + on;
    })()`);
    check(held.startsWith("held:"), `arrowing moves focus without opening a product (${held})`);
    // And the focused tab opens on its own activation, which is what a
    // button does with Enter.
    await press("Enter");
    const opened = await evaluate(`(() => {
      const on = document.querySelector('.tabs [aria-selected="true"]')?.dataset.tab;
      const last = window.__walkTabs[window.__walkTabs.length - 1];
      return on === last ? "opened:" + on : "still:" + on;
    })()`);
    check(opened.startsWith("opened:"), `Enter opens the tab the arrows reached (${opened})`);
    // Back to Overview, so what follows starts where it did before.
    await key("1");
  } else {
    check(false, `arrow keys walk the whole tab strip and wrap (${arrowed})`);
  }

  // And a tab the stylesheet hides cannot be selected. Under 768px the
  // product tabs and their panels are `display: none` (UX §10); round 9
  // stopped their *buttons* from being pressed, but `show` still took
  // those ids from the other two callers — a numeric shortcut, or a step
  // whose context is that product — so Overview was hidden and a panel
  // the stylesheet was suppressing marked selected: a blank product area.
  // The viewport is narrowed past the
  // breakpoint for this check and put back after, or every tab would be
  // offered and the check would prove nothing.
  await send(ws, "Emulation.setDeviceMetricsOverride",
    { width: 420, height: 900, deviceScaleFactor: 1, mobile: true }, S);
  await settle(300);
  const hiddenTab = await evaluate(`(() => {
    if (window.innerWidth > 768) return "viewport-too-wide:" + window.innerWidth;
    const hidden = [...document.querySelectorAll('.tabs [data-tab]')]
      .filter((t) => getComputedStyle(t).display === 'none').map((t) => t.dataset.tab);
    return hidden.length ? hidden.join(",") : "none";
  })()`);
  check(hiddenTab !== "none" && !hiddenTab.startsWith("viewport-too-wide"),
    `the phone layout hides this instance's product tabs (${hiddenTab})`);
  // And the rail is the same drawer it is at every width under 1200px —
  // over Overview, never stacked under it. UX §10 and plan S11 say so
  // since the treatment and the blueprint had said "stack" of a layout
  // that never was one.
  const phoneRail = await evaluate(`(() => {
    const el = document.querySelector('.rail-region');
    if (!el) return "no-rail-region";
    const pos = getComputedStyle(el).position;
    return pos === 'fixed' ? "drawer:" + Math.round(el.getBoundingClientRect().left) : "in-flow:" + pos;
  })()`);
  check(phoneRail.startsWith("drawer:"), `on a phone the rail is the drawer, as documented (${phoneRail})`);
  // The state after a gesture, read the same way for both gestures: one
  // tab selected, one panel shown, and the tab that is selected is one
  // the phone layout actually offers.
  const strip = `(() => {
    const tabs = [...document.querySelectorAll('.tabs [data-tab]')];
    const on = tabs.filter((t) => t.getAttribute('aria-selected') === 'true');
    if (on.length !== 1) return "tabs-selected:" + on.length;
    if (getComputedStyle(on[0]).display === 'none') return "hidden-tab-selected:" + on[0].dataset.tab;
    const shown = [...document.querySelectorAll('.panels .panel')].filter((p) => !p.hidden);
    if (shown.length !== 1) return "panels-shown:" + shown.length;
    if (shown[0].id !== 'panel-' + on[0].dataset.tab) return "panel-mismatch:" + shown[0].id;
    return "offered:" + on[0].dataset.tab;
  })()`;
  // 2 is the second tab the eye can count, which on a phone is not the
  // second button in the strip.
  await key("2");
  const byNumber = await evaluate(strip);
  check(byNumber.startsWith("offered:"), `a numeric shortcut cannot select a tab the phone layout hides (${byNumber})`);
  // And the path a step takes: selecting a step focuses its product tab,
  // and on a phone that tab is not there to focus.
  const byContext = await evaluate(`(() => {
    const tab = [...document.querySelectorAll('.tabs [data-tab]')]
      .find((t) => getComputedStyle(t).display === 'none');
    if (!tab) return "no-hidden-product-tab";
    window.Alpine.$data(document.querySelector('.tabs')).show(tab.dataset.tab);
    return ${strip};
  })()`);
  check(byContext.startsWith("offered:"), `a step's context cannot select a tab the phone layout hides (${byContext})`);
  // 1 is Overview on every layout: the walk goes back to where it was.
  await key("1");
  await send(ws, "Emulation.clearDeviceMetricsOverride", {}, S);
  await settle(200);

  // And the other direction, which is how a phone actually arrives at
  // it: a product tab chosen on a wide layout, and then the window
  // narrows or the device turns. The guard above only stops a hidden tab
  // being *chosen*; nothing watched the one already chosen, so the
  // stylesheet hid that tab and its panel while Overview stayed hidden
  // by its own attribute — a blank workspace until some other shortcut
  // was pressed.
  await send(ws, "Emulation.setDeviceMetricsOverride",
    { width: 1600, height: 900, deviceScaleFactor: 1, mobile: false }, S);
  await settle(250);
  const chose = await evaluate(`(() => {
    const product = [...document.querySelectorAll('.tabs [data-tab]')]
      .find((t) => t.dataset.kind === 'iframe' || t.dataset.kind === 'newtab');
    if (!product) return "no-product-tab";
    product.click();
    return document.getElementById('panel-' + product.dataset.tab)?.hidden === false
      ? "showing:" + product.dataset.tab : "not-shown";
  })()`);
  check(chose.startsWith("showing:"), `a product tab can be chosen on the wide layout (${chose})`);
  await send(ws, "Emulation.setDeviceMetricsOverride",
    { width: 420, height: 900, deviceScaleFactor: 1, mobile: true }, S);
  await settle(500);
  const narrowed = await evaluate(strip);
  check(narrowed.startsWith("offered:"), `narrowing under a selected product tab leaves a panel showing (${narrowed})`);
  // And the keyboard's own stop survives the same narrowing. Arrowing
  // moves `tabIndex 0` without selecting anything (round 28), so a
  // learner who arrowed onto a product and then narrowed the window left
  // the strip's only stop on a tab the stylesheet now hides: every
  // visible tab at -1, and Tab skipping the strip altogether.
  // The selection is still Overview
  // throughout, which is why the round-15 check above cannot see this.
  await send(ws, "Emulation.setDeviceMetricsOverride",
    { width: 1600, height: 900, deviceScaleFactor: 1, mobile: false }, S);
  await settle(250);
  await evaluate(`(() => {
    const tabs = [...document.querySelectorAll('.tabs [data-tab]')];
    tabs[0].click();
    tabs[0].focus();
    return true;
  })()`);
  await press("ArrowRight");
  const parked = await evaluate(`(() => {
    const stop = document.querySelector('.tabs [data-tab][tabindex="0"]');
    const on = document.querySelector('.tabs [aria-selected="true"]')?.dataset.tab;
    return stop && stop.dataset.tab !== on ? "parked-on:" + stop.dataset.tab : "no-park:" + (stop?.dataset.tab);
  })()`);
  await send(ws, "Emulation.setDeviceMetricsOverride",
    { width: 420, height: 900, deviceScaleFactor: 1, mobile: true }, S);
  await settle(500);
  const stopKept = await evaluate(`(() => {
    const tabs = [...document.querySelectorAll('.tabs [data-tab]')];
    const visible = tabs.filter((t) => t.getClientRects().length > 0);
    if (visible.length === 0) return "no-visible-tabs";
    const stops = tabs.filter((t) => t.tabIndex === 0);
    if (stops.length !== 1) return "stops:" + stops.length;
    return visible.includes(stops[0]) ? "reachable:" + stops[0].dataset.tab : "stranded-on:" + stops[0].dataset.tab;
  })()`);
  check(parked.startsWith("parked-on:") && stopKept.startsWith("reachable:"),
    `narrowing brings the keyboard's tab stop back to a visible tab (${parked} → ${stopKept})`);
  // The narrow viewport is where the round-15 check left it too, so the
  // restore below is the one that was already here.
  await key("1");
  await send(ws, "Emulation.clearDeviceMetricsOverride", {}, S);
  await settle(200);

  // The status bar's Evidence action selects the tab, rather than moving
  // the URL fragment and nothing else.
  await evaluate(`document.querySelector('.statusbar [data-tab-link="evidence"]').click()`);
  await settle(600);
  check(await evaluate(`document.querySelector('#tab-evidence')?.getAttribute('aria-selected') === 'true' && !document.querySelector('#panel-evidence').hidden`),
    "the status bar's Evidence action selects the Evidence tab");
  check(await evaluate(`!!document.querySelector('#panel-evidence .scoreboard, #panel-evidence table, #panel-evidence .empty')`),
    "the Evidence scoreboard loaded when its tab was first shown");
  // The journal beneath the scoreboard is a second read, of the twin
  // that actually carries the entries. Until round 4 the section was in
  // the template and no handler ever filled it, so the Evidence tab
  // showed each checkpoint's latest verdict and none of the runs, seeds,
  // milestones or reveals behind them.
  await settle(600);
  check(await evaluate(`!!document.querySelector('#panel-evidence .journal-region .journal, #panel-evidence .journal-region .empty')`),
    "the Evidence journal loaded from its own twin");
  // The filter chip is the learner's, and a live refresh must not take
  // it away: the scoreboard is what knows which chip is in force, so the
  // scoreboard is what re-reads (round 6).
  // "no chip" is not a pass: a check that reports success because it
  // could not find what it was going to test is a check that passes by
  // not checking. It waits for the board, and says so if it never comes.
  const filterKept = await evaluate(`(async () => {
    const find = () => [...document.querySelectorAll('#panel-evidence .chip')].find(c => /baseline/.test(c.textContent));
    let chip = find();
    for (let i = 0; i < 20 && !chip; i++) {
      await new Promise(r => setTimeout(r, 150));
      chip = find();
    }
    if (!chip) return "no-chip-after-3s";
    chip.click();
    await new Promise(r => setTimeout(r, 900));
    const board = document.querySelector('#panel-evidence .evidence');
    if (!board) return "no-board";
    const url = board.getAttribute('hx-get') || "";
    return /filter=baseline/.test(url) ? "kept" : "lost:" + (url || "no-hx-get");
  })()`);
  check(filterKept === "kept",
    `a chosen Evidence filter survives the next live refresh (${filterKept})`);
  const journalRows = await evaluate(`document.querySelectorAll('#panel-evidence .journal li').length`);
  check(journalRows > 0, `the journal carries this instance's entries (${journalRows} rows)`);
  // A panel that holds flowing content scrolls inside its column. The
  // shell's main never scrolls (S11), so a scoreboard and journal taller
  // than the workspace were clipped and unreachable while only Overview
  // had been given a scroll container.
  // Measured at a viewport short enough that both panels must overflow:
  // a scrollTop that stays at zero is a panel that cannot scroll.
  await send(ws, "Emulation.setDeviceMetricsOverride",
    { width: 1600, height: 420, deviceScaleFactor: 1, mobile: false }, S);
  await settle(300);
  const scrolls = await evaluate(`(() => {
    const out = [];
    for (const id of ['panel-evidence', 'panel-overview']) {
      const panel = document.getElementById(id);
      if (!panel) { out.push(id + ":missing"); continue; }
      const tab = document.querySelector('.tabs [data-tab="' + id.slice('panel-'.length) + '"]');
      if (tab) tab.click();
      if (panel.hidden) { out.push(id + ":hidden"); continue; }
      if (panel.scrollHeight <= panel.clientHeight + 1) { out.push(id + ":does-not-overflow:" + panel.scrollHeight + "/" + panel.clientHeight); continue; }
      panel.scrollTop = 100000;
      out.push(id + (panel.scrollTop > 0 ? ":scrolls" : ":clipped"));
      panel.scrollTop = 0;
    }
    return out.join(",");
  })()`);
  check(/panel-evidence:scrolls/.test(scrolls) && /panel-overview:scrolls/.test(scrolls),
    `a panel taller than the workspace scrolls inside its column (${scrolls})`);
  await send(ws, "Emulation.clearDeviceMetricsOverride", {}, S);
  await settle(200);
  await evaluate(`document.querySelector('#tab-overview').click()`);
  await settle(400);

  // A revealed credential carries its own way back: the control that
  // revealed it returns in its place when the value re-masks, which is
  // what makes the remask work in the rail as well as in the table.
  const revealed = await evaluate(`(async () => {
    const b = document.querySelector('.credentials .reveal');
    if (!b) return "no-credential";
    b.click();
    await new Promise(r => setTimeout(r, 800));
    const span = document.querySelector('.credentials .revealed');
    if (!span) return "no-reveal";
    return [!!span.querySelector('.value'), !!span.querySelector('.reveal'), !!span.querySelector('.masked')].join(",");
  })()`);
  check(revealed === "true,true,true" || revealed === "no-credential",
    `a revealed credential carries the control that re-masks it (${revealed})`);

  // Request URLs seen so far, and the seed POSTs among them. Defined
  // here because the rail leg below asks about them.
  const urlsSeen = () => events
    .filter((e) => e.method === "Network.requestWillBeSent")
    .map((e) => e.params.request.url);
  const urlsWithSeed = () => urlsSeen().filter((u) => /\/seeds\//.test(u));

  await shot("03-keyboard-rail");

  // 5. Open the playbook and walk it with the keyboard alone.
  const opened = await evaluate(`(() => {
    const a = document.querySelector('.start-here a.button, #rail a.button');
    if (a) { a.click(); return true; }
    return false;
  })()`);
  await settle(1200);
  if (opened && (await evaluate(`!!document.querySelector('.step')`))) {
    await shot("04-rail-open");
    // The step a swapped-in rail opens at is recorded by the swap, and
    // by nothing else: no gesture selects it. Opening a playbook aims at
    // #rail, which *contains* the rail and is not inside it, so a
    // handler that asked only `closest` found no rail on exactly the
    // path that brings one into being — and a first step with nothing to
    // verify stayed unrecorded, which is enough on its own to keep the
    // completion card away for ever.
    //
    // Asked of the engine, and asked here, because this is the one
    // moment in the walk where a rail has just arrived and nothing has
    // been selected in it.
    const openedAt = await evaluate(`(async () => {
      const rail = document.querySelector('.rail');
      if (!rail) return "no-rail";
      const step = rail.querySelector('.step.current');
      if (!step) return "no-current-step";
      if (step.dataset.checkpoint) return "opens-on-a-judged-step:" + step.dataset.step;
      const r = await fetch('/api/v1alpha1/instances/' + rail.dataset.instance +
        '/playbooks/' + rail.dataset.playbook + '/progress', {headers: {Accept: 'application/json'}});
      if (!r.ok) return "http-" + r.status;
      const saved = ((await r.json()).steps || {})[step.dataset.step];
      return (saved && saved.status ? "recorded:" + saved.status : "unrecorded") + " " + step.dataset.step;
    })()`);
    check(openedAt.startsWith("recorded:skipped"),
      `the step a swapped-in rail opens at is recorded (${openedAt})`);
    // The collapsed rail, where there is one to collapse. UX §6:
    // "Collapsed rail shows a slim progress spine (seven-ish dots) with
    // the current step title." Round 6 made `r` collapse the rail on the
    // desktop layout, which it had not done at all, and collapsed it to
    // `display: none` — an absent rail rather than a collapsed one, so
    // the learner lost every trace of their position and had no visible
    // way back. Widened past the 1200px
    // breakpoint on purpose, as round 6's check is.
    await send(ws, "Emulation.setDeviceMetricsOverride",
      { width: 1600, height: 900, deviceScaleFactor: 1, mobile: false }, S);
    await settle(200);
    await key("r");
    const collapsed = await evaluate(`(() => {
      if (window.innerWidth <= 1200) return "viewport-too-narrow:" + window.innerWidth;
      const el = document.querySelector('.rail-region');
      if (!el) return "no-rail-region";
      const spine = el.querySelector('.rail-spine');
      if (!spine) return "no-spine";
      if (spine.getClientRects().length === 0) return "spine-hidden";
      const steps = el.querySelector('.steps');
      if (steps && steps.getClientRects().length > 0) return "steps-still-shown";
      const label = (spine.textContent || "").replace(/[\s]+/g, " ").trim();
      if (!/Step [0-9]+ of [0-9]+/.test(label)) return "no-position:" + label.slice(0, 40);
      return "spine:" + label.slice(0, 40);
    })()`);
    check(collapsed.startsWith("spine:"),
      `a closed rail collapses to its progress spine, not to nothing (${collapsed})`);
    // And the spine is the way back — there is no other visible control,
    // so a learner who pressed `r` must not be stranded by it.
    const reopened = await evaluate(`(async () => {
      const spine = document.querySelector('.rail-spine');
      if (!spine) return "no-spine";
      spine.click();
      await new Promise(r => setTimeout(r, 300));
      const steps = document.querySelector('.rail-region .steps');
      return steps && steps.getClientRects().length > 0 ? "reopened" : "still-collapsed";
    })()`);
    check(reopened === "reopened", `the spine is the way back into the rail (${reopened})`);
    // The soft gate's eyeball (plan S11): the surface with a playbook
    // open and a product showing, at two desktop sizes.
    for (const [name, size] of [["08-desktop-1440", { width: 1440, height: 900 }], ["09-desktop-1920", { width: 1920, height: 1080 }]]) {
      await send(ws, "Emulation.setDeviceMetricsOverride", { ...size, deviceScaleFactor: 1, mobile: false }, S);
      await settle(300);
      await evaluate(`(() => {
        const product = [...document.querySelectorAll('.tabs [data-tab]')].find((t) => t.dataset.kind === 'iframe');
        if (product) product.click();
        return true;
      })()`);
      await settle(600);
      await shot(name, size);
    }
    // And the two themes, for the same eyeball (plan S12), the page back
    // on System afterwards so nothing below inherits a choice.
    await send(ws, "Emulation.setDeviceMetricsOverride",
      { width: 1600, height: 900, deviceScaleFactor: 1, mobile: false }, S);
    await settle(300);
    await chooseTheme("light");
    await shot("10-light", { width: 1600, height: 900 });
    await shot("12-type-light", { width: 1600, height: 900 });
    await chooseTheme("dark");
    await shot("11-dark", { width: 1600, height: 900 });
    await shot("13-type-dark", { width: 1600, height: 900 });
    await chooseTheme("system");
    await key("1");
    await settle(300);
    // The spine is rendered once with the fragment and the learner keeps
    // moving after that, so it has to move with them: it kept naming the
    // step that was current when the rail loaded — in its dot, its title
    // and its accessible name — however far the learner had walked.
    const spineFollows = await evaluate(`(async () => {
      const steps = [...document.querySelectorAll('.rail .step')];
      if (steps.length < 2) return "too-few-steps";
      const target = steps.find((s) => !s.classList.contains('current')) || steps[1];
      const title = target.querySelector('.step-title')?.textContent.trim();
      if (!title) return "no-title";
      window.Alpine.$data(document.querySelector('.lab')).selectStep(target);
      await new Promise(r => setTimeout(r, 250));
      const spine = document.querySelector('.rail-spine');
      if (!spine) return "no-spine";
      const shown = (spine.querySelector('.spine-title')?.textContent || "").trim();
      // The name a screen reader composes from the button's contents.
      // It used to be read from an aria-label, which round 24 removed
      // because such a label replaces that name rather than adding to
      // it — the words the dots carry were announced by nothing.
      const named = (spine.textContent || "").replace(/[\s]+/g, " ").trim();
      const dots = [...spine.querySelectorAll('.spine-dot')];
      const marked = dots.findIndex((d) => d.classList.contains('current'));
      if (marked !== steps.indexOf(target)) return "dot-on:" + marked + " want:" + steps.indexOf(target);
      if (!shown.endsWith(title)) return "title-says:" + shown;
      if (!named.endsWith(title)) return "label-says:" + named;
      return "follows:" + shown;
    })()`);
    check(spineFollows.startsWith("follows:"),
      `the collapsed rail names the step the learner is on (${spineFollows})`);
    // Whatever those two found, the rail is open for what follows: a
    // walk whose later checks fail because an earlier one left the page
    // collapsed reports the same defect several times and hides any
    // other.
    if ((await evaluate(`document.querySelector('.lab')?.dataset.rail`)) !== "open") {
      await key("r");
    }
    // UX §10: "768-1200px: rail overlays as a drawer (same content, `r`
    // toggles)." The rule for that band put the rail in normal flow
    // under the workspace, which is a stack and not a drawer: on a
    // tablet or a narrow laptop the rail was below the fold and `r`
    // toggled something the learner had to scroll to find.
    await send(ws, "Emulation.setDeviceMetricsOverride",
      { width: 1000, height: 800, deviceScaleFactor: 1, mobile: false }, S);
    await settle(300);
    const drawer = await evaluate(`(() => {
      const w = window.innerWidth;
      if (w <= 768 || w > 1200) return "wrong-band:" + w;
      const el = document.querySelector('.rail-region');
      if (!el) return "no-rail-region";
      const pos = getComputedStyle(el).position;
      if (pos === 'static') return "in-flow:" + pos;
      const box = el.getBoundingClientRect();
      if (box.top >= window.innerHeight) return "below-the-fold:" + Math.round(box.top);
      return "drawer:" + pos;
    })()`);
    check(drawer.startsWith("drawer:"), `the rail overlays as a drawer between 768 and 1200px (${drawer})`);
    // And from the left, where the rail lives (S11).
    const drawerSide = await evaluate(`(() => {
      const el = document.querySelector('.rail-region');
      if (!el) return "no-rail-region";
      const box = el.getBoundingClientRect();
      return Math.abs(box.left) <= 1 ? "left:" + Math.round(box.left) : "not-at-left:" + Math.round(box.left);
    })()`);
    check(drawerSide.startsWith("left:"), `the drawer opens from the left edge (${drawerSide})`);
    // And a pointer can dismiss it. `r` closed the rail and the spine
    // opened it, so the only control that could close it was a key —
    // and here the drawer covers most of the workspace, which a
    // touch-only tablet or phone had no way to get out of.
    const dismiss = await evaluate(`(async () => {
      if (document.querySelector('.lab')?.dataset.rail !== 'open') return "rail-not-open";
      // The whole drawer, not just the playbook rail inside it: round 22
      // moved the control out of the swappable content, which is where
      // it has to live to survive a swap.
      const controls = [...document.querySelectorAll('.rail-region [data-rail-toggle]')]
        .filter((el) => el.getClientRects().length > 0);
      if (controls.length === 0) return "no-visible-control";
      controls[0].click();
      await new Promise(r => setTimeout(r, 300));
      return document.querySelector('.lab')?.dataset.rail === 'closed' ? "dismissed" : "still-open";
    })()`);
    check(dismiss === "dismissed", `a pointer can dismiss the drawer (${dismiss})`);
    // The drawer is closed now, which is its own scrollport: 3.5 rem
    // wide, holding the spine and the Show control, and a narrower
    // inset than the open rail's until this round.
    const drawerRing = await ringRoomOf([["closed-drawer", ".rail-region", ".rail-region .button", "x"]]);
    check(ringFits(drawerRing), `the closed drawer keeps a focus ring inside it too (${drawerRing})`);
    // And it keeps one when the drawer's contents are swapped. The
    // chooser, a playbook rail and the reset dialog all replace what is
    // inside `#rail`, so a control rendered in the rail went with the
    // next swap — and Reset… is exactly that swap, at a width where the
    // drawer covers the workspace: a touch-only user was left with a
    // destructive confirm or a page reload.
    // The reset dialog is opened here and put back after.
    const acrossSwap = await evaluate(`(async () => {
      const rail = document.querySelector('.rail');
      if (!rail) return "no-rail";
      // Where to put the rail back from, captured before the swap.
      const back = '/api/v1alpha1/instances/' + rail.dataset.instance +
        '/playbooks/' + rail.dataset.playbook + '?mode=' + (rail.dataset.mode || 'guided');
      const bar = [...document.querySelectorAll('.statusbar .button, .statusbar .bar-action')]
        .find((b) => /Reset/.test(b.textContent));
      if (!bar) return "no-reset-action";
      bar.click();
      await new Promise(r => setTimeout(r, 900));
      const opened = !!document.querySelector('.reset-dialog');
      const controls = opened
        ? [...document.querySelectorAll('.rail-region [data-rail-toggle]')].filter((el) => el.getClientRects().length > 0)
        : [];
      // Whatever this found, the rail goes back: a check that leaves the
      // page somewhere else reports its own defect again in every check
      // after it (round 18).
      await window.htmx.ajax('GET', back, { target: '#rail', swap: 'innerHTML' });
      await new Promise(r => setTimeout(r, 600));
      if (!opened) return "dialog-did-not-open";
      return controls.length > 0 ? "kept:" + controls.length : "no-visible-control";
    })()`);
    check(acrossSwap.startsWith("kept:"),
      `the drawer keeps a control when its contents are swapped (${acrossSwap})`);
    if ((await evaluate(`document.querySelector('.lab')?.dataset.rail`)) !== "open") {
      await key("r");
    }
    await send(ws, "Emulation.clearDeviceMetricsOverride", {}, S);
    await settle(200);
    const firstStep = await evaluate(`document.querySelector('.step.current')?.dataset.step || document.querySelector('.step')?.dataset.step`);
    await key("]");
    const nextStep = await evaluate(`document.querySelector('.step.current')?.dataset.step`);
    check(firstStep !== nextStep, `] moves to the next step (${firstStep} → ${nextStep})`);
    await key("[");
    check((await evaluate(`document.querySelector('.step.current')?.dataset.step`)) === firstStep, "[ moves back");
    check(await evaluate(`document.activeElement.classList.contains('step-title')`), "the focused step's title takes focus, so a reader is told where it landed");
    // The pointer's way through the same walk. Before round 4 the only
    // code that moved the current step was the key handler above, so a
    // mouse or touch user read every card while the position saved on
    // the instance stayed where it opened.
    check(await evaluate(`!!document.querySelector('.step-nav[data-step-move="1"]') && !!document.querySelector('.step-nav[data-step-move="-1"]')`),
      "the rail offers Previous and Next to a pointer");
    await evaluate(`document.querySelector('.step-nav[data-step-move="1"]').click()`);
    await settle(400);
    const byButton = await evaluate(`document.querySelector('.step.current')?.dataset.step`);
    check(byButton !== firstStep, `Next step moves the current step (${firstStep} → ${byButton})`);
    // A click on a card selects it — and yields to the controls inside
    // it, so pressing Verify is still only pressing Verify.
    const byClick = await evaluate(`(() => {
      const steps = [...document.querySelectorAll('.step')];
      const target = steps.find(s => !s.classList.contains('current'));
      if (!target) return "one-step";
      target.querySelector('.step-title').click();
      return document.querySelector('.step.current')?.dataset.step === target.dataset.step ? "selected" : "not-selected";
    })()`);
    check(byClick === "selected" || byClick === "one-step", `clicking a step card selects it (${byClick})`);
    // Reading is not navigating. A drag to select a sentence in a card
    // ends with a click on that card, and the card-click convenience
    // would take it for a choice: it would move the current step and
    // write the new position to the instance, over a learner who was
    // only reading ahead — and the focus it takes would drop their
    // selection on the way out. Found in self-review of the round-4
    // fix, before the reviewer saw it.
    const dragGuard = await evaluate(`(() => {
      const steps = [...document.querySelectorAll('.step')];
      const cur = document.querySelector('.step.current');
      if (!cur) return "no-current";
      const other = steps.find(s => s !== cur);
      if (!other) return "one-step";
      const body = other.querySelector('.step-body');
      if (!body) return "no-body";
      const range = document.createRange();
      range.selectNodeContents(body);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      body.click();
      const now = document.querySelector('.step.current')?.dataset.step;
      sel.removeAllRanges();
      return now === cur.dataset.step ? "held" : "moved to " + now;
    })()`);
    check(dragGuard === "held" || dragGuard === "one-step",
      `selecting text in a card is reading, not choosing (${dragGuard})`);
    // An auto step whose actions carry no checkpoint. Both shipped
    // playbooks give their auto steps one, but `checkpoint` is optional
    // in schemas/playbook.v1alpha1.json, so a schema-valid step can
    // declare actions and no verification — and the one control that
    // runs them bailed on the empty action, doing nothing at all.
    // Synthesised here because no shipped playbook has such a step; the
    // handler is document-delegated, so the button is the whole case.
    const seedsBefore = urlsWithSeed().length;
    await evaluate(`(() => {
      const rail = document.querySelector('.rail');
      const b = document.createElement('button');
      b.className = 'button primary run-step';
      b.type = 'button';
      b.id = 'synthetic-auto';
      b.dataset.action = '';
      b.dataset.result = '#result-none';
      b.dataset.actions = 'seed:not-declared';
      b.dataset.instance = rail.dataset.instance;
      b.dataset.csrf = rail.dataset.csrf;
      b.textContent = 'Run this step';
      rail.appendChild(b);
      b.click();
      return true;
    })()`);
    await settle(2500);
    const seedsAfter = urlsWithSeed().length;
    check(seedsAfter > seedsBefore,
      `an auto step with actions and no checkpoint still runs them (${seedsAfter - seedsBefore} seed request(s))`);
    await evaluate(`document.querySelector('#synthetic-auto')?.remove()`);
    // And a reveal among those actions. Round 6 made the one control
    // perform every declared action, and a revealed value needs the
    // region the step carries for it — with the same countdown and the
    // same way back the credentials table's reveal has. No shipped
    // playbook declares an auto step with a reveal, so the shape is
    // synthesised the same way; the handler is document-delegated, so
    // the button and its region are the whole case.
    const autoReveal = await evaluate(`(async () => {
      const rail = document.querySelector('.rail');
      const secret = await (async () => {
        const r = await fetch('/api/v1alpha1/instances/' + rail.dataset.instance + '/secrets',
          {headers: {Accept: 'application/json'}});
        if (!r.ok) return "";
        const b = await r.json();
        return (b.secrets && b.secrets[0] && b.secrets[0].name) || "";
      })();
      if (!secret) return "no-secret";
      const wrap = document.createElement('div');
      wrap.className = 'actions';
      wrap.id = 'synthetic-auto-wrap';
      wrap.innerHTML = '<button class="button primary run-step" type="button" id="synthetic-auto-reveal"></button><div class="action-output"></div>';
      rail.appendChild(wrap);
      const b = document.getElementById('synthetic-auto-reveal');
      b.dataset.action = '';
      // Two of them: a step may declare more than one reveal, and
      // assigning innerHTML took the first credential away before
      // anyone could copy it (round 9).
      b.dataset.actions = 'reveal:' + secret + ',reveal:' + secret;
      b.dataset.instance = rail.dataset.instance;
      b.dataset.csrf = rail.dataset.csrf;
      b.textContent = 'Run this step';
      b.click();
      for (let i = 0; i < 20; i++) {
        await new Promise(r => setTimeout(r, 150));
        const all = wrap.querySelectorAll('.action-output .revealed');
        if (all.length >= 2) {
          const parts = [...all].every(g => g.querySelector('.value') && g.querySelector('.countdown') && g.querySelector('.reveal'));
          return parts ? "both revealed, each with its countdown and its way back" : "incomplete";
        }
      }
      return "nothing-landed";
    })()`);
    check(/^both revealed/.test(autoReveal),
      `every credential an auto step reveals stays readable (${autoReveal})`);
    await evaluate(`document.querySelector('#synthetic-auto-wrap')?.remove()`);
    // And a reveal among those actions that the server refuses. The seed
    // branch beside it has always stopped the step with a receipt; this
    // one returned in silence and the button simply came back, so a
    // learner whose reveal was refused watched the one control do
    // nothing. The button is synthesised
    // — no shipped playbook declares an auto step with a reveal — but
    // the region is the page's own, which is the distinction round 11
    // had to learn, and the refusal is the server's own: the action
    // names a secret this instance does not have.
    const revealRefused = await evaluate(`(async () => {
      const rail = document.querySelector('.rail');
      const wrap = rail.querySelector('.actions');
      if (!wrap) return "no-actions-block";
      const region = wrap.querySelector('.action-output');
      if (!region) return "the page renders no receipt region";
      const b = document.createElement('button');
      b.className = 'button primary run-step';
      b.type = 'button';
      b.id = 'synthetic-reveal-refused';
      wrap.appendChild(b);
      b.dataset.action = '';
      b.dataset.actions = 'reveal:no-such-secret-r15';
      b.dataset.instance = rail.dataset.instance;
      b.dataset.csrf = rail.dataset.csrf;
      b.textContent = 'Run this step';
      b.click();
      for (let i = 0; i < 20; i++) {
        await new Promise(r => setTimeout(r, 150));
        const text = region.textContent.trim();
        if (text) return /PDR-[A-Z]?[0-9]+/.test(text) ? "reported:" + text.slice(0, 50) : "unnamed:" + text.slice(0, 50);
      }
      return "silent";
    })()`);
    check(revealRefused.startsWith("reported:"), `a refused reveal in an auto step says so (${revealRefused})`);
    await evaluate(`(() => {
      document.getElementById('synthetic-reveal-refused')?.remove();
      const region = document.querySelector('.rail .actions .action-output');
      if (region) region.innerHTML = '';
    })()`);
    // A verdict can arrive without a Verify press: a checkpoint serving
    // several steps answers with out-of-band swaps into each of their
    // result regions, and a Presenter re-check is initiated by the light
    // region rather than by a step. Painting from the initiating step
    // left those showing a verdict the collapsed rail contradicted.
    //
    // No shipped playbook shares a checkpoint between steps, so the
    // *shape* is made here the way round 5's checkpoint-free auto button
    // was: a real request to the real endpoint, landing a real result
    // fragment in the step's own region, with something other than that
    // step's Verify button as the initiator. Nothing about the verdict
    // is invented — the checkpoint passes now because the walk drove the
    // traffic, while the rail was rendered when it did not.
    const withoutAPress = await evaluate(`(async () => {
      const rail = document.querySelector('.rail');
      const step = [...rail.querySelectorAll('.step')].find((el) => el.querySelector('.verify-button, .run-step'));
      if (!step) return "no-verifiable-step";
      const dot = rail.querySelectorAll('.rail-spine .spine-dot')[[...rail.querySelectorAll('.step')].indexOf(step)];
      if (!dot) return "no-dot";
      const control = step.querySelector('.verify-button, .run-step');
      const action = control.getAttribute('hx-post') || control.dataset.action;
      if (!action) return "no-action";
      const before = [...dot.classList].find((c) => c.startsWith('status-'));
      // The step's own declared seed, sent to the real endpoint, so the
      // checkpoint's verdict genuinely turns: the rail was rendered when
      // it was red and the lab is green by the time it is asked again.
      const seed = (control.dataset.actions || "").split(",").map((x) => x.trim())
        .find((x) => x.indexOf("seed:") === 0);
      if (seed) {
        await fetch('/api/v1alpha1/instances/' + rail.dataset.instance + '/seeds/' + seed.slice(5),
          { method: 'POST', headers: { 'X-Podaro-CSRF': rail.dataset.csrf || '', Accept: 'application/json' } });
        await new Promise(r => setTimeout(r, 2500));
      }
      await window.htmx.ajax('POST', action, {
        target: '#result-' + step.dataset.step,
        swap: 'innerHTML',
        headers: { 'X-Podaro-CSRF': rail.dataset.csrf || '' },
      });
      await new Promise(r => setTimeout(r, 400));
      const result = step.querySelector('.result');
      const verdict = result ? [...result.classList].find((c) => c.startsWith('status-')) : "";
      const after = [...dot.classList].find((c) => c.startsWith('status-'));
      if (!verdict) return "no-verdict";
      if (verdict === before) return "verdict-unchanged:" + verdict;
      return after === verdict ? "repainted:" + before + "->" + after : "dot-stuck:" + after + " result:" + verdict;
    })()`);
    check(withoutAPress.startsWith("repainted:"),
      `a verdict that arrives without a Verify press still reaches the spine (${withoutAPress})`);

    // `v` verifies the current step (UX §9, and the keymap says so in
    // those words). An `auto: true` step with a machine checkpoint
    // renders its one control and no separate Verify — which is every
    // such step in both shipped playbooks — so a key that looked only
    // for `.verify-button` did nothing on exactly the steps the shortcut
    // is most useful on. The step is the
    // page's own; only the keypress is the walk's.
    const vKey = await evaluate(`(() => {
      const step = [...document.querySelectorAll('.rail .step')]
        .find((el) => el.querySelector('.run-step') && !el.querySelector('.verify-button'));
      if (!step) return "no-auto-step";
      window.Alpine.$data(document.querySelector('.lab')).selectStep(step);
      return "current:" + step.dataset.step;
    })()`);
    check(vKey.startsWith("current:"), `the rail has an auto step whose only control is the one control (${vKey})`);
    if (vKey.startsWith("current:")) {
      const runsBefore = urlsSeen().filter((u) => /\/checkpoints\/[^/]+\/run/.test(u)).length;
      await key("v");
      await settle(2500);
      const runsAfter = urlsSeen().filter((u) => /\/checkpoints\/[^/]+\/run/.test(u)).length;
      check(runsAfter > runsBefore,
        `v verifies a step whose only control is the one control (${runsAfter - runsBefore} checkpoint run(s))`);
    }
    // And the verdict reaches the collapsed rail. The spine's dots carry
    // the status the server rendered with the fragment, and a verify
    // swaps only the result region — so a rail collapsed after a pass
    // showed a pending dot beside a passed result until the whole rail
    // was reloaded.
    const spineStatus = await evaluate(`(() => {
      const rail = document.querySelector('.rail');
      if (!rail) return "no-rail";
      const steps = [...rail.querySelectorAll('.step')];
      const dots = [...rail.querySelectorAll('.rail-spine .spine-dot')];
      // Every judged step, not the first: whatever verdict the page
      // shows — pass, fail, attested or the amber error a re-run can
      // produce — the dot beside it must say the same thing.
      const judged = steps.filter((el) => {
        const r = el.querySelector('.result');
        return r && [...r.classList].some((c) => /^status-(pass|fail|attested|error)$/.test(c));
      });
      if (judged.length === 0) return "no-judged-step";
      for (const step of judged) {
        const verdict = [...step.querySelector('.result').classList].find((c) => c.startsWith('status-'));
        const dot = dots[steps.indexOf(step)];
        if (!dot) return "no-dot";
        const on = [...dot.classList].find((c) => c.startsWith('status-'));
        if (on !== verdict) return "dot-says:" + on + " result-says:" + verdict;
      }
      return "matches:" + judged.length;
    })()`);
    check(spineStatus.startsWith("matches:"),
      `the collapsed rail carries the verdicts the open one shows (${spineStatus})`);
    // And it carries them the way UX §4 requires: colour *and* glyph
    // *and* word. The dots were one shape in four colours, hidden from
    // assistive technology — a colour-blind reader could not tell a pass
    // from a failure and a screen reader was told nothing.
    const pairing = await evaluate(`(() => {
      const rail = document.querySelector('.rail');
      if (!rail) return "no-rail";
      const dots = [...rail.querySelectorAll('.rail-spine .spine-dot')];
      if (dots.length === 0) return "no-dots";
      const seen = new Map();
      for (const dot of dots) {
        const status = [...dot.classList].find((c) => c.startsWith('status-'));
        const mark = (dot.querySelector('.spine-glyph')?.textContent || "").trim();
        const word = (dot.querySelector('.spine-word')?.textContent || "").trim();
        if (!mark) return "no-glyph:" + status;
        if (!word) return "no-word:" + status;
        const already = seen.get(mark);
        if (already && already !== status) return "same-glyph:" + mark + " for " + already + " and " + status;
        seen.set(mark, status);
      }
      return "paired:" + seen.size + " glyph(s) for " + dots.length + " dots";
    })()`);
    check(pairing.startsWith("paired:"),
      `each collapsed-rail dot pairs colour with a glyph and a word (${pairing})`);
    // And a screen reader is actually told them. The words are inside a
    // button, and a button's own `aria-label` *replaces* the name its
    // contents compose — so round 23's words were in the page and
    // announced by nothing. The name is
    // read here the way a reader composes it: no override, and the
    // contents carrying the action, the verdicts and the position.
    const announced = await evaluate(`(() => {
      const spine = document.querySelector('.rail-spine');
      if (!spine) return "no-spine";
      if (spine.hasAttribute('aria-label')) return "overridden:" + spine.getAttribute('aria-label').slice(0, 40);
      const name = (spine.textContent || "").replace(/[\s]+/g, " ").trim();
      if (!/Open the playbook rail/.test(name)) return "no-action:" + name.slice(0, 50);
      if (!/Step [0-9]+ of [0-9]+:/.test(name)) return "no-verdicts:" + name.slice(0, 50);
      if (!/Step [0-9]+ of [0-9]+ · /.test(name)) return "no-position:" + name.slice(0, 50);
      return "announced:" + name.slice(0, 60);
    })()`);
    check(announced.startsWith("announced:"),
      `the collapsed rail's verdicts reach its accessible name (${announced})`);
    // A standalone seed press left the button unchanged whether it
    // succeeded, failed or was refused — its 202 was thrown away and
    // nothing waited for the job (round 9). It leaves a receipt now.
    // Synthesised **button**, but never a synthesised region: this check
    // fabricated the `.action-output` beside it, and so proved the
    // handler writes a receipt while the shipped template rendered
    // nowhere to put one — the fix was inert and this check hid it.
    // The region now comes from the
    // page's own markup, and the Go test asserts the template renders
    // it. `first-dashboard`'s only seed is inside an auto step, so the
    // button itself still has to be made.
    const seedReceipt = await evaluate(`(async () => {
      const rail = document.querySelector('.rail');
      const wrap = rail.querySelector('.actions');
      if (!wrap) return "no-actions-block";
      if (!wrap.querySelector('.action-output')) return "the page renders no receipt region";
      const b = document.createElement('button');
      b.className = 'button primary seed-button';
      b.type = 'button';
      b.id = 'synthetic-seed';
      wrap.appendChild(b);
      // A seed this instance actually has, read off the auto control
      // already on the page: a name it does not have would only ever
      // exercise the refusal branch, and the receipt for a refusal is
      // not the receipt this check is about.
      const real = (document.querySelector('.rail .run-step')?.dataset.actions || '')
        .split(',').map(x => x.trim()).find(x => x.startsWith('seed:'));
      if (!real) return "no-seed-to-send";
      b.dataset.actions = real;
      b.dataset.instance = rail.dataset.instance;
      b.dataset.csrf = rail.dataset.csrf;
      b.dataset.runningLabel = 'Sending…';
      b.textContent = 'Send';
      b.click();
      for (let i = 0; i < 40; i++) {
        await new Promise(r => setTimeout(r, 250));
        const got = wrap.querySelector('.action-output .result');
        if (got) return got.className.includes('status-pass') ? "sent: " + got.textContent : "reported: " + got.textContent;
      }
      return "no-receipt";
    })()`);
    check(/^sent:/.test(seedReceipt), `a standalone seed says what it did (${seedReceipt})`);
    await evaluate(`document.querySelector('#synthetic-seed')?.remove()`);
    await evaluate(`document.querySelector('.step-nav[data-step-move="-1"]').click()`);
    await settle(300);
    // The position is *saved*, not only shown (Manual §3: Guided saves
    // progress). Before this was fixed, moving between steps changed
    // DOM classes and nothing else, so a reload returned the learner to
    // the first step and a finished lab had no record of being finished.
    // Asked of the engine, not the page.
    await key("]");
    await settle(600);
    const saved = await evaluate(`(async () => {
      const rail = document.querySelector('.rail');
      if (!rail || !rail.dataset.playbook) return "no-rail";
      const r = await fetch('/api/v1alpha1/instances/' + rail.dataset.instance +
        '/playbooks/' + rail.dataset.playbook + '/progress', {headers: {Accept: 'application/json'}});
      if (!r.ok) return "http-" + r.status;
      const body = await r.json();
      return body.current_step || "";
    })()`);
    check(saved === (await evaluate(`document.querySelector('.step.current')?.dataset.step`)),
      `the step the learner moved to is recorded (engine says ${saved})`);
    // And the start-here card catches up. Since round 4 what it says
    // depends on the saved position, and a progress write emits nothing
    // on the feed — so without a refresh the card went on offering
    // "Begin" to a learner who was two steps in (round 7). The shipped
    // first-dashboard playbook is the case: its first step declares no
    // checkpoint, so nothing else would have moved the card either.
    await settle(900);
    const cardNow = await evaluate(`(() => {
      const card = document.querySelector('#start-here-region .start-here');
      if (!card) return "no-card";
      const m = card.className.match(/state-([a-z]+)/);
      return m ? m[1] : "no-state-class:" + card.className;
    })()`);
    check(cardNow === "resume",
      `the start-here card catches up with the saved position (${cardNow})`);
    // And walked to its end, the card says so. UX §8 asks Guided for a
    // factual completion line; round 30 added one that could not appear,
    // because a step with no checkpoint records nothing and both shipped
    // playbooks have such steps — first-dashboard has four steps and two
    // checkpoints — so the count never reached the total and a finished
    // lab still said Resume. This walks
    // the real shipped playbook to its end rather than a fixture whose
    // every step happens to carry a checkpoint.
    const finishedCard = await evaluate(`(async () => {
      // Each step selected the way the pointer selects one. The step a
      // swapped-in rail *opens* at is not covered here — nothing selects
      // that one — and it has its own check above, where the rail is
      // opened for the first time.
      const lab = window.Alpine.$data(document.querySelector('.lab'));
      const steps = [...document.querySelectorAll('.rail .step')];
      if (steps.length === 0) return "no-steps";
      for (const step of steps) {
        lab.selectStep(step);
        await new Promise(r => setTimeout(r, 400));
        const verify = step.querySelector('.verify-button, .run-step');
        if (!verify) continue;
        verify.click();
        // Wait for the *request* to finish, not for a verdict to appear:
        // the rail renders the checkpoint's standing result, so a step
        // whose objective already failed at create shows status-fail
        // before anything is pressed, and waiting for a class that is
        // already there proves nothing (found writing this check).
        for (let i = 0; i < 120; i++) {
          await new Promise(r => setTimeout(r, 250));
          if (!verify.classList.contains('htmx-request')) break;
        }
        await new Promise(r => setTimeout(r, 700));
        const refused = (step.querySelector('.action-output')?.textContent || '').trim();
        if (refused) window.__refused = (window.__refused || []).concat(step.dataset.step + ":" + refused.slice(0, 70));
      }
      await new Promise(r => setTimeout(r, 1500));
      const rail = document.querySelector('.rail');
      const r = await fetch('/api/v1alpha1/instances/' + rail.dataset.instance +
        '/playbooks/' + rail.dataset.playbook + '/progress', {headers: {Accept: 'application/json'}});
      if (!r.ok) return "http-" + r.status;
      const saved = (await r.json()).steps || {};
      const recorded = steps.map((st) => st.dataset.step + "=" + ((saved[st.dataset.step] || {}).status || "-")).join(",");
      const card = document.querySelector('#start-here-region .start-here');
      const state = (card?.className.match(/state-([a-z]+)/) || [])[1];
      const body = (card?.querySelector('.start-body')?.textContent || '').trim();
      return state + " " + recorded + (window.__refused ? " · refused " + JSON.stringify(window.__refused) : " · " + body);
    })()`);
    check(finishedCard.startsWith("complete "),
      `a Guided playbook walked to its end says so (${finishedCard.slice(0, 260)})`);
    // Manual §7: selecting a step focuses the product tab it belongs to,
    // and switching tabs highlights the steps that apply there.
    const ctx = await evaluate(`(() => {
      const s = [...document.querySelectorAll('.step[data-context]')]
        .find(s => document.querySelector('[data-tab="' + s.dataset.context + '"]'));
      return s ? s.dataset.context : "";
    })()`);
    if (ctx) {
      await evaluate(`(() => {
        const s = [...document.querySelectorAll('.step[data-context="${ctx}"]')][0];
        document.querySelectorAll('.step').forEach(x => x.classList.remove('current'));
        s.classList.add('current');
      })()`);
      await key("]");
      await key("[");
      const selected = await evaluate(`document.querySelector('[data-tab="${ctx}"]')?.getAttribute('aria-selected')`);
      check(selected === "true", `selecting a step focuses its product tab (${ctx})`);
      check(await evaluate(`!!document.querySelector('.step.for-tab[data-context="${ctx}"]')`),
        "the open tab highlights the steps that apply to it");
    } else {
      console.log("· no step names a product tab on this instance; the linkage is not exercised");
    }
    await shot("05-step-walked");

    // Presenter: reachable from the chooser (its link is the one the
    // rows gained), and its confidence lights re-check on their own —
    // a light that is only remembered is a claim about the lab as it
    // was, shown where it matters that it is true now (Manual §3).
    const urlsSoFar = () => events
      .filter((e) => e.method === "Network.requestWillBeSent")
      .map((e) => e.params.request.url);
    const before = urlsSoFar().length;
    const opened = await evaluate(`(() => {
      const back = document.querySelector('.statusbar .brand');
      const rail = document.querySelector('#rail');
      if (!rail) return false;
      // Re-open the chooser, then the Presenter link it offers.
      return true;
    })()`);
    if (opened) {
      await evaluate(`htmx.ajax('GET', '/api/v1alpha1/instances/walk/playbooks', {target: '#rail', swap: 'innerHTML'})`);
      await settle(800);
      const presenterLink = await evaluate(`!!document.querySelector('.playbook-actions a[href*="mode=presenter"]')`);
      check(presenterLink, "the chooser offers Presenter for a playbook that declares it");
      if (presenterLink) {
        await evaluate(`document.querySelector('.playbook-actions a[href*="mode=presenter"]').click()`);
        await settle(1200);
        check(await evaluate(`!!document.querySelector('.rail[data-presenter="true"]')`), "Presenter opens from the console");
        check(await evaluate(`!document.querySelector('.verify-button')`), "Presenter presses nothing: no Verify button");
        // Presenter opens light when nothing is chosen (UX §4), without
        // storing it — System stays pressed, because nothing was chosen —
        // and a choice, once made, is what Presenter keeps.
        const presenterLight = await themeState();
        check(presenterLight === "light/none/system", `Presenter opens light when nothing is chosen, and stores nothing (${presenterLight})`);
        await chooseTheme("dark");
        await evaluate(`htmx.ajax('GET', '/api/v1alpha1/instances/walk/playbooks', {target: '#rail', swap: 'innerHTML'})`);
        await settle(800);
        await evaluate(`document.querySelector('.playbook-actions a[href*="mode=presenter"]').click()`);
        await settle(1200);
        const presenterKept = await themeState();
        check(presenterKept === "dark/dark/dark", `a chosen theme is kept when Presenter opens (${presenterKept})`);
        await chooseTheme("system");
        // A choice storage refused to keep is still the choice:
        // a fresh page whose setItem throws,
        // Dark pressed, then Presenter opened — the page stays dark,
        // nothing stored, Dark pressed. Then a fresh page without the
        // refusal, Presenter reopened, for the checks below.
        await goto(`${instURL}/`);
        await settle(800);
        await evaluate(`(() => { Storage.prototype.setItem = function () { throw new Error("storage refused"); }; return true; })()`);
        await chooseTheme("dark");
        await evaluate(`htmx.ajax('GET', '/api/v1alpha1/instances/walk/playbooks', {target: '#rail', swap: 'innerHTML'})`);
        await settle(800);
        await evaluate(`document.querySelector('.playbook-actions a[href*="mode=presenter"]').click()`);
        await settle(1200);
        const presenterRefused = await themeState();
        check(presenterRefused === "dark/none/dark", `a choice storage refused to keep is still the choice when Presenter opens (${presenterRefused})`);
        // The default is once per presenter rail, not once per page:
        // a page whose choice was Dark
        // when Presenter first opened, and whose choice is System when
        // Presenter is opened again, opens light the second time — and
        // a swap inside that rail (the lights re-check, two seconds
        // after it opens) never re-applies the default over a press.
        await goto(`${instURL}/`);
        await settle(800);
        await chooseTheme("dark");
        await evaluate(`htmx.ajax('GET', '/api/v1alpha1/instances/walk/playbooks', {target: '#rail', swap: 'innerHTML'})`);
        await settle(800);
        await evaluate(`document.querySelector('.playbook-actions a[href*="mode=presenter"]').click()`);
        await settle(1200);
        await chooseTheme("system");
        await evaluate(`htmx.ajax('GET', '/api/v1alpha1/instances/walk/playbooks', {target: '#rail', swap: 'innerHTML'})`);
        await settle(800);
        await evaluate(`document.querySelector('.playbook-actions a[href*="mode=presenter"]').click()`);
        await settle(1200);
        const presenterAgain = await themeState();
        check(presenterAgain === "light/none/system", `Presenter opened again after System is pressed opens light again (${presenterAgain})`);
        await chooseTheme("system");
        await settle(3500);
        const presenterHeld = await themeState();
        check(presenterHeld === "system/none/system", `a swap inside the open presenter rail never re-applies the default over a press (${presenterHeld})`);
        await goto(`${instURL}/`);
        await settle(800);
        await evaluate(`htmx.ajax('GET', '/api/v1alpha1/instances/walk/playbooks', {target: '#rail', swap: 'innerHTML'})`);
        await settle(800);
        await evaluate(`document.querySelector('.playbook-actions a[href*="mode=presenter"]').click()`);
        await settle(1200);
        // The lights re-check: give the load delay time, then look for
        // the checkpoint runs in the request log.
        await settle(3500);
        const runs = urlsSoFar().slice(before).filter((u) => /\/checkpoints\/[^/]+\/run/.test(u));
        check(runs.length > 0, `Presenter re-runs its checkpoints on its own (${runs.length} run${runs.length === 1 ? "" : "s"})`);
        // And never attests on its own. This template declares no attest
        // checkpoint, so the check is that nothing reached that endpoint
        // at all; the rule itself is stated in internal/console.
        const attests = urlsSoFar().slice(before).filter((u) => /\/attest/.test(u));
        check(attests.length === 0, "Presenter posted to no attest endpoint");
        // And a re-check the presenter did not ask for says nothing when
        // it fails. UX §8's Presenter row is "absolutely none — no
        // toasts, modals, or async popups", and this console swaps every
        // response, so a 4xx from the unattended timer put the error
        // panel on stage.
        //
        // The failure is real and the server's: the element is aimed at
        // the same endpoint on an instance that does not exist, so the
        // engine answers PDR-E202 through the same path a reset from
        // another window would take. `htmx.process` is needed because a
        // control's path is read when the node is processed, not when it
        // fires.
        const quiet = await evaluate(`(async () => {
          const region = document.querySelector('.rail .light-region');
          if (!region) return "no-light-region";
          const step = region.closest('.step');
          const light = step?.querySelector('.light');
          if (!light) return "no-light";
          light.className = 'light light-ready';
          const was = document.querySelectorAll('.rail .error, .rail .pdr-error, .rail .action-output *').length;
          const aimed = region.getAttribute('hx-post')
            .replace(new RegExp('instances/[^/]+/'), 'instances/no-such-instance-round30/');
          region.setAttribute('hx-post', aimed);
          region.setAttribute('hx-trigger', 'recheck-probe');
          window.htmx.process(region);
          window.htmx.trigger(region, 'recheck-probe');
          await new Promise((r) => setTimeout(r, 1200));
          const after = [...document.querySelectorAll('.rail .error, .rail .pdr-error, .rail .action-output *')];
          if (after.length > was) return "interrupted:" + after.slice(was).map((e) => e.tagName + "." + e.className).join("|");
          if (document.body.textContent.includes('PDR-E202')) return "error-on-stage";
          return "quiet:" + light.className;
        })()`);
        check(quiet === "quiet:light light-pending",
          `a failed re-check says nothing on stage and drops the light to unknown (${quiet})`);
      }
      await shot("06-presenter");
    }
  } else {
    console.log("· no playbook rail on this instance; the step keys are not exercised");
  }

  // 5b. A reset the engine refuses says so. The console asks htmx to
  // swap every response (layout.html), so a refusal renders wherever the
  // control was aiming — and this one aims nowhere: its 202 is a job
  // envelope with no HTML twin (ADR-0003), so `hx-swap="none"` is right
  // for the success and threw the *failure* away with it. A refused
  // reset re-enabled the button and told the operator nothing, while no
  // ladder event is produced for a reset that never started.
  //
  // The refusal is the server's own and arrives every time: the submit
  // button's `formaction` — plain HTML, which htmx reads at request time
  // — aims this one press at an instance that does not exist. What is
  // under test is what the page does with the answer, and the region it
  // lands in is the template's, not one this check writes.
  await evaluate(`[...document.querySelectorAll('.statusbar .button, .statusbar .bar-action')].find(b => /Reset/.test(b.textContent))?.click()`);
  await settle(900);
  const dialog = await evaluate(`(() => {
    const d = document.querySelector('.reset-dialog');
    if (!d) return "no-dialog";
    const region = d.querySelector('.action-output');
    if (!region) return "no-region";
    if (region.textContent.trim() !== "") return "region-not-empty";
    return "ready";
  })()`);
  check(dialog === "ready", `the reset dialog opens with an empty region for a refusal (${dialog})`);
  if (dialog === "ready") {
    await evaluate(`(() => {
      const button = document.querySelector('.reset-dialog form button[type="submit"]');
      button.setAttribute("formaction", "/api/v1alpha1/instances/no-such-instance-round14/reset");
      button.click();
    })()`);
    await settle(1200);
    const refused = await evaluate(`(() => {
      const region = document.querySelector('.reset-dialog .action-output');
      if (!region) return "region-gone";
      const text = region.textContent.trim();
      if (text === "") return "silent";
      return /PDR-[A-Z]?\\d+/.test(text) ? "reported:" + text.slice(0, 60) : "unnamed:" + text.slice(0, 60);
    })()`);
    check(refused.startsWith("reported:"), `a refused reset says so where it was asked for (${refused})`);
    await shot("07-reset-refused");
  }

  // 5c. The licence and source page (the reconciliation plan's R5): one
  // link away from every page's footer, the same for everyone — it
  // carries no session chrome even for a signed-in operator — and read in
  // both themes, for the owner's eyeball and the contrast floor. Its
  // source locations are links, never requests; step 6 below holds every
  // request the page made to the gateway.
  {
    await goto(`${base}/`);
    const footerLink = await evaluate(`(() => {
      const a = document.querySelector('footer a[href="/legal"]');
      return a ? a.textContent.trim() : 'no-link';
    })()`);
    check(footerLink === "Licence and source", `the footer links to the licence and source page (${footerLink})`);
    await goto(`${base}/legal`);
    const legalPage = await evaluate(`(() => {
      const h1 = document.querySelector('main h1');
      const facts = [...document.querySelectorAll('.legal dl.facts dt')].map((d) => d.textContent.trim());
      const rows = document.querySelectorAll('.legal table.third-party tbody tr').length;
      const text = document.querySelector('main').textContent;
      return [h1 ? h1.textContent.trim() : 'no-h1',
              facts.includes('licence') && facts.includes('copyright') && facts.includes('source of this build') ? 'facts' : 'facts-missing:' + facts.join('|'),
              rows >= 20 ? 'components' : 'components:' + rows,
              /AGPL-3\.0-only/.test(text) && /to the extent copyright subsists/.test(text) ? 'statements' : 'statements-missing',
              document.querySelector('.who') ? 'session-chrome' : 'no-session-chrome'].join(',');
    })()`);
    check(legalPage === "Licence and source,facts,components,statements,no-session-chrome",
      `the legal page: its heading, the licence, the statements, the source offer and the components, with no session chrome (${legalPage})`);
    await send(ws, "Emulation.setDeviceMetricsOverride", { width: 1600, height: 900, deviceScaleFactor: 1, mobile: false }, S);
    await settle(300);
    await chooseTheme("light");
    const legalLight = await contrast();
    check(legalLight === "all-clear", `every sampled pair on the legal page clears its ratio in Light (${legalLight})`);
    await shot("16-legal-light", { width: 1600, height: 900 });
    await chooseTheme("dark");
    const legalDark = await contrast();
    check(legalDark === "all-clear", `every sampled pair on the legal page clears its ratio in Dark (${legalDark})`);
    await shot("17-legal-dark", { width: 1600, height: 900 });
    await chooseTheme("system");
    await send(ws, "Emulation.clearDeviceMetricsOverride", {}, S);
  }

  // 6. Every request the page made went to this gateway (UX §2 no. 9).
  // "External" means off the gateway — a CDN, a font host, an analytics
  // beacon. The lab's own product vhosts (`<service>-<instance>.<domain>`)
  // are the gateway too: serving them is what the product tabs are for,
  // and they travel over the same port under the same certificate.
  const consoleURL = new URL(base);
  const requested = events
    .filter((e) => e.method === "Network.requestWillBeSent")
    .map((e) => e.params.request.url);
  const origins = new Set(requested.map((u) => { try { return new URL(u).origin; } catch { return u; } }));
  const onTheGateway = (o) => {
    if (o.startsWith("data:") || o.startsWith("blob:")) return true;
    let u;
    try { u = new URL(o); } catch { return false; }
    return u.protocol === "https:" && u.port === consoleURL.port &&
      (u.hostname === consoleURL.hostname || u.hostname.endsWith("." + consoleURL.hostname));
  };
  // The fonts are the gateway's too (plan S13): they must be requested,
  // and from it — a face that silently fell back to a system font would
  // pass the check above by asking for nothing at all.
  const fontURLs = requested.filter((u) => /\.woff2(\?|$)/.test(u));
  const faceNames = ["poppins-latin-600-normal.woff2", "inter-latin-400-normal.woff2"];
  const served = faceNames.filter((n) => fontURLs.some((u) => u.includes(n) && onTheGateway(new URL(u).origin)));
  check(served.length === faceNames.length,
    `the console's faces are fetched from the gateway (${served.length}/${faceNames.length}: ${fontURLs.length} font request(s))`);
  const foreign = [...origins].filter((o) => !onTheGateway(o));
  check(foreign.length === 0,
    foreign.length === 0
      ? `no request left the gateway (${requested.length} requests over ${origins.size} of its hostnames)`
      : `requests left the gateway: ${foreign.join(", ")}`);
  await fs.writeFile(`${outDir}/requests.txt`, requested.join("\n") + "\n");

  // 7. No console errors — a page that throws is not a page that works.
  const errors = events
    .filter((e) => e.method === "Runtime.exceptionThrown")
    .map((e) => e.params.exceptionDetails.text);
  check(errors.length === 0, `no uncaught exceptions${errors.length ? ": " + errors.join(" | ") : ""}`);

  // 8. The rendered text of every page and state the walk saw, for the
  // identity guard (the reconciliation plan's R6) — the sign-in page and
  // the public legal page among them, the two a visitor with no session
  // reads.
  await fs.writeFile(`${outDir}/page-text.txt`, pageTexts.join("\n"));
  const dumped = [`${base}/login`, `${base}/legal`].filter((u) => pageTexts.some((t) => t.startsWith(`==> ${u} <==`)));
  check(dumped.length === 2,
    `the rendered text of every visited page is dumped to page-text.txt (${pageTexts.length} pages and states; sign-in and legal: ${dumped.length}/2)`);

  ws.close();
  if (failures.length) {
    console.error(`\nFAILED: ${failures.length}`);
    for (const f of failures) console.error("  - " + f);
    process.exit(1);
  }
  console.log("\nall S7 browser checks passed");
}

main().catch((e) => {
  console.error("walk failed:", e);
  process.exit(1);
});
