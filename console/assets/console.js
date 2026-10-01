// SPDX-License-Identifier: AGPL-3.0-only
//
// The console's purely local state (ADR-0003): warm tab switching, the
// rail, the reveal countdown and the keyboard map. Everything else —
// what a lab is, what a checkpoint says — comes from the engine as
// rendered fragments; nothing here decides a fact.
//
// Written for Alpine's CSP build, which the console's strict
// Content-Security-Policy requires: expressions in templates are limited
// to property and method references, so every handler below is a named
// method and reads its parameters from the element's data attributes
// rather than from an inline argument list.

// saveProgress records the learner's position and what they have earned
// (API §8). It exists because the rail is the console's *view* of a
// playbook and `PUT …/progress` is where a playbook's state actually
// lives: without this, closing the tab returns the learner to the first
// step, the start-here card cannot offer "Resume at …", and a completed
// lab has no record of having been completed.
//
// The whole record is sent, not the one field that changed: the engine
// replaces a progress row rather than merging into it, so a body
// carrying only the new position would erase the statuses already
// earned. The rail carries the current record in `data-progress` — the
// `GET …/progress` twin, marshalled — and this changes one field of it
// and stores back what the engine accepted.
//
// It saves in Guided only. Manual §3 assigns saved progress to that
// mode; Presenter is a person advancing their own slides and Author
// preview is free navigation over a lab being written, and neither
// should leave a record of a learner's work that no learner did.
//
// A failed write is not an error the learner sees. The position is a
// convenience; the lab is the containers and the checkpoints, and
// neither depends on it.
// The writes are queued, one at a time, and each body is built when its
// turn comes rather than when it was asked for. Two of them in flight at
// once both read the same base — the endpoint replaces the record whole,
// so whichever answered last would put back the step the other had
// moved past, or erase the status it had just earned.
// A queue is the whole fix: there is one writer.
let progressQueue = Promise.resolve();

function saveProgress(rail, changes) {
  if (!rail || rail.dataset.mode !== "guided") return progressQueue;
  progressQueue = progressQueue.then(() => writeProgress(rail, changes)).catch(() => {});
  return progressQueue;
}

async function writeProgress(rail, changes) {
  const playbook = rail.dataset.playbook;
  const instance = rail.dataset.instance;
  if (!playbook || !instance) return;
  let body;
  try {
    // Read at the moment of writing: by now the write before this one
    // has stored what the engine accepted.
    body = JSON.parse(rail.dataset.progress || "{}");
  } catch (_) {
    body = {};
  }
  if (!body.steps) body.steps = {};
  if (changes.current_step) body.current_step = changes.current_step;
  if (changes.step && changes.status) {
    body.steps[changes.step] = { status: changes.status, at: new Date().toISOString() };
  }
  try {
    const resp = await fetch(
      `/api/v1alpha1/instances/${encodeURIComponent(instance)}/playbooks/${encodeURIComponent(playbook)}/progress`,
      {
        method: "PUT",
        headers: { "Content-Type": "application/json", "X-Podaro-CSRF": rail.dataset.csrf || "" },
        body: JSON.stringify(body),
      },
    );
    if (!resp.ok) return;
    // Store what the engine accepted, not what was sent: a claim it
    // refused must not become the base of the next write.
    const saved = await resp.json();
    rail.dataset.progress = JSON.stringify({
      current_step: saved.current_step || body.current_step,
      steps: saved.steps || body.steps,
    });
    // The start-here card is a projection of the instance twin, and
    // since round 4 what it says depends on this record: a learner who
    // advances off a checkpoint-free first step now qualifies for
    // "Resume". A progress write emits no event on the feed, so nothing
    // refreshed the card and it went on saying "Begin" until something
    // unrelated happened. This is the
    // same read the feed's listeners make, so the card, the status bar
    // and the tab words all come back together, out of band.
    if (window.htmx) {
      window.htmx.ajax("GET", `/api/v1alpha1/instances/${encodeURIComponent(instance)}`,
        { target: "#ladder-region", swap: "innerHTML" });
    }
  } catch (_) {
    // Offline, or the engine restarting: the page keeps working.
  }
}

// L: `data-running-label` was inert metadata. A control that is merely
// disabled during a slow checkpoint tells a learner nothing about
// whether anything started (UX §6), so the label is applied while the
// request is in flight and put back after it.
document.addEventListener("htmx:beforeRequest", (event) => {
  const el = event.detail && event.detail.elt;
  if (!el || !el.dataset || !el.dataset.runningLabel) return;
  el.dataset.restLabel = el.textContent;
  el.textContent = el.dataset.runningLabel;
});
document.addEventListener("htmx:afterRequest", (event) => {
  const el = event.detail && event.detail.elt;
  if (!el || !el.dataset || el.dataset.restLabel === undefined) return;
  el.textContent = el.dataset.restLabel;
  delete el.dataset.restLabel;
});

// G: an auto step is one control (spec 0001 §8) — press it and the
// step's seeds run in the order the playbook names them, and then it is
// judged. The sequence lives here because it *is* a sequence; each part
// of it is an ordinary API call the console could make on its own.
document.addEventListener("click", async (event) => {
  // `.run-step` is an auto step's one control; `.seed-button` is a
  // single declared seed. Different controls, same need: post, wait for
  // the job, say what happened. They keep separate classes because the
  // rest of the console — and several tests — mean "the one control" by
  // `run-step`, and overloading it would blur exactly the distinction
  // rounds 5 and 8 were about.
  const button = event.target.closest && event.target.closest(".run-step, .seed-button");
  if (!button) return;
  const { instance, csrf, actions, action, result } = button.dataset;
  // Spec 0001 defines this control as *all* of the step's actions
  // followed by its verification. It read only the seeds, so a declared
  // `reveal` was never run — and the per-action controls are suppressed
  // for an auto step, so it had no other way to happen.
  // The list is `kind:name` in the playbook's order.
  //
  // A step's actions and its verification are two things, and only the
  // second is optional: `checkpoint` is not required by
  // schemas/playbook.v1alpha1.json, so a schema-valid auto step may
  // declare actions and nothing to judge them by. Bailing on the empty
  // action left that step's one control doing nothing at all (round 5).
  const todo = (actions || "").split(",").filter(Boolean);
  if (!action && todo.length === 0) return;
  const rest = button.textContent;
  button.disabled = true;
  button.textContent = button.dataset.runningLabel || "Running…";
  const reveals = button.closest(".actions")?.querySelector(".action-output");
  if (reveals) reveals.innerHTML = "";
  try {
    for (const item of todo) {
      const sep = item.indexOf(":");
      const kind = item.slice(0, sep);
      const name = item.slice(sep + 1);
      if (!name) continue;
      if (kind === "reveal") {
        // A reveal answers with the fragment that carries the value, its
        // countdown and the control that re-masks it. The per-action
        // controls are gone for an auto step, so it lands in the region
        // the step carries for exactly this.
        const resp = await fetch(
          `/api/v1alpha1/instances/${encodeURIComponent(instance)}/secrets/${encodeURIComponent(name)}/reveal`,
          { method: "POST", headers: { "X-Podaro-CSRF": csrf || "", Accept: "text/html" } },
        );
        // A refused reveal stops the step and says so, exactly as a
        // refused seed does below. This branch returned in silence — the
        // button simply came back — so a learner whose session had
        // expired, or whose reveal was refused, watched the one control
        // do nothing and had no way to know why.
        // The request asks for HTML, so what comes back is
        // the server's own error fragment: the §3 envelope's twin, with
        // its code and its next step.
        if (!resp.ok) {
          const failed = button.closest(".actions")?.querySelector(".action-output");
          const envelope = await resp.text().catch(() => "");
          if (failed && envelope) {
            failed.insertAdjacentHTML("beforeend", envelope);
            if (window.htmx) window.htmx.process(failed);
          } else {
            receipt(button, name + " could not be revealed", false);
          }
          return;
        }
        const html = await resp.text();
        // Appended, not assigned: a step may declare more than one
        // reveal, and replacing the region took the first credential
        // away before anyone could copy it — every request audited, one
        // value usable. The region is
        // cleared once, before the run.
        const region = button.closest(".actions")?.querySelector(".action-output");
        if (region) {
          region.insertAdjacentHTML("beforeend", html);
          if (window.htmx) window.htmx.process(region);
        }
        continue;
      }
      const resp = await fetch(
        `/api/v1alpha1/instances/${encodeURIComponent(instance)}/seeds/${encodeURIComponent(name)}`,
        { method: "POST", headers: { "X-Podaro-CSRF": csrf || "", Accept: "application/json" } },
      );
      // A seed that was refused stops the step: judging a lab the step
      // did not finish setting up would report a failure about the wrong
      // thing.
      if (!resp.ok) {
        receipt(button, name + " was refused", false);
        return;
      }
      // A 202 means the job was *admitted*, not that the data is in
      // (API §4). Verifying now would judge the lab as it was, and the
      // next seed would be refused by the exclusive slot this one holds
      // — the step would be nondeterministic.
      // So each job is waited out before the next thing.
      const body = await resp.json().catch(() => null);
      const id = body && body.job && body.job.id;
      if (id && !(await awaitJob(instance, id))) {
        receipt(button, name + " did not finish", false);
        return;
      }
      if (!action) receipt(button, name + " sent", true);
    }
    if (!action) return;
    // innerHTML, into the result wrapper: the wrapper owns the id, so
    // an error envelope swapped in cannot take the target with it.
    await window.htmx.ajax("POST", action, {
      target: result,
      swap: "innerHTML",
      headers: { "X-Podaro-CSRF": csrf || "" },
    });
    // And what the step earned is recorded, as a Verify press is: the
    // swap above goes through htmx.ajax, which carries no element, so
    // the global handler cannot see whose result it was.
    const step = button.closest(".step");
    const rail = button.closest(".rail");
    if (rail) syncSpine(rail);
    if (step && rail) recordStatus(rail, step);
  } finally {
    button.disabled = false;
    button.textContent = rest;
  }
});

// The receipt a control leaves behind. A seed press that vanishes tells
// a learner nothing about whether the declared action happened, and the
// ladder is not where they are looking.
function receipt(button, text, ok) {
  const region = button.closest(".actions")?.querySelector(".action-output");
  if (!region) return;
  const p = document.createElement("p");
  p.className = "result status-" + (ok ? "pass" : "fail");
  p.setAttribute("role", "status");
  p.textContent = text;
  region.appendChild(p);
}

// awaitJob waits for one job to finish, and answers whether it
// succeeded. It gives up after a while rather than holding the control
// disabled for ever: a job that outlives this is still running, and the
// ladder on the feed is where it is followed.
async function awaitJob(instance, id, budgetMs = 120000) {
  const started = Date.now();
  while (Date.now() - started < budgetMs) {
    await new Promise((r) => setTimeout(r, 500));
    let job;
    try {
      const resp = await fetch(`/api/v1alpha1/jobs/${encodeURIComponent(id)}`, {
        headers: { Accept: "application/json" },
      });
      if (!resp.ok) return false;
      job = (await resp.json()).job;
    } catch (_) {
      return false;
    }
    if (!job) return false;
    if (job.state === "succeeded") return true;
    if (job.state === "failed") return false;
  }
  return false;
}

// J: the status bar's Evidence action pointed at a hidden panel and
// nothing selected it, so it moved the URL fragment and no more.
document.addEventListener("click", (event) => {
  const link = event.target.closest && event.target.closest("[data-tab-link]");
  if (!link) return;
  const strip = document.querySelector(".tabs");
  if (!strip || !window.Alpine) return;
  const data = window.Alpine.$data(strip);
  if (data && data.show) {
    event.preventDefault();
    data.show(link.dataset.tabLink);
  }
});

// The pointer's way through the rail. Until this existed the only code
// that moved the current step was the `[`/`]` key handler, so a mouse or
// touch user could work through every card while the position saved on
// the instance stayed on step one — and the start-here card offered them
// "Begin" the next morning.
//
// Two gestures, one path. The Previous/Next controls are the announced
// ones — UX §8's Guided row names Next, and UX §9's map gives them their
// keyboard twins. A click on the card itself is the unannounced
// convenience: a pointer user who has scrolled to step five and starts
// reading it has said which step they are on, and the rail should
// believe them. It yields to anything interactive inside the card, so
// pressing Verify, opening "Show me", or following an evidence link
// still does only that.
function selectionIsCollapsed() {
  try {
    const sel = window.getSelection();
    return !sel || sel.isCollapsed;
  } catch (_) {
    return true;
  }
}

// The collapsed rail's spine is the way back into it (UX §6). It is a
// control in swapped-in markup, so it is handled here rather than with
// an Alpine binding, exactly as the step controls beside it are.
document.addEventListener("click", (event) => {
  if (!event.target.closest) return;
  const spine = event.target.closest("[data-rail-toggle]");
  if (!spine) return;
  const surface = spine.closest(".lab");
  if (!surface || !window.Alpine) return;
  const lab = window.Alpine.$data(surface);
  if (lab && lab.toggleRail) lab.toggleRail();
});

document.addEventListener("click", (event) => {
  if (!event.target.closest) return;
  const nav = event.target.closest("[data-step-move]");
  const row = nav ? null : event.target.closest(".step");
  if (!nav && !row) return;
  if (row && event.target.closest("button, a, summary, input, select, textarea, label, iframe")) return;
  // A drag to select a sentence ends with a click on the card it was in.
  // Reading ahead is not choosing a step, and taking it for one would
  // move the position saved on the instance under a learner who never
  // asked — and drop their selection when the new step takes focus. A
  // collapsed selection is an ordinary click; anything else is a read.
  if (row && !selectionIsCollapsed()) return;
  const surface = (nav || row).closest(".lab");
  if (!surface || !window.Alpine) return;
  const data = window.Alpine.$data(surface);
  if (!data) return;
  if (nav && data.step) {
    data.step(Number(nav.dataset.stepMove) || 0);
  } else if (row && data.selectStep) {
    data.selectStep(row);
  }
});

// spineDotFor is the collapsed rail's dot for one step. The mapping is
// by position, because the spine renders one dot per step in the rail's
// own order (rail.html) — written once, so the two things that move a
// dot cannot disagree about which one is whose.
function spineDotFor(step) {
  const rail = step.closest(".rail");
  const spine = rail && rail.querySelector(".rail-spine");
  if (!spine) return null;
  const steps = Array.from(rail.querySelectorAll(".step"));
  return spine.querySelectorAll(".spine-dot")[steps.indexOf(step)] || null;
}

// syncSpine paints every dot from the result its own step is showing.
//
// Every dot, and not the one whose button was pressed: a checkpoint that
// serves several steps answers with out-of-band swaps into each of their
// result regions (result.html), and a Presenter re-check is initiated by
// the light region rather than by any step at all. Painting from the
// initiating step left a sibling — or every step in Presenter — showing
// a verdict the collapsed rail contradicted.
// Reading each dot from its own step's result cannot get that
// wrong, whatever the response happened to change.
//
// The status is read from the result the server rendered and never
// decided here: the console does not judge checkpoints.
function syncSpine(rail) {
  if (!rail || !rail.querySelector(".rail-spine")) return;
  rail.querySelectorAll(".step").forEach((step) => {
    const result = step.querySelector(".result");
    const dot = spineDotFor(step);
    if (!result || !dot) return;
    const status = (Array.from(result.classList).find((c) => c.startsWith("status-")) || "").slice(7);
    // `error` is a verdict the result template renders in its own amber,
    // and it was not in this list: a checkpoint that passed and then
    // errored turned the result amber and left the dot green, which is
    // the one way for the collapsed rail to be reassuring and wrong.
    // The list here is what the page
    // *shows*; the list in recordStatus is what the engine *accepts* for
    // progress, and they are deliberately not the same — PutProgress
    // takes pass, fail, attested and skipped, and would refuse an error.
    if (!["pass", "fail", "attested", "error"].includes(status)) return;
    Array.from(dot.classList)
      .filter((c) => c.startsWith("status-"))
      .forEach((c) => dot.classList.remove(c));
    dot.classList.add("status-" + status);
    // The glyph and the word come from the result the server rendered,
    // not from a second mapping written here: UX §4 pairs colour, glyph
    // and word, and two mappings for one pairing is how they come to
    // disagree.
    const mark = dot.querySelector(".spine-glyph");
    const said = dot.querySelector(".spine-word");
    const shown = result.querySelector(".glyph");
    const word = result.querySelector(".word");
    if (mark && shown) mark.textContent = shown.textContent;
    if (said && word) {
      const position = step.querySelector(".step-position");
      said.textContent = (position ? position.textContent.trim().split(" · ")[0] + ": " : "") +
        word.textContent.trim() + ". ";
    }
  });
}

// recordStatus saves what a step just earned on the instance. The status
// is read from the result the server rendered and never decided here.
// walkedStatus is what *reaching* a step records, if anything.
//
// A step with no checkpoint has nothing to judge, so reaching it is the
// whole of it — and the engine says exactly that: `PutProgress` refuses
// any other status for such a step ("step X has no checkpoint: only
// skipped can be recorded for it"). The console never wrote it, so a
// playbook holding a narrative step could never be finished: both
// shipped playbooks have several, and the completion card round 30
// added could not appear for either.
//
// The fact comes from the server's own render (`data-checkpoint`, from
// the checkpoints twin) rather than from the presence of a control,
// because a control's absence has several causes and this has one.
function walkedStatus(step) {
  return step && step.dataset && !step.dataset.checkpoint ? "skipped" : "";
}

// recordWalked records that for a step the learner is already on — the
// first paint's step, and the one a freshly swapped rail opens at.
// Moving to a step is `selectStep`'s to record, in the same write that
// moves the position.
function recordWalked(rail, step) {
  const walked = walkedStatus(step);
  if (rail && walked) saveProgress(rail, { step: step.dataset.step, status: walked });
}

function recordStatus(rail, step) {
  const result = step.querySelector(".result");
  if (!result) return;
  const status = (Array.from(result.classList).find((c) => c.startsWith("status-")) || "").slice(7);
  if (["pass", "fail", "attested"].includes(status)) {
    saveProgress(rail, { step: step.dataset.step, status });
  }
}

// The theme (UX §4, plan S12): System, Light or Dark, chosen from the
// status bar, remembered by this browser in localStorage and by nothing
// else — the engine never learns it, and it is not a cookie. `theme.js`
// applies a stored choice before first paint; this is the same reading,
// for the control and for Presenter's default. Every storage access is
// wrapped: a browser that refuses storage (a private window, blocked
// site data) still switches for the page's lifetime.
const THEME_KEY = "podaro.theme";

// The choice this page made, for the page's lifetime. Storage may refuse
// to remember it (a private window, blocked site data); the page still
// wears the theme, so the control must press what was chosen, not what
// storage holds. Presenter's unstored
// light default is not a choice and never lands here.
let chosen = null;

function storedTheme() {
  try {
    const choice = window.localStorage.getItem(THEME_KEY);
    return choice === "light" || choice === "dark" ? choice : null;
  } catch (_) {
    return null;
  }
}

// currentChoice is what this page has chosen: the press it made, else
// what storage holds — `system`, `light`, `dark`, or null when nothing
// was ever chosen. The control and Presenter's default both read it,
// so a choice storage refused to keep is still the choice everywhere.
function currentChoice() {
  return chosen || storedTheme();
}

// applyTheme sets the page's theme now and, when asked, remembers it.
// `system` is the absence of a choice: the attribute comes off and the
// stylesheet follows the OS.
function applyTheme(choice, remember) {
  const root = document.documentElement;
  if (choice === "light" || choice === "dark") root.dataset.theme = choice;
  else delete root.dataset.theme;
  if (remember) {
    chosen = choice === "light" || choice === "dark" ? choice : "system";
    try {
      if (choice === "light" || choice === "dark") window.localStorage.setItem(THEME_KEY, choice);
      else window.localStorage.removeItem(THEME_KEY);
    } catch (_) {
      // Refused storage: the page keeps the theme for its lifetime, and
      // `chosen` is what the control presses.
    }
  }
  document.dispatchEvent(new CustomEvent("podaro:theme"));
}

// Presenter opens light (UX §4: projectors wash out dark themes) when
// neither Light nor Dark is the choice, and does so once per presenter
// rail: the default is applied without being stored, so it is not
// mistaken for a choice, and it stays until the page is reloaded or a
// choice is pressed — leaving Presenter never flips the theme back,
// because a theme change mid-session is a pop, and Presenter forbids
// pops (UX §8). A press on the control while Presenter is open is a
// choice like any other, and is kept. "Once per rail", not once per
// page: a whole rail arrives only when a person opens a playbook or a
// mode, so a Presenter opened again after System was pressed opens
// light again, while the swaps inside an open rail — the lights
// re-check every twenty seconds — never re-apply it over a press.
let presenterRail = null;
function presenterDefault(rail) {
  if (!rail || rail.dataset.presenter !== "true" || rail === presenterRail) return;
  presenterRail = rail;
  const choice = currentChoice();
  if (choice !== "light" && choice !== "dark") applyTheme("light", false);
}

// A verify that produced a verdict records it against its step. The
// engine judges the claim against the checkpoint's own latest result
// (engine.PutProgress), so a status this sends is one the result already
// supports; a claim it does not is refused, and refusing is fine — the
// verdict itself is in evidence either way.
// afterSettle, not afterRequest: the status is read from the result the
// server rendered, so the swap must already have happened.
document.addEventListener("htmx:afterSettle", (event) => {
  const detail = event.detail;
  const elt = detail && detail.elt;
  const xhr = detail && detail.xhr;
  if (!elt || !elt.closest || !xhr || xhr.status >= 400) return;
  // The rail this settle belongs to, whether the target is inside it or
  // is the region it was swapped into. Opening a playbook aims at
  // `#rail`, which *contains* the rail and is not inside it, so asking
  // only `closest` returned null on exactly the path that brings a rail
  // into being — and the first step of a swapped-in rail was recorded by
  // nothing.
  const rail = elt.closest(".rail") || (elt.querySelector && elt.querySelector(".rail"));
  if (!rail) return;
  // A presenter rail that has just arrived opens the page light when
  // nothing is chosen (UX §4); a Guided rail, the chooser and the reset
  // dialog leave the theme alone.
  presenterDefault(rail);
  // Anything that settled inside a rail may have changed a verdict
  // somewhere in it, so the spine is re-read from the steps themselves.
  syncSpine(rail);
  // A rail that has just been swapped in opens at a step nobody selected,
  // so nothing else would record it.
  recordWalked(rail, rail.querySelector(".step.current"));
  // The progress write is the settled result's own: it records the
  // verdict that region is now showing, which is what this learner
  // earned there.
  //
  // It used to ask whether `detail.elt` was the Verify button. It never
  // is: htmx dispatches this on the *target*, and a Verify button always
  // aims at its step's result region — so the test was never true and an
  // ordinary Verify press recorded nothing at all. Only the auto step's
  // one control, which calls `recordStatus` itself after `htmx.ajax`,
  // ever wrote a step's status, which is why the hole survived every
  // round that looked at progress. Found by walking the shipped playbook
  // to its end.
  //
  // Round 30 fixed the same misreading of `elt` in the handler above, by
  // asking `requestConfig.elt` for the control that fired. That is not
  // available here — this event carries no `requestConfig` (the page
  // said so: `result-region||result-region`) — so the target is what
  // decides, and it decides precisely: a step's result region is only
  // ever the target of that step's own checkpoint control, and a
  // Presenter re-check cannot reach this because `saveProgress` writes
  // in Guided alone.
  if (!elt.classList || !elt.classList.contains("result-region")) return;
  const step = elt.closest(".step");
  if (step) recordStatus(rail, step);
});

// Whether a tab is one this layout offers. Only a positive "the
// stylesheet hides this" rejects: a page whose stylesheet never arrived
// offers every tab rather than none, and the width itself is never read
// here — the breakpoint lives in console.css, and a copy of it in this
// file would be a second one to keep in step.
function available(tab) {
  return !!tab && getComputedStyle(tab).display !== "none";
}

// A request that failed says so where it was made. The console asks htmx
// to swap every response (layout.html: `responseHandling` is `.*`), so a
// refusal renders as the server's own error fragment wherever the
// control was aiming — except for a control aiming nowhere. The reset
// form is exactly that: its 202 is a job envelope with no HTML twin
// (ADR-0003), so `hx-swap="none"` is right for the success and threw the
// failure away with it. A reset the engine refused, because another
// exclusive job holds the instance, re-enabled the button and left the
// page exactly as it was, and no ladder event is produced for a reset
// that never started.
//
// So a failure is re-aimed at the region its own component carries. The
// swap is still htmx's, of the server's own fragment — the §3 envelope's
// HTML twin, with its code, cause and next step — never a sentence this
// file invents about a failure it did not diagnose. The status is read
// from the response rather than from `isError`, which this console's
// response handling deliberately never sets.
document.addEventListener("htmx:beforeSwap", (event) => {
  const detail = event.detail;
  if (!detail || !detail.xhr || detail.xhr.status < 400) return;
  const elt = detail.elt;
  if (!elt || !elt.closest) return;
  // Except that nothing at all lands from a request the presenter did
  // not make. UX §8's Presenter row is "absolutely none — no toasts,
  // modals, or async popups", and the confidence light's re-check is an
  // unattended timer: a 4xx or 5xx from it — the instance being reset
  // from another window, the session ending — would have swapped the
  // error panel into the rail on stage, unbidden.
  //
  // The light goes hollow instead, which is what hollow means: "unknown"
  // (UX §6). Not stale green, which is the failure the re-check exists
  // to prevent, and not amber, which is reserved for a regression the
  // engine actually judged.
  //
  // The element to ask is the one that *made* the request. On a swap
  // aimed elsewhere htmx reports `detail.elt` as the target — here the
  // step's result region — and only `requestConfig.elt` is the control
  // that fired (found by asking the page: `result-region/404/true`).
  const source = (detail.requestConfig && detail.requestConfig.elt) || elt;
  if (source.classList && source.classList.contains("light-region")) {
    detail.shouldSwap = false;
    const step = source.closest(".step");
    const light = step && step.querySelector(".light");
    if (light) light.className = "light light-pending";
    return;
  }
  // The region belongs to the component the control is in, so a refusal
  // cannot land under someone else's button — and a control that swaps
  // itself keeps existing, rather than being replaced by the error.
  const scope = elt.closest(".reset-dialog, .step");
  const region = scope && scope.querySelector(".action-output");
  if (!region) return;
  detail.target = region;
  detail.swapOverride = "innerHTML";
  detail.shouldSwap = true;
});

document.addEventListener("alpine:init", () => {
  // The tab strip. Panels are warm: once a tab has been shown its panel
  // stays in the document and is only hidden, so switching back costs no
  // reload — the iframe keeps its session and scroll position (UX §6,
  // and the <150 ms warm switch of §11).
  Alpine.data("tabs", () => ({
    current: "overview",
    init() {
      this.show(this.current);
      // Resize covers a turned phone too, and is debounced because a
      // drag fires it continuously; the check itself is a style read.
      this._reflow = () => {
        clearTimeout(this._pending);
        this._pending = setTimeout(() => this.reflow(), 150);
      };
      window.addEventListener("resize", this._reflow);
    },
    destroy() {
      clearTimeout(this._pending);
      window.removeEventListener("resize", this._reflow);
    },
    select(event) {
      const button = event.currentTarget || event.target;
      if (button && button.dataset.tab) this.show(button.dataset.tab);
    },
    show(id) {
      const root = this.$root;
      const tabs = Array.from(root.querySelectorAll("[data-tab]"));
      // A tab the stylesheet is hiding cannot be selected. Under 768px
      // the product tabs and their panels are `display: none` (UX §10);
      // round 9 stopped their buttons from being pressed, and that was
      // half of it — `show` still took those ids from the other two
      // callers, a numeric shortcut and a step whose context is that
      // product, so Overview was hidden and a panel the stylesheet was
      // suppressing marked selected: a blank product area.
      // This is the choke point, so every caller is
      // covered by the one rule.
      if (!available(tabs.find((tab) => tab.dataset.tab === id))) return;
      this.current = id;
      // Switching tabs highlights the steps that apply there (Manual §7):
      // the rail stays authoritative for context either way, so a learner
      // who wandered into a product tab can see which steps belong to it.
      document.querySelectorAll(".step[data-context]").forEach((step) => {
        step.classList.toggle("for-tab", step.dataset.context === id);
      });
      tabs.forEach((tab) => {
        const on = tab.dataset.tab === id;
        tab.setAttribute("aria-selected", on ? "true" : "false");
        tab.tabIndex = on ? 0 : -1;
      });
      // The panels are the strip's siblings, not its children: this
      // looked them up under the strip's own root and therefore found
      // none, so no panel was ever shown or hidden. It went unnoticed
      // while every panel but Evidence was rendered visible; rendering
      // them hidden — which is what stops a browser loading every
      // product iframe during parsing — is what made it matter.
      document.querySelectorAll(".panels .panel").forEach((panel) => {
        panel.hidden = panel.id !== "panel-" + id;
      });
    },
    // A layout that narrows under a selected tab. The rule above stops a
    // hidden tab from being *chosen*; nothing was watching the tab that
    // was already chosen when the window narrowed or the device turned,
    // and the stylesheet then hid both that tab and its panel while
    // Overview stayed hidden by its own attribute — a blank workspace
    // until some other shortcut was pressed.
    // The same predicate decides it, so there is still one rule and
    // still no copy of the breakpoint in this file.
    reflow() {
      const tabs = Array.from(this.$root.querySelectorAll("[data-tab]"));
      const on = tabs.find((tab) => tab.dataset.tab === this.current);
      if (!available(on)) {
        const first = tabs.find(available);
        // `show` re-seats the keyboard's stop on what it selects.
        if (first) this.show(first.dataset.tab);
        return;
      }
      // The selection can still be visible while the *keyboard's* stop
      // is not: arrowing moves `tabIndex 0` without selecting anything
      // (round 28), so a learner who arrowed onto a product and then
      // narrowed the window left the strip's only stop on a tab the
      // stylesheet now hides — every visible tab at `-1`, and Tab
      // skipping the strip altogether.
      // It goes back where `show` puts it: on the selection.
      if (!available(tabs.find((tab) => tab.tabIndex === 0))) {
        tabs.forEach((tab) => {
          tab.tabIndex = tab === on ? 0 : -1;
        });
      }
    },
    // Arrow keys walk the strip, which is the WAI-ARIA tabs pattern and
    // the only way across it for a lab with more tabs than the digits
    // reach. `show` gives the selected tab `tabIndex 0` and every other
    // `-1` — the roving tabindex the pattern asks for — so Tab enters
    // the strip once and lands on the selection; without arrows, a tab
    // that no digit names could not be focused at all. The template
    // schema puts no maximum on `services`, so a tenth product is a
    // supported input and UX §9 says "fully keyboard operable".
    //
    // Focus moves; activation does not follow it. A product panel is an
    // iframe that loads when it is shown, so arrowing across the strip
    // with automatic activation would load every product on the way
    // past — the pattern's manual activation is the one for panels that
    // cost something, and Enter or Space (a button's own activation,
    // through `select`) opens the focused tab.
    walk(event) {
      if (event.altKey || event.ctrlKey || event.metaKey) return;
      const steps = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1, Home: "first", End: "last" };
      const step = steps[event.key];
      if (step === undefined) return;
      // The same predicate the rest of this component uses: a tab the
      // stylesheet is hiding is not on the way anywhere (UX §10).
      const tabs = Array.from(this.$root.querySelectorAll("[data-tab]")).filter(available);
      if (tabs.length === 0) return;
      event.preventDefault();
      let next;
      if (step === "first") {
        next = tabs[0];
      } else if (step === "last") {
        next = tabs[tabs.length - 1];
      } else {
        // From where the keyboard is, or from the selection when focus
        // is somewhere the strip does not know about.
        let from = tabs.indexOf(document.activeElement);
        if (from === -1) from = tabs.findIndex((tab) => tab.dataset.tab === this.current);
        next = tabs[(from + step + tabs.length) % tabs.length];
      }
      if (!next) return;
      // The roving tabindex follows focus, so leaving and re-entering
      // the strip comes back to where the keyboard was.
      tabs.forEach((tab) => {
        tab.tabIndex = tab === next ? 0 : -1;
      });
      next.focus();
    },
    // 1–9 select a tab by position (UX §9). The map is the strip's own
    // order, so it matches what the eye counts.
    byIndex(n) {
      // Only the tabs the eye can count: on a phone the products are not
      // in the strip, so 2 is the second tab that is actually offered.
      const tabs = Array.from(this.$root.querySelectorAll("[data-tab]")).filter(available);
      if (n >= 1 && n <= tabs.length) this.show(tabs[n - 1].dataset.tab);
    },
  }));

  // The lab surface: the rail toggle and the keyboard map. Key handling
  // is document-level because the shortcuts are the page's, not one
  // widget's — but it never fires while the caret is in a field, and
  // never with a modifier held, so it cannot steal a browser shortcut or
  // eat someone's typing.
  Alpine.data("lab", () => ({
    railOpen: true,
    mapOpen: false,
    init() {
      this._keys = (event) => this.onKey(event);
      document.addEventListener("keydown", this._keys);
      // The first paint's rail arrives with the page rather than through
      // a swap, so its opening step is recorded here.
      const rail = this.$root.querySelector(".rail");
      if (rail) recordWalked(rail, rail.querySelector(".step.current"));
      if (rail) presenterDefault(rail);
    },
    destroy() {
      document.removeEventListener("keydown", this._keys);
    },
    toggleRail() {
      this.railOpen = !this.railOpen;
      this.$root.dataset.rail = this.railOpen ? "open" : "closed";
    },
    // `?` shows the keyboard map (UX §9). The map is rendered into the
    // page hidden and this is what un-hides it — the property alone was
    // read by nothing, so the shortcut did nothing at all.
    // `hidden` rather than a class, so a page whose
    // stylesheet never arrived still hides it.
    toggleMap() {
      this.mapOpen = !this.mapOpen;
      const region = document.getElementById("keymap-region");
      if (region) region.hidden = !this.mapOpen;
    },
    onKey(event) {
      if (event.metaKey || event.ctrlKey || event.altKey) return;
      const el = event.target;
      if (el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName))) return;
      switch (event.key) {
        case "[":
          this.step(-1);
          break;
        case "]":
          this.step(1);
          break;
        case "v":
          this.verifyCurrent();
          break;
        case "r":
          this.toggleRail();
          break;
        case "?":
          this.toggleMap();
          break;
        default:
          if (/^[1-9]$/.test(event.key)) {
            const strip = Alpine.$data(this.$root.querySelector(".tabs"));
            if (strip && strip.byIndex) strip.byIndex(Number(event.key));
            return;
          }
          return;
      }
      event.preventDefault();
    },
    // [ and ] move the focused step. The rail scrolls it into view and
    // focuses its heading, so a keyboard-only walk keeps its place and a
    // screen reader is told where it landed.
    step(delta) {
      const steps = Array.from(this.$root.querySelectorAll(".step"));
      if (steps.length === 0) return;
      let i = steps.findIndex((s) => s.classList.contains("current"));
      if (i < 0) i = 0;
      this.selectStep(steps[Math.min(steps.length - 1, Math.max(0, i + delta))]);
    },
    // selectStep is what selecting a step *is*, whichever gesture asked
    // for it: the keys, the Previous/Next controls, or a click on the
    // card itself. One implementation, so a pointer walk and a keyboard
    // walk cannot drift apart.
    selectStep(next) {
      if (!next) return;
      const steps = Array.from(this.$root.querySelectorAll(".step"));
      steps.forEach((s) => {
        s.classList.toggle("current", s === next);
        if (s === next) {
          s.setAttribute("aria-current", "step");
        } else {
          s.removeAttribute("aria-current");
        }
      });
      // Selecting a step focuses the product tab it belongs to (Manual
      // §7). A step whose context names no tab — an overview step, or a
      // product this instance does not run — leaves the tab strip alone
      // rather than jumping somewhere arbitrary.
      const context = next.dataset.context;
      if (context && document.querySelector(`[data-tab="${context}"]`)) {
        const strip = Alpine.$data(document.querySelector(".tabs"));
        if (strip && strip.show) strip.show(context);
      }
      // The collapsed rail names where the learner is, so it moves with
      // them. The spine is rendered once with the fragment and a
      // progress write emits no rail refresh, so without this it went on
      // naming the step that was current when the rail loaded — in its
      // dot, its title and its accessible name — however far they had
      // walked. Here, because this is
      // where selection happens for all three gestures.
      this.markSpine(next);
      next.scrollIntoView({ block: "nearest" });
      const title = next.querySelector(".step-title");
      if (title) {
        title.tabIndex = -1;
        title.focus();
      }
      const changes = { current_step: next.dataset.step };
      const walked = walkedStatus(next);
      if (walked) {
        changes.step = next.dataset.step;
        changes.status = walked;
      }
      saveProgress(next.closest(".rail"), changes);
    },
    // markSpine points the collapsed rail at a step: its dot, the title
    // it shows, and the name a screen reader is given. The label is
    // built the way the server builds it (RailData.SpineLabel) —
    // position, then the step's title — so the two cannot drift apart
    // between a fragment render and a walk through the steps.
    markSpine(step) {
      const rail = step.closest(".rail");
      const spine = rail && rail.querySelector(".rail-spine");
      if (!spine) return;
      spine.querySelectorAll(".spine-dot").forEach((dot) => dot.classList.remove("current"));
      const here = spineDotFor(step);
      if (here) here.classList.add("current");
      const title = step.querySelector(".step-title");
      if (!title) return;
      // The position line carries the pacing too when notes are shown;
      // the position is its first part, which is what the label wants.
      const position = step.querySelector(".step-position");
      const label = (position ? position.textContent.trim().split(" · ")[0] + " · " : "") + title.textContent.trim();
      // The title is part of the button's accessible name, so writing it
      // is writing that too. No `aria-label` is set here or in the
      // template: one would replace the name the contents compose, and
      // the dots' words would be announced by nothing (round 24).
      const shown = spine.querySelector(".spine-title");
      if (shown) shown.textContent = label;
    },
    // v verifies the current step (UX §9, and the keymap says exactly
    // that). Whichever control does the verifying: an `auto: true` step
    // with a machine checkpoint renders its one control and no separate
    // Verify (RailStep.OffersVerify), and that is every such step in
    // both shipped playbooks — so looking only for `.verify-button` made
    // the documented key do nothing on the steps it is most useful on.
    //
    // Verify first, because a step may carry both: an auto attest step
    // runs its actions through the one control and is confirmed through
    // "I confirm this", and the confirmation is the verification there.
    //
    // The comment that stood here said Presenter has no such button and
    // the key must not invent one. Presenter renders the one control
    // too, so pressing what is already on the screen invents nothing;
    // what Presenter still has no button for is a lone checkpoint, and
    // there the key does nothing, as before.
    verifyCurrent() {
      const step = this.$root.querySelector(".step.current") || this.$root.querySelector(".step");
      if (!step) return;
      const button = step.querySelector(".verify-button") || step.querySelector(".run-step");
      if (button && !button.disabled) button.click();
    },
  }));

  // A revealed credential re-masks itself. The countdown reads the
  // remask window the server sent (data-remask), never a constant of its
  // own, so the two can never disagree.
  //
  // At zero the value is *removed from the document*, not hidden: a
  // secret behind `display: none` is a secret still in the page, in the
  // DOM inspector and in a saved copy of it. What comes back is the
  // control that revealed it, which the fragment carries with it — so
  // the remask works identically in the credentials table and in a
  // playbook step, which is what the swap-an-ancestor version could not
  // do.
  Alpine.data("reveal", () => ({
    left: 0,
    init() {
      this.left = Number(this.$root.dataset.remask || 0);
      if (this.left <= 0) {
        this.remask();
        return;
      }
      this._tick = setInterval(() => {
        this.left -= 1;
        if (this.left <= 0) {
          clearInterval(this._tick);
          this.remask();
        }
      }, 1000);
    },
    remask() {
      const root = this.$root;
      root.querySelectorAll(".value, .copy, .countdown").forEach((el) => el.remove());
      root.querySelectorAll(".masked, .reveal").forEach((el) => {
        el.hidden = false;
      });
    },
    // Copy puts the value on the clipboard — the button's whole job, and
    // the way a credential gets from here into a product's login form.
    // The clipboard API needs a secure context, which the console is;
    // where it is refused the button says so rather than looking as
    // though it worked.
    async copy() {
      const value = this.$root.querySelector(".value");
      if (!value) return;
      const button = this.$root.querySelector(".copy");
      try {
        await navigator.clipboard.writeText(value.textContent);
        if (button) button.textContent = "Copied";
      } catch (_) {
        if (button) button.textContent = "Copy failed";
      }
    },
    destroy() {
      if (this._tick) clearInterval(this._tick);
    },
  }));

  // The theme control (UX §6, plan S12): the fifth purely local
  // component ADR-0003 assigns to Alpine. The server renders no button
  // pressed — it does not know the choice and must not — and `init`
  // presses the stored one, System when nothing is stored. Property and
  // method references only, the CSP build's rule.
  Alpine.data("theme", () => ({
    init() {
      this.reflect();
      this._onTheme = () => this.reflect();
      document.addEventListener("podaro:theme", this._onTheme);
    },
    destroy() {
      document.removeEventListener("podaro:theme", this._onTheme);
    },
    choose(event) {
      const button = event.target.closest("[data-theme-choice]");
      if (!button) return;
      applyTheme(button.dataset.themeChoice, true);
    },
    // What is pressed is the choice, never the page's momentary theme:
    // Presenter's unstored light default leaves System pressed, which
    // is the truth about what was chosen. A choice this page made comes
    // first, because storage may have refused to keep it.
    reflect() {
      const current = currentChoice() || "system";
      this.$root.querySelectorAll("[data-theme-choice]").forEach((button) => {
        button.setAttribute("aria-pressed", button.dataset.themeChoice === current ? "true" : "false");
      });
    },
  }));
});
