/* OctoScan AI security agent page.
 * Everything that comes from the API, the model or the scanned repo is
 * untrusted: the DOM is built with createElement + textContent only. */
"use strict";

(function () {
  // ---------------------------------------------------------------- helpers
  // Pure functions (no DOM): exported for node tests at the bottom.

  var SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  var VERDICT_RANK = { real: 0, review: 1, false_positive: 2 };
  var VERDICT_LABEL = { real: "Real", false_positive: "False positive", review: "Needs review" };
  var STAGES = ["scan", "prefilter", "triage", "fix", "verify", "story"];
  var TOOL_PHASE = {
    reuse_scan: "scan", scan: "scan", prefilter: "prefilter", triage: "triage",
    fix: "fix", verify: "fix", finish: "fix", story: "story"
  };
  var KNOWN_TOOLS = ["reuse_scan", "scan", "prefilter", "triage", "fix", "verify", "finish", "story"];
  var RUN_ID_RE = /^[a-fA-F0-9]{8,64}$/;

  function str(v) { return v === null || v === undefined ? "" : String(v); }
  function arr(v) { return Array.isArray(v) ? v : []; }

  function classifyDiffLine(line) {
    var l = str(line);
    if (l.indexOf("+++") === 0 || l.indexOf("---") === 0 || l.indexOf("diff ") === 0 || l.indexOf("index ") === 0) return "hdr";
    if (l.indexOf("@@") === 0) return "hunk";
    if (l.charAt(0) === "+") return "add";
    if (l.charAt(0) === "-") return "del";
    return "ctx";
  }

  function diffLines(diff) {
    var lines = str(diff).replace(/\r\n/g, "\n").split("\n");
    while (lines.length && lines[lines.length - 1] === "") lines.pop();
    return lines.map(function (l) { return { text: l, cls: classifyDiffLine(l) }; });
  }

  function verifiedBadge(v) {
    if (v === true) return { cls: "ok", text: "Verified by re-scan" };
    if (v === false) return { cls: "bad", text: "Not fixed (scanner still flags it)" };
    return { cls: "na", text: "Not verifiable" };
  }

  function sevKey(s) { var k = str(s).toLowerCase(); return SEV_RANK.hasOwnProperty(k) ? k : "info"; }
  function verdictKey(v) { var k = str(v); return VERDICT_RANK.hasOwnProperty(k) ? k : "review"; }

  function clampConf(c) {
    var n = Number(c);
    if (!isFinite(n)) return 0;
    return Math.max(0, Math.min(1, n));
  }
  function pct(c) { return Math.round(clampConf(c) * 100); }

  function sortFindings(list) {
    return arr(list).slice().sort(function (a, b) {
      return (VERDICT_RANK[verdictKey(a.verdict)] - VERDICT_RANK[verdictKey(b.verdict)])
        || (SEV_RANK[sevKey(a.severity)] - SEV_RANK[sevKey(b.severity)])
        || (clampConf(b.confidence) - clampConf(a.confidence))
        || str(a.file).localeCompare(str(b.file))
        || ((Number(a.line) || 0) - (Number(b.line) || 0));
    });
  }

  function countVerdicts(list) {
    var c = { all: 0, real: 0, false_positive: 0, review: 0 };
    arr(list).forEach(function (f) { c.all++; c[verdictKey(f.verdict)]++; });
    return c;
  }

  function filterFindings(list, filter) {
    if (!filter || filter === "all") return arr(list).slice();
    return arr(list).filter(function (f) { return verdictKey(f.verdict) === filter; });
  }

  function locText(file, line) {
    var f = str(file);
    if (!f) return "";
    var n = Number(line);
    return line !== null && line !== undefined && line !== "" && isFinite(n) ? f + ":" + n : f;
  }

  function findingById(findings, id) {
    var list = arr(findings);
    for (var i = 0; i < list.length; i++) if (str(list[i].id) === str(id)) return list[i];
    return null;
  }

  function fixTitle(findings, fix) {
    var f = findingById(findings, fix.finding_id);
    if (f && f.title) return str(f.title);
    return str(fix.rule) || ("Finding " + str(fix.finding_id));
  }

  // Index of the highlighted stage in STAGES (STAGES.length = all done, -1 = none yet).
  function stageIndex(run) {
    var phase = str(run && run.phase);
    if (run && run.status === "done") return STAGES.length;
    if (phase === "done") return STAGES.length;
    if (phase === "story") return 5;
    if (phase === "fix") {
      var steps = arr(run.steps);
      var last = steps.length ? steps[steps.length - 1] : null;
      return last && last.tool === "verify" ? 4 : 3;
    }
    return ["scan", "prefilter", "triage"].indexOf(phase);
  }

  function stageStates(run) {
    var idx = stageIndex(run);
    var failed = run && run.status === "failed";
    if (failed && idx < 0) idx = 0;
    return STAGES.map(function (key, i) {
      var st = i < idx ? "done" : i === idx ? (failed ? "error" : "active") : "pending";
      return { key: key, state: st };
    });
  }

  function formatElapsed(ms) {
    var s = Math.max(0, Math.floor((Number(ms) || 0) / 1000));
    var m = Math.floor(s / 60);
    var r = s % 60;
    return m + ":" + (r < 10 ? "0" : "") + r;
  }

  function formatMs(ms) {
    var n = Number(ms);
    if (!isFinite(n) || n < 0) return "";
    if (n < 1000) return Math.round(n) + " ms";
    return (n / 1000).toFixed(1) + " s";
  }

  function fmtInt(n) {
    var v = Number(n);
    if (!isFinite(v)) return "—";
    return Math.round(v).toLocaleString("en-US");
  }

  // FastAPI errors: {"detail": "..."} or {"detail": [{msg, loc}, ...]} (422).
  function errorDetail(status, body) {
    var d = body && typeof body === "object" ? body.detail : null;
    if (typeof d === "string" && d) return d;
    if (Array.isArray(d) && d.length) {
      return d.map(function (e) {
        if (e && typeof e === "object") {
          var loc = arr(e.loc).filter(function (x) { return x !== "body"; }).join(".");
          return (loc ? loc + ": " : "") + str(e.msg);
        }
        return str(e);
      }).join("; ");
    }
    if (status === 403 || status === 401) return "Invalid or missing API key.";
    if (status === 404) return "Agent run not found.";
    if (status === 429) return "Too many requests, retry in a moment.";
    return "Request failed (HTTP " + status + ").";
  }

  // The step that "produces" a fix in the recorded run: the last verify/fix
  // step naming its finding_id (or listing it in args.findings).
  function fixRevealStep(steps, fix) {
    var n = null;
    arr(steps).forEach(function (s) {
      var a = s && s.args && typeof s.args === "object" ? s.args : {};
      var hit = str(a.finding_id) === str(fix.finding_id)
        || arr(a.findings).map(str).indexOf(str(fix.finding_id)) >= 0;
      if (hit && (s.tool === "verify" || s.tool === "fix")) n = s.n;  // last one wins (after retries)
    });
    return n;
  }

  // Replay: turn a finished recorded run into a list of {run, delay} frames.
  function buildReplayFrames(rec) {
    var steps = arr(rec.steps);
    var findings = arr(rec.findings);
    var fixes = arr(rec.fixes);
    var stats = rec.stats && typeof rec.stats === "object" ? rec.stats : {};
    var reveal = fixes.map(function (fx) { return fixRevealStep(steps, fx); });
    var frames = [];
    var shownSteps = [];
    var shownFindings = [];
    var shownFixes = [];
    var scanId = null;
    var phase = "queued";

    function snap(over) {
      return Object.assign({
        run_id: str(rec.run_id) || "demo",
        status: "running",
        repo_url: rec.repo_url,
        target_url: rec.target_url || null,
        scan_id: scanId,
        phase: phase,
        current: "",
        steps: shownSteps.slice(),
        findings: shownFindings.slice(),
        fixes: shownFixes.slice(),
        verdict: null,
        blockers: [],
        attack_story: "",
        stats: { model: stats.model },
        error: null,
        created_at: null,
        finished_at: null
      }, over || {});
    }

    frames.push({ run: snap({ current: "queued: starting the agent…" }), delay: 900 });
    steps.forEach(function (s) {
      phase = TOOL_PHASE[s.tool] || phase;
      var running = Object.assign({}, s, { status: "running", result: "", ms: 0 });
      frames.push({
        run: snap({ current: str(s.tool) + ": " + str(s.thought), steps: shownSteps.concat([running]) }),
        delay: s.tool === "fix" || s.tool === "triage" || s.tool === "story" ? 1000 : 700
      });
      shownSteps = shownSteps.concat([s]);
      if (s.tool === "reuse_scan" || s.tool === "scan") scanId = rec.scan_id || null;
      if (s.tool === "triage") shownFindings = findings.slice();
      fixes.forEach(function (fx, i) {
        if (reveal[i] === s.n) shownFixes = shownFixes.filter(function (x) { return x.finding_id !== fx.finding_id; }).concat([fx]);
      });
      frames.push({ run: snap({ current: str(s.tool) + ": " + str(s.result) }), delay: 450 });
    });
    frames.push({
      run: Object.assign({}, rec, { status: rec.status === "failed" ? "failed" : "done", phase: "done", current: "" }),
      delay: 0
    });
    return frames;
  }

  function stepSig(s) {
    return [s.status, s.tool, s.thought, s.result, s.ms, s.args && s.args.attempt].map(str).join("\u0001");
  }

  var helpers = {
    classifyDiffLine: classifyDiffLine, diffLines: diffLines, verifiedBadge: verifiedBadge,
    sortFindings: sortFindings, countVerdicts: countVerdicts, filterFindings: filterFindings,
    pct: pct, clampConf: clampConf, locText: locText, fixTitle: fixTitle, stageIndex: stageIndex,
    stageStates: stageStates, formatElapsed: formatElapsed, formatMs: formatMs, errorDetail: errorDetail,
    fixRevealStep: fixRevealStep, buildReplayFrames: buildReplayFrames, RUN_ID_RE: RUN_ID_RE
  };
  if (typeof module !== "undefined" && module.exports) module.exports = helpers;
  if (typeof document === "undefined") return;

  // -------------------------------------------------------------------- DOM

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function setText(e, text) {
    var t = str(text);
    if (e.textContent !== t) e.textContent = t;
  }

  var els = {
    form: $("agent-form"), repo: $("repo-url"), key: $("api-key"), btn: $("run-btn"),
    err: $("error-banner"), warn: $("warn-banner"), empty: $("empty-state"), view: $("run-view"),
    pill: $("status-pill"), demoPill: $("demo-pill"), repoLabel: $("repo-label"), elapsed: $("elapsed"),
    track: $("track"), current: $("current"),
    stModel: $("st-model"), stCalls: $("st-calls"), stLatency: $("st-latency"), stFallback: $("st-fallback"), stTokens: $("st-tokens"),
    timeline: $("timeline"), stepsCount: $("steps-count"),
    verdictSection: $("verdict-section"), verdictCard: $("verdict-card"),
    fixesSection: $("fixes-section"), fixes: $("fixes"), fixesCount: $("fixes-count"),
    findingsSection: $("findings-section"), findingsBody: $("findings-body"), chips: $("chips"),
    footerModel: $("footer-model")
  };

  var POLL_MS = 2000;
  var MAX_POLL_ERRORS = 5;

  var state = {
    mode: "idle",          // idle | live | demo
    busy: false,
    run: null,
    renderedId: null,
    filter: "all",
    localStart: Date.now(),
    localEnd: null,
    stepCards: new Map(),  // n -> {el, refs, sig}
    fixCards: new Map(),   // finding_id -> {el, sig}
    fixesSig: null,
    findingsSig: null,
    verdictSig: null
  };

  // ---- API key (same storage as the dashboard)
  try { els.key.value = localStorage.getItem("apiKey") || ""; } catch (e) { /* storage blocked */ }
  els.key.addEventListener("change", function () {
    try { localStorage.setItem("apiKey", els.key.value.trim()); } catch (e) { /* ignore */ }
  });
  function apiHeaders(json) {
    var h = {};
    if (json) h["Content-Type"] = "application/json";
    var k = (els.key.value || "").trim();
    if (k) h["X-API-Key"] = k;
    return h;
  }

  // ---- banners
  function showError(msg) { setText(els.err, msg); els.err.hidden = !msg; }
  function showWarn(msg) { setText(els.warn, msg); els.warn.hidden = !msg; }

  function setBusy(b) {
    state.busy = b;
    els.btn.disabled = b;
    setText(els.btn, b ? "Agent running…" : "Run agent");
  }

  // ---- reset between runs
  function resetView() {
    state.stepCards.clear();
    state.fixCards.clear();
    state.fixesSig = state.findingsSig = state.verdictSig = null;
    els.timeline.replaceChildren();
    els.fixes.replaceChildren();
    els.findingsBody.replaceChildren();
    els.verdictCard.replaceChildren();
    els.verdictSection.hidden = true;
    els.fixesSection.hidden = true;
    els.findingsSection.hidden = true;
    state.renderedId = null;
  }

  // ---- render
  function render(run) {
    if (!run || typeof run !== "object") return;
    if (state.renderedId !== str(run.run_id)) {
      resetView();
      state.renderedId = str(run.run_id);
    }
    state.run = run;
    els.empty.hidden = true;
    els.view.hidden = false;
    renderStatus(run);
    renderStats(run.stats);
    renderSteps(arr(run.steps));
    renderVerdict(run);
    renderFixes(run);
    renderFindings(arr(run.findings));
  }

  function renderStatus(run) {
    var st = str(run.status) || "running";
    var known = st === "running" || st === "done" || st === "failed";
    els.pill.className = "pill" + (known ? " " + st : "");
    setText(els.pill, st);
    els.demoPill.hidden = state.mode !== "demo";
    setText(els.repoLabel, str(run.repo_url) + (run.scan_id ? "  ·  scan " + str(run.scan_id) : ""));
    var stages = stageStates(run);
    stages.forEach(function (s) {
      var li = els.track.querySelector('li[data-stage="' + s.key + '"]');
      if (!li) return;
      var cls = s.state === "pending" ? "" : s.state;
      if (li.className !== cls) li.className = cls;
      if (s.state === "active") li.setAttribute("aria-current", "step"); else li.removeAttribute("aria-current");
    });
    var cur = str(run.current);
    if (!cur) {
      if (st === "done") cur = "done: verdict " + (run.verdict === "ready" ? "READY" : run.verdict === "not_ready" ? "NOT READY" : "none");
      else if (st === "failed") cur = "failed";
      else cur = "working…";
    }
    setText(els.current, cur);
    if (st === "failed") showError("Agent run failed: " + (str(run.error) || "unknown error"));
    updateElapsed();
  }

  function elapsedMs() {
    var run = state.run;
    if (!run) return 0;
    if (state.mode !== "demo") {
      var a = Date.parse(str(run.created_at));
      if (isFinite(a)) {
        var b = run.finished_at ? Date.parse(str(run.finished_at)) : Date.now();
        if (isFinite(b)) return Math.max(0, b - a);
      }
    }
    return (state.localEnd || Date.now()) - state.localStart;
  }
  function updateElapsed() { if (state.run) setText(els.elapsed, formatElapsed(elapsedMs())); }
  setInterval(function () { if (state.run && state.run.status === "running") updateElapsed(); }, 1000);

  function renderStats(stats) {
    var s = stats && typeof stats === "object" ? stats : {};
    var model = str(s.model) || "—";
    setText(els.stModel, model);
    setText(els.footerModel, model);
    var hasNums = s.calls !== undefined && s.calls !== null;
    setText(els.stCalls, hasNums ? fmtInt(s.calls) : "—");
    setText(els.stLatency, hasNums ? fmtInt(s.median_latency_ms) + " ms" : "—");
    if (s.fallback_used === true || s.fallback_used === false) {
      setText(els.stFallback, s.fallback_used ? "yes" : "no");
      els.stFallback.className = "v " + (s.fallback_used ? "yes" : "no");
    } else {
      setText(els.stFallback, "—");
      els.stFallback.className = "v";
    }
    setText(els.stTokens, hasNums ? fmtInt(s.tokens_in) + " / " + fmtInt(s.tokens_out) : "—");
  }

  // Step cards are keyed by n and only their text is updated (no flicker).
  function createStepCard() {
    var card = el("div", "step");
    var head = el("div", "step-head");
    var n = el("span", "step-n");
    var tool = el("span", "tool");
    var attempt = el("span", "attempt");
    attempt.hidden = true;
    var right = el("span", "step-right");
    var spin = el("span", "spinner");
    spin.setAttribute("aria-hidden", "true");
    var ms = el("span", "step-ms");
    right.append(spin, ms);
    head.append(n, tool, attempt, right);
    var thought = el("p", "step-thought");
    var lbl = el("span", "lbl", "Thought:");
    var tText = el("span", "txt");
    thought.append(lbl, tText);
    var result = el("p", "step-result");
    card.append(head, thought, result);
    return { el: card, refs: { n: n, tool: tool, attempt: attempt, spin: spin, ms: ms, thought: thought, tText: tText, result: result }, sig: null };
  }

  function updateStepCard(rec, s) {
    var sig = stepSig(s);
    if (rec.sig === sig) return;
    rec.sig = sig;
    var r = rec.refs;
    var tool = str(s.tool);
    var toolCls = KNOWN_TOOLS.indexOf(tool) >= 0 ? "t-" + tool : "t-other";
    var status = s.status === "running" || s.status === "error" ? s.status : "done";
    var cls = "step " + status + " " + toolCls;
    if (rec.el.className !== cls) rec.el.className = cls;
    var toolBadge = "tool " + toolCls;
    if (r.tool.className !== toolBadge) r.tool.className = toolBadge;
    setText(r.n, "#" + str(s.n));
    setText(r.tool, tool || "step");
    var att = s.args && Number(s.args.attempt);
    r.attempt.hidden = !(att > 1);
    if (att > 1) setText(r.attempt, "retry, attempt " + att);
    r.spin.hidden = status !== "running";
    setText(r.ms, status === "running" ? "running…" : formatMs(s.ms));
    r.thought.hidden = !str(s.thought);
    setText(r.tText, s.thought);
    r.result.hidden = !str(s.result);
    setText(r.result, s.result);
  }

  function renderSteps(steps) {
    var box = els.timeline;
    var nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
    var sorted = steps.slice().sort(function (a, b) { return (Number(a.n) || 0) - (Number(b.n) || 0); });
    var seen = {};
    sorted.forEach(function (s) {
      var key = str(s.n);
      seen[key] = true;
      var rec = state.stepCards.get(key);
      if (!rec) {
        rec = createStepCard();
        state.stepCards.set(key, rec);
        box.appendChild(rec.el);
      }
      updateStepCard(rec, s);
    });
    state.stepCards.forEach(function (rec, key) {
      if (!seen[key]) { rec.el.remove(); state.stepCards.delete(key); }
    });
    if (!sorted.length && !box.firstChild) {
      box.appendChild(el("div", "empty", "Waiting for the agent's first step…"));
    } else if (sorted.length) {
      var ph = box.querySelector(":scope > .empty");
      if (ph) ph.remove();
    }
    setText(els.stepsCount, sorted.length ? sorted.length + " step" + (sorted.length === 1 ? "" : "s") : "");
    // follow the newest step only if the user has not scrolled up to read
    if (nearBottom && sorted.length) box.scrollTop = box.scrollHeight;
  }

  function renderVerdict(run) {
    var v = run.verdict === "ready" || run.verdict === "not_ready" ? run.verdict : null;
    els.verdictSection.hidden = !v;
    if (!v) { state.verdictSig = null; return; }
    var sig = JSON.stringify([v, run.blockers, run.attack_story]);
    if (sig === state.verdictSig) return;
    state.verdictSig = sig;
    var card = els.verdictCard;
    card.className = "panel verdict " + v;
    var head = el("div", "vd-head");
    head.append(
      el("span", "vd-badge " + v, v === "ready" ? "READY" : "NOT READY"),
      el("span", "vd-sub", v === "ready" ? "No launch blockers left in the confirmed findings." : "Fix the blockers below before launch.")
    );
    var parts = [head];
    var blockers = arr(run.blockers);
    if (blockers.length) {
      parts.push(el("div", "vd-h", "Blockers (" + blockers.length + ")"));
      var ul = el("ul", "blockers");
      blockers.forEach(function (b) { ul.appendChild(el("li", null, b)); });
      parts.push(ul);
    }
    var story = str(run.attack_story).trim();
    if (story) {
      parts.push(el("div", "vd-h", "How an attacker would break in"));
      var sd = el("div", "story");
      story.split(/\n\s*\n|\n/).forEach(function (p) { if (p.trim()) sd.appendChild(el("p", null, p.trim())); });
      parts.push(sd);
    }
    parts.push(el("p", "human-note", "Patches are suggestions: a human reviews and applies them."));
    card.replaceChildren.apply(card, parts);
  }

  function copyText(text, btn) {
    function done(ok) {
      setText(btn, ok ? "Copied" : "Copy failed");
      setTimeout(function () { setText(btn, "Copy diff"); }, 1500);
    }
    function fallback() {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      ta.remove();
      done(ok);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, fallback);
    } else {
      fallback();
    }
  }

  function buildFixCard(fix, findings) {
    var card = el("article", "panel fix");
    var head = el("div", "fix-head");
    var badge = verifiedBadge(fix.verified);
    head.append(el("div", "fix-title", fixTitle(findings, fix)), el("span", "vbadge " + badge.cls, badge.text));
    card.appendChild(head);
    var f = findingById(findings, fix.finding_id);
    var loc = locText(fix.file || (f && f.file), f ? f.line : null);
    if (loc) card.appendChild(el("div", "loc", loc));
    if (str(fix.note)) card.appendChild(el("p", "fix-note", "Scanner: " + str(fix.note)));
    if (str(fix.explanation)) card.appendChild(el("p", "fix-expl", fix.explanation));
    var diff = str(fix.diff);
    if (diff.trim()) {
      var wrap = el("div", "diff-wrap");
      var bar = el("div", "diff-bar");
      bar.appendChild(el("span", null, "Suggested patch"));
      var copy = el("button", "btn secondary small", "Copy diff");
      copy.type = "button";
      copy.addEventListener("click", function () { copyText(diff, copy); });
      bar.appendChild(copy);
      var box = el("div", "diffbox");
      box.tabIndex = 0;
      box.setAttribute("aria-label", "Unified diff");
      var pre = el("pre", "diff");
      diffLines(diff).forEach(function (l) { pre.appendChild(el("span", "dl " + l.cls, l.text === "" ? " " : l.text)); });
      box.appendChild(pre);
      wrap.append(bar, box);
      card.appendChild(wrap);
    } else {
      card.appendChild(el("p", "no-diff", "No code patch: advice only."));
    }
    return card;
  }

  function renderFixes(run) {
    var fixes = arr(run.fixes);
    var findings = arr(run.findings);
    els.fixesSection.hidden = !fixes.length;
    var titles = fixes.map(function (fx) { return fixTitle(findings, fx); });
    var sig = JSON.stringify([fixes, titles]);
    if (sig === state.fixesSig) return;
    state.fixesSig = sig;
    var next = new Map();
    var nodes = fixes.map(function (fx, i) {
      var key = str(fx.finding_id) + "#" + i;
      var s = JSON.stringify([fx, titles[i]]);
      var old = state.fixCards.get(key);
      var rec = old && old.sig === s ? old : { el: buildFixCard(fx, findings), sig: s };
      next.set(key, rec);
      return rec.el;
    });
    state.fixCards = next;
    // only touch the DOM when the node list really changed
    var same = nodes.length === els.fixes.children.length && nodes.every(function (n, i) { return els.fixes.children[i] === n; });
    if (!same) els.fixes.replaceChildren.apply(els.fixes, nodes);
    var v = fixes.filter(function (x) { return x.verified === true; }).length;
    setText(els.fixesCount, fixes.length + " patch" + (fixes.length === 1 ? "" : "es") + ", " + v + " verified by re-scan");
  }

  function buildFindingRow(f) {
    var vk = verdictKey(f.verdict);
    var sk = sevKey(f.severity);
    var row = el("div", "frow");
    row.setAttribute("role", "row");
    var cSev = el("div", "c-sev");
    cSev.appendChild(el("span", "sev " + sk, str(f.severity) || "info"));
    var cMain = el("div", "c-main");
    cMain.appendChild(el("div", "ftitle", f.title));
    var meta = [locText(f.file, f.line), str(f.scanner)].filter(Boolean).join("  ·  ");
    if (meta) cMain.appendChild(el("div", "fmeta", meta));
    var reason = el("div", "freason");
    reason.append(el("span", "lbl", "Why:"), document.createTextNode(str(f.reason) || "no reason given"));
    cMain.appendChild(reason);
    var cVerdict = el("div", "c-verdict");
    cVerdict.appendChild(el("span", "vb " + vk, VERDICT_LABEL[vk]));
    var cConf = el("div", "c-conf");
    var p = pct(f.confidence);
    cConf.appendChild(el("span", "conf-pct", p + "%"));
    var bar = el("div", "conf-bar " + vk);
    bar.setAttribute("role", "img");
    bar.setAttribute("aria-label", "confidence " + p + " percent");
    var fill = el("span");
    fill.style.width = p + "%";
    bar.appendChild(fill);
    cConf.appendChild(bar);
    [cSev, cMain, cVerdict, cConf].forEach(function (c) { c.setAttribute("role", "cell"); });
    row.append(cSev, cMain, cVerdict, cConf);
    return row;
  }

  function renderFindings(findings) {
    els.findingsSection.hidden = !findings.length;
    var counts = countVerdicts(findings);
    Array.prototype.forEach.call(els.chips.querySelectorAll("[data-count]"), function (n) {
      setText(n, counts[n.getAttribute("data-count")] || 0);
    });
    Array.prototype.forEach.call(els.chips.querySelectorAll("[data-filter]"), function (b) {
      var on = b.getAttribute("data-filter") === state.filter ? "true" : "false";
      if (b.getAttribute("aria-pressed") !== on) b.setAttribute("aria-pressed", on);
    });
    var sig = JSON.stringify([state.filter, findings]);
    if (sig === state.findingsSig) return;
    state.findingsSig = sig;
    var rows = sortFindings(filterFindings(findings, state.filter)).map(buildFindingRow);
    if (!rows.length) rows = [el("div", "fempty", "No findings in this filter.")];
    els.findingsBody.replaceChildren.apply(els.findingsBody, rows);
  }

  els.chips.addEventListener("click", function (ev) {
    var b = ev.target.closest("[data-filter]");
    if (!b) return;
    state.filter = b.getAttribute("data-filter");
    if (state.run) renderFindings(arr(state.run.findings));
  });

  // ---- polling (exactly one poller at a time)
  var pollGen = 0;
  var pollTimer = null;

  function stopPolling() {
    pollGen++;
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = null;
  }

  function startPolling(runId) {
    stopPolling();
    var gen = pollGen;
    var errors = 0;
    setBusy(true);

    function schedule() { if (gen === pollGen) pollTimer = setTimeout(tick, POLL_MS); }
    function stop(msg) {
      if (gen !== pollGen) return;
      stopPolling();
      setBusy(false);
      showWarn("");
      if (msg) showError(msg);
    }

    function tick() {
      pollTimer = null;
      if (gen !== pollGen) return;
      var status = 0;
      fetch("/api/agent-scan/" + encodeURIComponent(runId), { headers: apiHeaders(false), cache: "no-store" })
        .then(function (res) {
          status = res.status;
          return res.json().then(function (b) { return b; }, function () { return null; })
            .then(function (body) { return { ok: res.ok, body: body }; });
        })
        .then(function (r) {
          if (gen !== pollGen) return;
          if (r.ok && r.body && typeof r.body === "object" && !Array.isArray(r.body)) {
            errors = 0;
            showWarn("");
            render(r.body);
            if (r.body.status === "done" || r.body.status === "failed") stop(null);
            else schedule();
            return;
          }
          if (status >= 400 && status < 500 && status !== 408 && status !== 429) {
            stop(errorDetail(status, r.body));
            return;
          }
          fail("server answered HTTP " + status);
        })
        .catch(function (e) {
          if (gen !== pollGen) return;
          fail(e && e.message ? e.message : "network error");
        });
    }

    function fail(why) {
      errors++;
      if (errors >= MAX_POLL_ERRORS) {
        stop("Lost contact with the server (" + why + ") after " + errors + " tries. The run may still be going: reload the page to resume.");
        return;
      }
      showWarn("Connection problem (" + why + "), retrying… " + errors + "/" + MAX_POLL_ERRORS);
      schedule();
    }

    tick();
  }

  // ---- demo replay (no API calls)
  var replayGen = 0;
  var replayTimer = null;

  function stopReplay() {
    replayGen++;
    if (replayTimer) clearTimeout(replayTimer);
    replayTimer = null;
  }

  function startDemo() {
    stopPolling();
    stopReplay();
    var gen = replayGen;
    state.mode = "demo";
    showError("");
    showWarn("");
    setBusy(true);
    fetch("/static/fake-agent-run.json", { cache: "no-store" })
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (rec) {
        if (gen !== replayGen) return;
        if (!rec || typeof rec !== "object") throw new Error("bad recording");
        if (rec.repo_url) els.repo.value = str(rec.repo_url);
        var frames = buildReplayFrames(rec);
        var i = 0;
        state.renderedId = null;
        state.localStart = Date.now();
        state.localEnd = null;
        (function next() {
          replayTimer = null;
          if (gen !== replayGen) return;
          var f = frames[i++];
          if (i === frames.length) state.localEnd = Date.now();
          render(f.run);
          if (i < frames.length) replayTimer = setTimeout(next, f.delay);
          else setBusy(false);
        })();
      })
      .catch(function (e) {
        if (gen !== replayGen) return;
        setBusy(false);
        showError("Could not load the recorded run: " + (e && e.message ? e.message : "error"));
      });
  }

  // ---- start a live run
  function startRun() {
    if (state.busy && state.mode !== "demo") return;
    var repo = (els.repo.value || "").trim();
    showError("");
    showWarn("");
    if (!/^https:\/\/\S+$/i.test(repo)) {
      showError("Enter a public https repository URL, e.g. https://github.com/OWASP/NodeGoat");
      return;
    }
    stopReplay();
    stopPolling();
    state.mode = "live";
    els.demoPill.hidden = true;
    setBusy(true);
    var status = 0;
    fetch("/api/agent-scan", {
      method: "POST",
      headers: apiHeaders(true),
      body: JSON.stringify({ repo_url: repo, target_url: null })
    })
      .then(function (res) {
        status = res.status;
        return res.json().then(function (b) { return { ok: res.ok, body: b }; }, function () { return { ok: res.ok, body: null }; });
      })
      .then(function (r) {
        var id = r.body && r.body.run_id ? str(r.body.run_id) : "";
        if (!r.ok || !RUN_ID_RE.test(id)) {
          setBusy(false);
          showError(r.ok ? "The server did not return a valid run id." : errorDetail(status, r.body));
          return;
        }
        try { history.replaceState(null, "", "?run=" + encodeURIComponent(id)); } catch (e) { /* ignore */ }
        beginLive(id, repo);
      })
      .catch(function (e) {
        setBusy(false);
        showError("Could not reach the API: " + (e && e.message ? e.message : "network error"));
      });
  }

  function beginLive(id, repo) {
    state.mode = "live";
    state.localStart = Date.now();
    state.localEnd = null;
    render({
      run_id: id, status: "running", repo_url: repo || "", phase: "queued",
      current: "queued: loading run " + id + "…", steps: [], findings: [], fixes: [],
      verdict: null, stats: {}, created_at: null
    });
    startPolling(id);
  }

  els.form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    startRun();
  });

  // ---- boot
  var params;
  try { params = new URLSearchParams(window.location.search); } catch (e) { params = null; }
  if (params && params.get("demo") === "1") {
    startDemo();
  } else if (params && params.get("run")) {
    var rid = params.get("run");
    if (RUN_ID_RE.test(rid)) beginLive(rid, "");
    else showError("The run id in the URL is not valid.");
  }
})();
