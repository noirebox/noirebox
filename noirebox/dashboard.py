"""FLIGHT DECK — the NoireBox supervision view, styled as the instrument
panel of the box itself. Four switchable views, one journal:

- **DECK** (default): the chain as a vertical spine — every link visible,
  prev_hash → event_hash → signature on each block.
- **VAULT**: the same events as sealed envelopes — payload behind an
  unseal toggle, signature rendered as a wax seal.
- **TAPE**: the journal as a horizontal ticker-tape readout, like the
  film-to-paper playbacks of early flight recorders.
- **TRAFFIC**: the journal as a live radar — one node per event type on
  the perimeter, one beam per real sealed event flowing to the chain head,
  an amber pulse when an anchor seals the whole past. Tails the journal
  with a seq cursor (`since_seq`); nothing is simulated.

Plus the DEPARTURES / ARRIVALS board: the two-event pattern (issue #3) —
decisions depart, outcomes arrive, unpaired rows light up. And THE WITNESS:
the last RFC 3161 anchor sealed into the chain.

Not a generic admin dashboard: every element speaks flight recorder.

Hard rules (unchanged since design review):
1. Read-only — this view never mutates the journal.
2. It renders; it never attests — the exported dossier remains the proof.
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NoireBox — Flight Deck</title>
<style>
  :root { --bg:#05060a; --panel:#0a0c12; --line:rgba(255,255,255,.08);
    --line2:rgba(255,255,255,.16); --txt:#e8ecf1; --dim:#9aa4b2;
    --dimmer:#616b7a; --red:#e10600; --red-soft:#ff8577; --green:#3fb950;
    --amber:#f5a623; --mono:ui-monospace,SFMono-Regular,Menlo,monospace; }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:var(--bg); color:var(--txt); font-family:var(--mono);
    padding:28px 4vw; font-size:14px; }
  header { display:flex; align-items:center; justify-content:space-between;
    flex-wrap:wrap; gap:14px; margin-bottom:24px; }
  h1 { font-size:.95rem; letter-spacing:.22em; font-weight:800; }
  h1 .cube { display:inline-block; width:11px; height:11px; border-radius:3px;
    background:linear-gradient(145deg,#2a2e38,#0d1117); margin-right:9px;
    box-shadow: inset 0 0 6px rgba(225,6,0,.5), 0 0 12px rgba(225,6,0,.25); }
  .seal { font-weight:800; padding:9px 20px; border-radius:8px;
    font-size:.9rem; letter-spacing:.08em; }
  .seal.ok { color:var(--green); border:1px solid rgba(63,185,80,.5);
    background:rgba(63,185,80,.08); }
  .seal.bad { color:var(--red-soft); border:1px solid rgba(225,6,0,.6);
    background:rgba(225,6,0,.1); animation:pulse 1.1s infinite; }
  @keyframes pulse { 50% { opacity:.5; } }
  .viewbtns { display:flex; gap:6px; margin-bottom:22px; }
  .viewbtn { font-family:var(--mono); font-size:.72rem; letter-spacing:.14em;
    padding:7px 16px; border-radius:8px; cursor:pointer;
    background:var(--panel); color:var(--dimmer); border:1px solid var(--line); }
  .viewbtn.on { color:var(--txt); border-color:var(--red-soft);
    background:rgba(225,6,0,.08); }
  .strip { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr));
    gap:10px; margin-bottom:26px; }
  .card { background:var(--panel); border:1px solid var(--line);
    border-radius:10px; padding:14px 16px; }
  .card b { display:block; font-size:1.25rem; font-weight:800; }
  .card span { font-size:.64rem; letter-spacing:.16em; text-transform:uppercase;
    color:var(--dimmer); }
  h2 { font-size:.7rem; letter-spacing:.2em; text-transform:uppercase;
    color:var(--dimmer); margin:24px 0 10px; }
  .board { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
  @media (max-width: 900px) { .board { grid-template-columns:1fr; } }
  .panelbox { background:var(--panel); border:1px solid var(--line);
    border-radius:12px; overflow:hidden; }
  .panelbox h3 { font-size:.7rem; letter-spacing:.18em; text-transform:uppercase;
    color:var(--dimmer); padding:12px 16px; border-bottom:1px solid var(--line);
    background:rgba(255,255,255,.02); }
  table { width:100%; border-collapse:collapse; font-size:.82rem; }
  th { text-align:left; color:var(--dimmer); font-size:.62rem;
    letter-spacing:.14em; text-transform:uppercase; padding:8px 14px;
    border-bottom:1px solid var(--line); }
  td { padding:9px 14px; border-bottom:1px solid var(--line); color:var(--dim); }
  td.mono { color:var(--txt); }
  .chip { border-radius:99px; padding:2px 10px; font-size:.7rem; white-space:nowrap; }
  .chip.matched { color:var(--green); border:1px solid rgba(63,185,80,.45); }
  .chip.pending { color:var(--amber); border:1px solid rgba(245,166,35,.5); }
  .chip.unconfirmed, .chip.unauthorized { color:var(--red-soft);
    border:1px solid rgba(225,6,0,.55); }
  .chip.orphan { color:var(--amber); border:1px solid rgba(245,166,35,.5); }
  .empty { padding:14px 16px; color:var(--dimmer); }
  /* ── DECK view: the vertical spine ── */
  .spine { position:relative; padding-left:34px; }
  .spine::before { content:""; position:absolute; left:15px; top:6px; bottom:6px;
    width:2px; background:linear-gradient(180deg, var(--red) 0%, rgba(225,6,0,.15) 100%); }
  .block { position:relative; background:var(--panel); border:1px solid var(--line);
    border-radius:10px; padding:12px 16px; margin-bottom:18px; }
  .block::before { content:""; position:absolute; left:-25px; top:18px;
    width:12px; height:12px; border-radius:50%; background:var(--bg);
    border:2px solid var(--red); box-shadow:0 0 8px rgba(225,6,0,.6); }
  .block .seq { display:block; font-size:.66rem; color:var(--red-soft);
    letter-spacing:.12em; margin-bottom:4px; }
  .block .head { display:flex; gap:10px; flex-wrap:wrap; align-items:center;
    margin-bottom:6px; }
  .block .type { font-weight:700; color:var(--txt); }
  .block .ts { color:var(--dimmer); font-size:.72rem; }
  .block .hashes { display:flex; gap:14px; flex-wrap:wrap; font-size:.7rem;
    color:var(--dimmer); margin-top:6px; }
  .block .hashes b { color:var(--red-soft); font-weight:700; }
  .sealchip { display:none; }
  body.view-vault .block .head .sealchip {
    display:inline-flex; align-items:center; justify-content:center;
    width:30px; height:30px; border-radius:50%; flex-shrink:0;
    border:2px solid var(--amber); color:var(--amber);
    font-weight:800; font-size:.8rem; margin-right:6px; }
  .block details { margin-top:8px; }
  .block summary { cursor:pointer; color:var(--dimmer); font-size:.72rem; }
  .block pre { margin-top:6px; font-size:.7rem; color:var(--dim);
    background:#05060a; border:1px solid var(--line); border-radius:8px;
    padding:10px; overflow-x:auto; white-space:pre-wrap; word-break:break-all; }
  /* ── VAULT view: sealed envelopes ── */
  body.view-vault .spine { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr));
    gap:16px; padding-left:0; }
  body.view-vault .spine::before { display:none; }
  body.view-vault .block { padding:18px; border-radius:14px;
    border:1px solid rgba(245,166,35,.35);
    background:linear-gradient(160deg, var(--panel) 60%, rgba(245,166,35,.05)); }
  body.view-vault .block::before { display:none; }
  body.view-vault .block .seq { position:static; text-align:left; display:block;
    color:var(--amber); margin-bottom:8px; font-size:.7rem; letter-spacing:.14em; }
  body.view-vault .block .sealchip { display:inline-block; width:34px; height:34px;
    border-radius:50%; border:2px solid var(--amber); color:var(--amber);
    text-align:center; line-height:30px; font-weight:800; margin-left:10px; }
  body.view-vault .block details[open] summary { color:var(--amber); }
  /* ── TAPE view: horizontal ticker readout ── */
  body.view-tape .spine { display:flex; gap:10px; overflow-x:auto;
    padding:10px 4px 18px; align-items:stretch; }
  body.view-tape .spine::before { display:none; }
  body.view-tape .block { min-width:330px; max-width:330px; flex-shrink:0;
    margin-bottom:0; border-radius:6px; }
  body.view-tape .block::before { display:none; }
  body.view-tape .block .seq { position:static; text-align:left; display:block;
    color:var(--red-soft); margin-bottom:6px; }
  body.view-tape .block pre { max-height:110px; overflow:hidden; }
  /* ── Journal activity heatmap ── */
  .hm-top { display:flex; align-items:center; justify-content:space-between;
    flex-wrap:wrap; gap:10px; margin-bottom:14px; }
  .hm-total { font-size:.78rem; color:var(--dim); }
  .hm-modes { display:flex; gap:4px; }
  .hm-mode { font-family:var(--mono); font-size:.62rem; letter-spacing:.12em;
    padding:5px 12px; border-radius:7px; cursor:pointer;
    background:transparent; color:var(--dimmer); border:1px solid var(--line); }
  .hm-mode.on { color:var(--txt); border-color:var(--red-soft);
    background:rgba(225,6,0,.08); }
  .hm-scroll { overflow-x:auto; padding-bottom:4px; }
  .hm-wrap { display:flex; gap:8px; width:100%; }
  .hm-days { display:grid; grid-template-rows:repeat(7,22px); gap:3px;
    font-size:.58rem; color:var(--dimmer); flex-shrink:0; }
  .hm-days span { line-height:22px; }
  /* Fixed 22px cells: square like the flight-deck instrument language,
    and 53 of them fill a desktop panel without stretching into slivers. */
  .hm-grid { display:grid; grid-auto-flow:column;
    grid-template-rows:repeat(7,22px);
    grid-template-columns:repeat(53,22px); gap:3px; }
  .hm-grid.hm-weekly { grid-template-rows:repeat(1,22px); }
  .hm-cell { height:22px; border-radius:4px;
    background:rgba(255,255,255,.06); }
  .hm-cell.future { opacity:.35; }
  .hm-cell.l1 { background:rgba(225,6,0,.22); }
  .hm-cell.l2 { background:rgba(225,6,0,.42); }
  .hm-cell.l3 { background:rgba(225,6,0,.65); }
  .hm-cell.l4 { background:#e10600; box-shadow:0 0 6px rgba(225,6,0,.4); }
  .hm-months { position:relative; height:14px; margin-top:6px;
    font-size:.58rem; color:var(--dimmer); }
  .hm-months span { position:absolute; top:0; white-space:nowrap; }
  .hm-tip { position:absolute; display:none; pointer-events:none;
    background:#161a22; border:1px solid var(--line2); border-radius:8px;
    padding:7px 11px; font-size:.72rem; color:var(--txt); z-index:10;
    white-space:nowrap; box-shadow:0 6px 18px rgba(0,0,0,.5); }
  .hm-tip b { color:var(--red-soft); }
  .hm-legend { display:flex; align-items:center; gap:4px;
    justify-content:flex-end; margin-top:8px; font-size:.6rem;
    color:var(--dimmer); }
  .hm-legend .hm-cell { display:inline-block; width:22px; }
  /* ── TRAFFIC view: the live radar ── */
  #traffic-view { display:none; }
  body.view-traffic #traffic-view { display:block; }
  body.view-traffic #chain-title,
  body.view-traffic .spine,
  body.view-traffic #recon-board { display:none; }
  #radar { width:100%; height:560px; display:block; }
  .t-footline { display:flex; gap:18px; flex-wrap:wrap; align-items:baseline;
    margin-top:10px; font-size:.72rem; color:var(--dim); }
  .t-footline b { color:var(--red-soft); }
  .t-footline .t-motto { margin-left:auto; color:var(--dimmer);
    font-size:.64rem; letter-spacing:.06em; }
  footer { margin-top:32px; color:var(--dimmer); font-size:.76rem;
    display:flex; gap:18px; flex-wrap:wrap; }
  footer a { color:var(--red-soft); text-decoration:none; }
</style>
</head>
<body class="view-deck">
<header>
  <h1><span class="cube"></span>NOIREBOX — FLIGHT DECK</h1>
  <span class="seal" id="seal">CHECKING…</span>
</header>

<div class="viewbtns">
  <button class="viewbtn on" data-v="deck" onclick="setView('deck')">DECK</button>
  <button class="viewbtn" data-v="vault" onclick="setView('vault')">VAULT</button>
  <button class="viewbtn" data-v="tape" onclick="setView('tape')">TAPE</button>
  <button class="viewbtn" data-v="traffic" onclick="setView('traffic')">TRAFFIC</button>
</div>

<div class="strip">
  <div class="card"><b id="c-events">—</b><span>sealed events</span></div>
  <div class="card"><b id="c-head">—</b><span>chain head</span></div>
  <div class="card"><b id="c-last">—</b><span>last event (UTC)</span></div>
  <div class="card"><b id="c-gaps">—</b><span>unpaired intents</span></div>
</div>

<h2>Journal activity — sealed events per day</h2>
<div class="panelbox" style="position:relative; padding:16px" id="heatwrap">
  <div class="hm-top">
    <span class="hm-total" id="hm-total">—</span>
    <div class="hm-modes">
      <button class="hm-mode on" data-m="daily" onclick="setHmMode('daily')">DAILY</button>
      <button class="hm-mode" data-m="weekly" onclick="setHmMode('weekly')">WEEKLY</button>
      <button class="hm-mode" data-m="cumulative" onclick="setHmMode('cumulative')">CUMULATIVE</button>
    </div>
  </div>
  <div class="hm-scroll">
    <div class="hm-wrap">
      <div class="hm-days" id="hm-days">
        <span>Mon</span><span></span><span>Wed</span><span></span><span>Fri</span><span></span><span></span>
      </div>
      <div>
        <div class="hm-grid" id="hm-grid"></div>
        <div class="hm-months" id="hm-months"></div>
      </div>
    </div>
  </div>
  <div class="hm-legend">less
    <span class="hm-cell"></span><span class="hm-cell l1"></span><span class="hm-cell l2"></span><span class="hm-cell l3"></span><span class="hm-cell l4"></span>
  more</div>
  <div class="hm-tip" id="hm-tip"></div>
</div>

<h2 id="chain-title">The chain — every link visible</h2>

<div id="traffic-view">
  <div class="panelbox" style="padding:16px">
    <canvas id="radar"></canvas>
    <div class="t-footline">
      <span>last sealed <b id="t-last">—</b></span>
      <span>rate <b id="t-rate">—</b></span>
      <span id="t-dropped" style="display:none"></span>
      <span class="t-motto">every beam is a real sealed event — nothing simulated</span>
    </div>
  </div>
</div>

<div class="spine" id="spine">
  <div class="empty">loading…</div>
</div>

<div class="board" id="recon-board" style="display:none">
  <div class="panelbox">
    <h3>Departures — policy_decision</h3>
    <table><thead><tr><th>decision id</th><th>state</th></tr></thead>
    <tbody id="dep-rows"><tr><td class="empty">—</td></tr></tbody></table>
  </div>
  <div class="panelbox">
    <h3>Arrivals — provider_response</h3>
    <table><thead><tr><th>decision id</th><th>state</th></tr></thead>
    <tbody id="arr-rows"><tr><td class="empty">—</td></tr></tbody></table>
  </div>
</div>

<h2>The witness — last RFC 3161 anchor</h2>
<div class="panelbox" style="padding:14px 16px" id="witness">loading…</div>

<footer>
  <span>read-only — this view never mutates the journal</span>
  <span>it renders; the exported dossier attests</span>
  <a href="/docs">API docs</a>
  <a href="/api/v1/export">export dossier</a>
  <a href="https://github.com/slabbdev/noirebox" target="_blank" rel="noopener">GitHub</a>
</footer>

<script>
// esc() must be safe in attribute context too (e.g. class="${esc(e.type)}"):
// quotes are escaped, so a sealed event can never break out of an attribute.
const esc = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
const short = h => h ? h.slice(0,10) + "…" : "—";

function setView(v) {
  document.body.className = "view-" + v;
  try { localStorage.setItem("fd-view", v); } catch (e) {}
  document.querySelectorAll(".viewbtn").forEach(b =>
    b.classList.toggle("on", b.dataset.v === v));
  // The radar only runs while it is on screen: a hidden canvas must not
  // burn a requestAnimationFrame loop and a 2 s poller in the background.
  if (v === "traffic") trafficStart(); else trafficStop();
}
(function () {
  let saved = "deck";
  try { saved = localStorage.getItem("fd-view") || "deck"; } catch (e) {}
  document.body.className = "view-" + saved;
  document.querySelectorAll(".viewbtn").forEach(b =>
    b.classList.toggle("on", b.dataset.v === saved));
})();

// ── Journal activity heatmap ──
// One cell = one day (one week in weekly mode). Only real sealed events are
// rendered: an empty grid says "nothing sealed", it never decorates.
let hmMode = "daily";
let activityData = [];
try { hmMode = localStorage.getItem("fd-hm") || "daily"; } catch (e) {}
document.querySelectorAll(".hm-mode").forEach(b =>
  b.classList.toggle("on", b.dataset.m === hmMode));

function setHmMode(m) {
  hmMode = m;
  try { localStorage.setItem("fd-hm", m); } catch (e) {}
  document.querySelectorAll(".hm-mode").forEach(b =>
    b.classList.toggle("on", b.dataset.m === m));
  renderHeatmap();
}

// Day math stays in UTC end to end: the journal timestamps are UTC
// (now_iso), so a local-timezone bucketing could shift days for the very
// sealer whose journal is being read.
const utcDay = d => d.toISOString().slice(0, 10);
const asUTC = day => new Date(day + "T00:00:00Z");
const fmtDay = day => asUTC(day).toLocaleDateString("en-US",
  { month: "long", day: "numeric", year: "numeric", timeZone: "UTC" });
const fmtMonth = day => asUTC(day).toLocaleDateString("en-US",
  { month: "short", timeZone: "UTC" });
const mondayOf = day => {
  const d = asUTC(day);
  d.setUTCDate(d.getUTCDate() - (d.getUTCDay() + 6) % 7);
  return utcDay(d);
};
const plural = (n, w) => n + " " + w + (n === 1 ? "" : "s");

// Intensity thresholds are the quartiles of the displayed series' nonzero
// values: a quiet journal and a busy one both get a readable scale, with no
// magic counts baked in. The last quartile IS the series maximum, so the
// busiest day always sits at the top of the scale.
function hmLevel(v, thresholds) {
  if (v <= 0) return 0;
  // `<=`, not `<`: with strict comparison a sparse journal (one nonzero
  // bucket, all quartiles equal to it) collapsed every active day to the
  // faintest red.
  return Math.min(4, thresholds.filter(t => t <= v).length + 1);
}

function renderHeatmap() {
  const grid = document.getElementById("hm-grid");
  const months = document.getElementById("hm-months");
  const daysCol = document.getElementById("hm-days");
  const total = document.getElementById("hm-total");
  // A mode switch re-renders the grid under a stationary cursor: no
  // mouseout fires, so the previous tooltip would linger over cells it no
  // longer describes. Hide it; the next mouseover reopens it.
  document.getElementById("hm-tip").style.display = "none";

  const WEEKS = 53;
  const byDay = new Map(activityData.map(a => [a.day, a]));
  const sumAll = activityData.reduce((s, a) => s + a.count, 0);
  total.textContent = sumAll ?
    plural(sumAll, "event") + " over " + plural(byDay.size, "active day") :
    "no events sealed yet";

  // Display window: the last 53 weeks ending today. Value maps are computed
  // over the journal's whole life, so weekly sums and the cumulative total
  // stay honest even for days older than the window.
  const today = utcDay(new Date());
  const winStartDate = asUTC(today);
  winStartDate.setUTCDate(winStartDate.getUTCDate() - 364);
  const winStart = mondayOf(utcDay(winStartDate));
  const axisStart = (activityData.length && activityData[0].day < winStart) ?
    activityData[0].day : winStart;

  const cum = new Map(), weekSum = new Map(), weekAnchors = new Map();
  let running = 0;
  for (let d = asUTC(axisStart); utcDay(d) <= today; d.setUTCDate(d.getUTCDate() + 1)) {
    const day = utcDay(d);
    const a = byDay.get(day);
    running += a ? a.count : 0;
    cum.set(day, running);
    if (a) {
      const wk = mondayOf(day);
      weekSum.set(wk, (weekSum.get(wk) || 0) + a.count);
      weekAnchors.set(wk, (weekAnchors.get(wk) || 0) + a.anchors);
    }
  }

  const cols = [];
  for (let c = 0; c < WEEKS; c++) {
    const col = [];
    for (let r = 0; r < 7; r++) {
      const d = asUTC(winStart);
      d.setUTCDate(d.getUTCDate() + c * 7 + r);
      col.push(utcDay(d));
    }
    cols.push(col);
  }

  const shown = hmMode === "weekly" ?
    cols.map(col => weekSum.get(col[0]) || 0) :
    cols.flat().filter(day => day <= today)
      .map(day => hmMode === "cumulative" ? (cum.get(day) || 0)
                                           : (byDay.get(day)?.count || 0));
  const nz = shown.filter(v => v > 0).sort((a, b) => a - b);
  const q = p => nz.length ? nz[Math.min(nz.length - 1, Math.floor(p * nz.length))] : 0;
  const thresholds = [q(.25), q(.5), q(.75), q(.9)];

  grid.classList.toggle("hm-weekly", hmMode === "weekly");
  daysCol.style.display = hmMode === "weekly" ? "none" : "";

  let html = "";
  for (let c = 0; c < WEEKS; c++) {
    if (hmMode === "weekly") {
      const wk = cols[c][0];
      if (wk > today) { html += '<span class="hm-cell future"></span>'; continue; }
      const v = weekSum.get(wk) || 0;
      html += `<span class="hm-cell l${hmLevel(v, thresholds)}" ` +
        `data-m="weekly" data-d="${wk}" data-v="${v}"></span>`;
    } else {
      for (const day of cols[c]) {
        if (day > today) { html += '<span class="hm-cell future"></span>'; continue; }
        const v = hmMode === "cumulative" ? (cum.get(day) || 0)
                                          : (byDay.get(day)?.count || 0);
        html += `<span class="hm-cell l${hmLevel(v, thresholds)}" data-m="${hmMode}" ` +
          `data-d="${day}" data-v="${v}" data-a="${byDay.get(day)?.anchors || 0}"></span>`;
      }
    }
  }
  grid.innerHTML = html;

  // Month labels ride on the rendered column pitch, not a hardcoded pixel
  // width: cells are fluid (53 tracks + 52 gaps of 3px), so the pitch is
  // measured off the grid the browser just laid out.
  const pitch = (grid.getBoundingClientRect().width + 3) / WEEKS;
  let mhtml = "", lastM = "";
  for (let c = 0; c < WEEKS; c++) {
    const m = fmtMonth(cols[c][0]);
    if (m !== lastM) {
      mhtml += `<span style="left:${c * pitch}px">${m}</span>`;
      lastM = m;
    }
  }
  months.innerHTML = mhtml;
}

// Tooltip is bound once (delegation survives re-renders) and only ever
// interpolates generated numbers and locale dates — no sealed string
// reaches innerHTML.
(function bindHeatTip() {
  const wrap = document.getElementById("heatwrap");
  const tip = document.getElementById("hm-tip");
  const grid = document.getElementById("hm-grid");
  grid.addEventListener("mouseover", e => {
    const cell = e.target.closest(".hm-cell");
    if (!cell || !cell.dataset.d) return;
    const m = cell.dataset.m, day = cell.dataset.d, v = +cell.dataset.v;
    let label;
    if (m === "weekly") {
      label = `<b>week of ${fmtDay(day)}</b><br>${plural(v, "event")}`;
    } else if (m === "cumulative") {
      label = `<b>${fmtDay(day)}</b><br>${plural(v, "event")} to date`;
    } else {
      const a = +cell.dataset.a;
      label = `<b>${fmtDay(day)}</b><br>${plural(v, "event")}` +
        (a ? " · " + plural(a, "anchor") : "");
    }
    tip.innerHTML = label;
    tip.style.display = "block";
    const r = cell.getBoundingClientRect(), wr = wrap.getBoundingClientRect();
    let left = r.left - wr.left + r.width / 2 - tip.offsetWidth / 2;
    left = Math.max(4, Math.min(left, wr.width - tip.offsetWidth - 4));
    tip.style.left = left + "px";
    // Above the cell by default — but "above" must clear the summary bar
    // (total + mode buttons), not just the panel edge: the weekly row sits
    // right under that bar, so overlap there flips the tooltip below.
    const bar = wrap.querySelector(".hm-top");
    const barBottom = bar ? bar.getBoundingClientRect().bottom - wr.top + 4 : 0;
    let top = r.top - wr.top - tip.offsetHeight - 8;
    if (top < barBottom) top = r.bottom - wr.top + 8;
    tip.style.top = top + "px";
  });
  grid.addEventListener("mouseout", e => {
    if (e.target.closest(".hm-cell")) tip.style.display = "none";
  });
})();

// ── TRAFFIC view: the live radar ──
// The journal as air traffic: one node per event type on the perimeter,
// one beam per real sealed event flowing into the chain head, an amber
// pulse when an anchor seals the whole past. Nothing is simulated — a
// quiet radar means a quiet journal. Overflow bursts are condensed, never
// invented: every event still updates its node count and the seq, and the
// shortfall is printed on screen.
const tr = {
  on: false, raf: 0, timer: 0, ctx: null,
  nodes: new Map(),   // type -> { count }
  order: [],          // node insertion order (angles derive from it)
  beams: [], pulses: [], queue: [],
  seq: 0, arrivals: [], dropped: 0, sweep: 0, tPrev: 0,
};

function trColor(type) {
  if (type === "anchor") return "#f5a623";
  if (type === "incident") return "#e10600";
  if (type === "policy_decision" || type === "provider_response") return "#3fb950";
  return "#ff8577";
}

function trNode(type) {
  if (!tr.nodes.has(type)) {
    tr.nodes.set(type, { count: 0 });
    tr.order.push(type);
  }
  return tr.nodes.get(type);
}

function trNodeAngle(type) {
  // Even spacing over the node set, starting at 12 o'clock; re-derived on
  // every draw (n is small) so late-joining types re-space cleanly.
  const i = tr.order.indexOf(type);
  return ((i + 0.5) / tr.order.length) * Math.PI * 2 - Math.PI / 2;
}

function trFootline() {
  while (tr.arrivals.length &&
         performance.now() - tr.arrivals[0] > 60000) tr.arrivals.shift();
  document.getElementById("t-rate").textContent =
    tr.arrivals.length + " events/min";
  const d = document.getElementById("t-dropped");
  if (tr.dropped > 0) {
    d.style.display = "";
    d.textContent = "+" + tr.dropped + " earlier beams condensed (all counted)";
  }
}

function trPush(e) {
  if (e.seq <= tr.seq) return;
  tr.seq = e.seq;
  trNode(e.type).count++;
  tr.arrivals.push(performance.now());
  document.getElementById("t-last").textContent =
    "seq " + e.seq + " — " + e.type + " — " + e.ts.slice(11, 19) + " UTC";
  if (e.type === "anchor") tr.pulses.push({ t0: performance.now() });
  if (tr.beams.length < 60) {
    tr.beams.push({ angle: trNodeAngle(e.type), type: e.type, t0: performance.now() });
  } else if (tr.queue.length < 1000) {
    tr.queue.push({ angle: trNodeAngle(e.type), type: e.type });
  } else {
    tr.dropped++;
  }
  trFootline();
}

async function trafficPoll() {
  if (!tr.on) return;
  // Drain until the tail is dry (a long outage can hold thousands of
  // events); 12 batches of 500 per poll caps the loop, the next tick
  // resumes from the same cursor — nothing is lost, only delayed.
  for (let guard = 0; guard < 12; guard++) {
    let batch;
    try {
      batch = await fetch("/api/v1/events?since_seq=" + tr.seq + "&limit=500")
        .then(r => r.json());
    } catch (err) {
      return;  // keep the cursor; next tick retries from the same seq
    }
    batch.forEach(trPush);
    if (batch.length < 500) return;
  }
}

async function trafficInit() {
  // Seed the node map from recent history WITHOUT animating it: the radar
  // opens on the true current state, then only new events fly.
  try {
    const v = await fetch("/api/v1/verify").then(r => r.json());
    tr.seq = v.nb_events;
    const seed = await fetch(
      "/api/v1/events?limit=500&offset=" + Math.max(0, v.nb_events - 500)
    ).then(r => r.json());
    seed.forEach(e => {
      trNode(e.type).count++;
      if (e.seq > tr.seq) tr.seq = e.seq;
    });
    const lastE = seed[seed.length - 1];
    if (lastE) {
      document.getElementById("t-last").textContent =
        "seq " + lastE.seq + " — " + lastE.type + " — " +
        lastE.ts.slice(11, 19) + " UTC";
    }
  } catch (err) {
    // API hiccup at open: the radar starts empty and the poller fills it.
  }
  trFootline();
  tr.timer = setInterval(trafficPoll, 2000);
  trafficPoll();
}

function trSize() {
  const c = document.getElementById("radar");
  const dpr = window.devicePixelRatio || 1;
  c.width = c.clientWidth * dpr;
  c.height = c.clientHeight * dpr;
  tr.ctx = c.getContext("2d");
  tr.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}
window.addEventListener("resize", () => { if (tr.on) trSize(); });

function trafficStart() {
  if (tr.on) return;
  tr.on = true;
  trSize();
  if (!tr.timer) trafficInit(); else trafficPoll();
  tr.tPrev = performance.now();
  tr.raf = requestAnimationFrame(trDraw);
}

function trafficStop() {
  tr.on = false;
  if (tr.raf) cancelAnimationFrame(tr.raf);
  tr.raf = 0;
  if (tr.timer) { clearInterval(tr.timer); tr.timer = 0; }
}

function trDraw(now) {
  if (!tr.on) return;
  const c = document.getElementById("radar");
  const dpr = window.devicePixelRatio || 1;
  // The saved view can restore TRAFFIC before layout: the canvas may still
  // be 0-wide. Resize lazily on change and skip the frame rather than draw
  // with a negative radius (which would throw and kill the loop).
  if (!tr.ctx || c.width !== Math.round(c.clientWidth * dpr)) trSize();
  const W = c.clientWidth, H = c.clientHeight;
  if (W < 10 || H < 10) {
    tr.raf = requestAnimationFrame(trDraw);
    return;
  }
  const ctx = tr.ctx;
  const cx = W / 2, cy = H / 2;
  const R = Math.min(W, H) / 2 - 56;
  const dt = Math.min(0.1, (now - tr.tPrev) / 1000);
  tr.tPrev = now;
  tr.sweep = (tr.sweep + dt * 0.9) % (Math.PI * 2);
  ctx.clearRect(0, 0, W, H);

  // rings + cross
  ctx.lineWidth = 1;
  ctx.strokeStyle = "rgba(255,255,255,.06)";
  for (const f of [1, 2 / 3, 1 / 3]) {
    ctx.beginPath(); ctx.arc(cx, cy, R * f, 0, Math.PI * 2); ctx.stroke();
  }
  ctx.beginPath();
  ctx.moveTo(cx - R, cy); ctx.lineTo(cx + R, cy);
  ctx.moveTo(cx, cy - R); ctx.lineTo(cx, cy + R);
  ctx.stroke();

  // sweep with fading trail
  for (let i = 0; i < 60; i++) {
    const a = tr.sweep - i * 0.022;
    ctx.strokeStyle = "rgba(225,6,0," + (0.22 * (1 - i / 60)).toFixed(3) + ")";
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + R * Math.cos(a), cy + R * Math.sin(a));
    ctx.stroke();
  }

  // nodes + labels
  ctx.font = "10px ui-monospace, Menlo, monospace";
  for (const type of tr.order) {
    const a = trNodeAngle(type);
    const x = cx + R * Math.cos(a), y = cy + R * Math.sin(a);
    const col = trColor(type);
    ctx.fillStyle = col;
    ctx.shadowColor = col; ctx.shadowBlur = 8;
    ctx.beginPath(); ctx.arc(x, y, 4, 0, Math.PI * 2); ctx.fill();
    ctx.shadowBlur = 0;
    const lx = cx + (R + 16) * Math.cos(a);
    const ly = cy + (R + 16) * Math.sin(a);
    ctx.textAlign = Math.cos(a) > 0.3 ? "left"
      : Math.cos(a) < -0.3 ? "right" : "center";
    ctx.textBaseline = Math.sin(a) > 0.3 ? "top"
      : Math.sin(a) < -0.3 ? "bottom" : "middle";
    ctx.fillStyle = "rgba(154,164,178,.9)";
    const name = type.length > 18 ? type.slice(0, 17) + "…" : type;
    ctx.fillText(name + " · " + tr.nodes.get(type).count, lx, ly);
  }

  // queue drain: a burst replays fast-forward, at most 3 beams per frame
  let spawn = 3;
  while (spawn-- > 0 && tr.queue.length && tr.beams.length < 60) {
    const q = tr.queue.shift();
    tr.beams.push({ angle: q.angle, type: q.type, t0: now });
  }

  // beams: rim → chain head, trail fading after arrival
  for (let i = tr.beams.length - 1; i >= 0; i--) {
    const b = tr.beams[i];
    const t = (now - b.t0) / 900;
    if (t >= 1) { tr.beams.splice(i, 1); continue; }
    const ease = 1 - (1 - t) * (1 - t);
    const headR = R * (1 - ease);
    const col = trColor(b.type);
    ctx.globalAlpha = t < 0.6 ? 0.75 : 0.75 * (1 - (t - 0.6) / 0.4);
    ctx.strokeStyle = col;
    ctx.beginPath();
    ctx.moveTo(cx + R * Math.cos(b.angle), cy + R * Math.sin(b.angle));
    ctx.lineTo(cx + headR * Math.cos(b.angle), cy + headR * Math.sin(b.angle));
    ctx.stroke();
    ctx.fillStyle = col;
    ctx.beginPath();
    ctx.arc(cx + headR * Math.cos(b.angle), cy + headR * Math.sin(b.angle),
            2.5, 0, Math.PI * 2);
    ctx.fill();
    ctx.globalAlpha = 1;
  }

  // anchor pulses: the whole past locking, amber to the rim
  for (let i = tr.pulses.length - 1; i >= 0; i--) {
    const p = tr.pulses[i];
    const t = (now - p.t0) / 1400;
    if (t >= 1) { tr.pulses.splice(i, 1); continue; }
    ctx.globalAlpha = 0.55 * (1 - t);
    ctx.strokeStyle = "#f5a623";
    ctx.lineWidth = 2;
    ctx.beginPath(); ctx.arc(cx, cy, R * t, 0, Math.PI * 2); ctx.stroke();
    ctx.lineWidth = 1;
    ctx.globalAlpha = 1;
  }

  // core: the chain head, live
  ctx.fillStyle = "rgba(225,6,0,.12)";
  ctx.beginPath(); ctx.arc(cx, cy, 42, 0, Math.PI * 2); ctx.fill();
  ctx.strokeStyle = "rgba(225,6,0,.6)";
  ctx.beginPath(); ctx.arc(cx, cy, 42, 0, Math.PI * 2); ctx.stroke();
  ctx.fillStyle = "#e8ecf1";
  ctx.font = "700 24px ui-monospace, Menlo, monospace";
  ctx.textAlign = "center"; ctx.textBaseline = "middle";
  ctx.fillText(String(tr.seq), cx, cy - 6);
  ctx.fillStyle = "rgba(97,107,122,1)";
  ctx.font = "9px ui-monospace, Menlo, monospace";
  ctx.fillText("CHAIN HEAD SEQ", cx, cy + 14);

  tr.raf = requestAnimationFrame(trDraw);
}

// Boot the radar if the saved view restored TRAFFIC: the restore IIFE runs
// before the `tr` state above exists, so the start must wait until the
// whole script — state included — has been evaluated.
if (document.body.className === "view-traffic") trafficStart();

async function refresh() {
  try {
    const verify = await fetch("/api/v1/verify").then(r => r.json());
    // à l'échelle : fetcher la FIN du journal (les événements les plus récents),
    // pas le début — un dashboard qui rate les derniers événements est un bug.
    const offset = Math.max(0, verify.nb_events - 1000);
    const events = await fetch(`/api/v1/events?limit=1000&offset=${offset}`)
      .then(r => r.json());
    // Heatmap: keep the last known day-buckets if the aggregate endpoint
    // hiccups — a transient fetch failure must not blank the whole panel.
    activityData = await fetch("/api/v1/activity")
      .then(r => r.json()).catch(() => activityData);
    renderHeatmap();

    const seal = document.getElementById("seal");
    if (verify.valid) {
      seal.textContent = "✓ CHAIN INTACT";
      seal.className = "seal ok";
    } else {
      seal.textContent = "✗ TAMPERING — " + (verify.first_error?.reason || "invalid");
      seal.className = "seal bad";
    }

    document.getElementById("c-events").textContent = events.length;
    document.getElementById("c-head").textContent =
      short(events.length ? events[events.length-1].event_hash : null);
    document.getElementById("c-last").textContent =
      events.length ? events[events.length-1].ts.slice(0,19) : "—";

    // ── the chain, newest first ──
    const spine = document.getElementById("spine");
    spine.innerHTML = events.slice().reverse().map(e => {
      const payload = JSON.stringify(e.payload, null, 2);
      return `<div class="block">` +
        `<span class="seq">SEQ ${e.seq}</span>` +
        `<div class="head"><span class="sealchip">✓</span>` +
        `<span class="type ${esc(e.type)}">${esc(e.type)}</span>` +
        `<span class="ts">${esc(e.ts.slice(0,19))} UTC</span></div>` +
        `<div class="hashes"><span>prev <b>${short(e.prev_hash)}</b></span>` +
        `<span>→ event <b>${short(e.event_hash)}</b></span>` +
        `<span>sig ${short(e.signature)}</span></div>` +
        `<details><summary>payload</summary><pre>${esc(payload)}</pre></details>` +
        `</div>`;
    }).join("") || '<div class="empty">journal is empty — seal the first event</div>';

    // ── departures / arrivals: pair the two-event pattern ──
    const decisions = {}, outcomes = {};
    for (const e of events) {
      const k = e.payload && (e.payload.decision_id || e.payload.payment_intent_id);
      if (!k) continue;
      if (e.type === "policy_decision") decisions[k] = e;
      if (e.type === "provider_response") outcomes[k] = e;
    }
    const hasPayout = Object.keys(decisions).length || Object.keys(outcomes).length;
    document.getElementById("recon-board").style.display = hasPayout ? "" : "none";
    document.getElementById("c-gaps").textContent = hasPayout ?
      Object.keys(decisions).filter(k => !(k in outcomes)).length +
      Object.keys(outcomes).filter(k => !(k in decisions)).length : "—";

    const depRows = [], arrRows = [];
    for (const k of new Set([...Object.keys(decisions), ...Object.keys(outcomes)])) {
      const inD = k in decisions, inO = k in outcomes;
      const state = inD && inO ? '<span class="chip matched">MATCHED</span>'
        : inD ? '<span class="chip pending">PENDING</span>'
              : '<span class="chip orphan">ORPHAN</span>';
      if (inD) depRows.push(`<tr><td class="mono">${esc(k)}</td><td>${state}</td></tr>`);
      if (inO) arrRows.push(`<tr><td class="mono">${esc(k)}</td><td>${state}</td></tr>`);
    }
    for (const k of Object.keys(decisions)) {
      if (!(k in outcomes)) {
        // Arrivals board only: the departure already shows its own row as
        // PENDING — pushing here too would render the same id twice with
        // contradictory states.
        arrRows.push(`<tr><td class="mono">${esc(k)}</td>` +
          `<td><span class="chip unconfirmed">UNCONFIRMED</span></td></tr>`);
      }
    }
    document.getElementById("dep-rows").innerHTML =
      depRows.join("") || '<tr><td class="empty">no departures</td></tr>';
    document.getElementById("arr-rows").innerHTML =
      arrRows.join("") || '<tr><td class="empty">no arrivals</td></tr>';

    // ── the witness: last anchor ──
    const anchor = events.slice().reverse().find(e => e.type === "anchor");
    document.getElementById("witness").innerHTML = anchor ?
      `last anchor: seq ${anchor.seq} — ${esc(anchor.ts.slice(0,19))} UTC — ` +
      `head covered <b>${short(anchor.payload?.head_hash || anchor.payload?.hash)}</b>` :
      'no RFC 3161 anchor sealed yet — run <b>make tsa</b> + POST /api/v1/anchors';
  } catch (err) {
    document.getElementById("seal").textContent = "API UNREACHABLE";
    document.getElementById("seal").className = "seal bad";
  }
}

refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>
"""
