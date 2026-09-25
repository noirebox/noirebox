"""FLIGHT DECK — the NoireBox supervision view, styled as the instrument
panel of the box itself. Three switchable views, one journal:

- **DECK** (default): the chain as a vertical spine — every link visible,
  prev_hash → event_hash → signature on each block.
- **VAULT**: the same events as sealed envelopes — payload behind an
  unseal toggle, signature rendered as a wax seal.
- **TAPE**: the journal as a horizontal ticker-tape readout, like the
  film-to-paper playbacks of early flight recorders.

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
</div>

<div class="strip">
  <div class="card"><b id="c-events">—</b><span>sealed events</span></div>
  <div class="card"><b id="c-head">—</b><span>chain head</span></div>
  <div class="card"><b id="c-last">—</b><span>last event (UTC)</span></div>
  <div class="card"><b id="c-gaps">—</b><span>unpaired intents</span></div>
</div>

<h2>The chain — every link visible</h2>
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
}
(function () {
  let saved = "deck";
  try { saved = localStorage.getItem("fd-view") || "deck"; } catch (e) {}
  document.body.className = "view-" + saved;
  document.querySelectorAll(".viewbtn").forEach(b =>
    b.classList.toggle("on", b.dataset.v === saved));
})();

async function refresh() {
  try {
    const verify = await fetch("/api/v1/verify").then(r => r.json());
    // à l'échelle : fetcher la FIN du journal (les événements les plus récents),
    // pas le début — un dashboard qui rate les derniers événements est un bug.
    const offset = Math.max(0, verify.nb_events - 1000);
    const events = await fetch(`/api/v1/events?limit=1000&offset=${offset}`)
      .then(r => r.json());

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
