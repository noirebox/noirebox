/* NoireBox developer reference — copy buttons, scrollspy, mobile sidebar. Zero deps. */

// ── copy buttons ────────────────────────────────────
for (const btn of document.querySelectorAll(".copy-btn")) {
  btn.addEventListener("click", async () => {
    const target = btn.dataset.copy ? document.getElementById(btn.dataset.copy) : btn.closest("pre");
    if (!target) return;
    const text = target.textContent.trim();
    try { await navigator.clipboard.writeText(text); } catch { /* clipboard unavailable */ }
    const old = btn.textContent;
    btn.textContent = "✓";
    setTimeout(() => { btn.textContent = old; }, 900);
  });
}

// ── mobile sidebar ──────────────────────────────────
const sidebar = document.getElementById("sidebar");
const scrim = document.getElementById("scrim");
const menuBtn = document.getElementById("menu-btn");
function closeMenu() {
  sidebar.classList.remove("open");
  scrim.hidden = true;
}
menuBtn.addEventListener("click", () => {
  const open = sidebar.classList.toggle("open");
  scrim.hidden = !open;
});
scrim.addEventListener("click", closeMenu);
for (const link of sidebar.querySelectorAll(".toc a")) link.addEventListener("click", closeMenu);

// ── scrollspy ───────────────────────────────────────
const links = [...sidebar.querySelectorAll(".toc a")];
const byId = new Map(links.map((a) => [a.getAttribute("href").slice(1), a]));
const spy = new IntersectionObserver(
  (entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      links.forEach((a) => a.classList.remove("active"));
      const active = byId.get(entry.target.id);
      if (active) active.classList.add("active");
    }
  },
  { rootMargin: "-15% 0px -70% 0px" }
);
for (const section of document.querySelectorAll("main section[id]")) spy.observe(section);
