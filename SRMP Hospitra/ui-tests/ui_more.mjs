import { ADMIN, apiSession, signIn, withBrowser } from "./cdp.mjs";

const results = [];
const check = (name, ok, detail = "") => { results.push(ok); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`); };
const session = await apiSession(ADMIN);
const drawer = `(document.querySelector('.drawer')?.innerText || '')`;
const notLoading = `!document.querySelector('table.data .skeleton')`;

await withBrowser(async (p) => {
  await signIn(p);
  await p.waitFor(`document.querySelectorAll('.kpi').length === 5`);

  // Live update with no user interaction: trigger externally via the API.
  const before = await p.eval(`+document.querySelectorAll('.kpi .kpi-value')[2].textContent.replace(/,/g,'')`);
  await session.post("/simulation/trigger", { scenario_id: "S7", branch_code: "B" });
  await p.waitFor(`+document.querySelectorAll('.kpi .kpi-value')[2].textContent.replace(/,/g,'') === ${before + 6}`, 8000);
  check("Dashboard event KPI refreshes via WebSocket without reload", true, `${before} → ${before + 6}`);
  await p.waitFor(`document.querySelector('.branch-card[data-posture="Critical"]') !== null`);
  check("Branch B posture becomes Critical after S7 (Critical incident)", (await p.eval(`document.querySelector('.branch-card[data-posture="Critical"] .bc-name').textContent`)).includes("Branch B"));
  check("Toast offers to open the new incident", (await p.eval(`document.querySelector('.toast-sim')?.innerText || ''`)).includes("Open INC-"));
  await p.shot("more-01-dashboard-live");

  // Branch context selector
  await p.eval(`(() => { const s = document.getElementById('branch-context'); s.value = s.options[1].value; s.dispatchEvent(new Event('change')); })()`);
  await p.waitFor(`document.querySelector('.kpi .kpi-value')?.textContent === '16'`);
  check("Branch context scopes the dashboard to 16 assets", true);
  await p.eval(`location.hash = '#/assets'`);
  await p.waitFor(`document.querySelector('.toolbar .count')?.textContent === '16 assets'`);
  check("Branch context carries into Asset Inventory", true);
  await p.eval(`(() => { const s = document.getElementById('branch-context'); s.value = ''; s.dispatchEvent(new Event('change')); })()`);
  await p.waitFor(`document.querySelector('.toolbar .count')?.textContent === '48 assets'`);
  check("Clearing context restores all 48 assets", true);

  // Sorting
  await p.eval(`[...document.querySelectorAll('th.sortable')].find(t => t.textContent.startsWith('IP address')).click()`);
  await p.waitFor(notLoading);
  await p.sleep(400);
  const ips = await p.eval(`[...document.querySelectorAll('table.data tbody tr')].map(r => r.children[5].textContent)`);
  check("Sorting by IP column works", JSON.stringify(ips) === JSON.stringify([...ips].sort()), ips.slice(0, 3).join(", "));

  // Empty state
  await p.eval(`location.hash = '#/monitoring'`);
  await p.waitFor(`document.querySelectorAll('.scenario').length === 8`);
  await p.eval(`(() => { const i = document.querySelector('.toolbar input[type=search]'); i.value = 'zzz-no-such-thing'; i.dispatchEvent(new Event('input')); })()`);
  await p.waitFor(`[...document.querySelectorAll('.state h3')].some(h => h.textContent.includes('No events match'))`);
  check("Empty state shown for a search with no results", true);

  // Error state (bad deep link)
  await p.eval(`location.hash = '#/assets?id=does-not-exist'`);
  await p.waitFor(`${drawer}.includes('Could not load data')`);
  check("Missing record shows an error state with retry", (await p.eval(drawer)).includes("Asset 'does-not-exist' was not found"));
  await p.eval(`document.querySelector('.drawer [aria-label="Close panel"]').click()`);

  // Create a risk via the form
  await p.eval(`location.hash = '#/risks'`);
  await p.waitFor(notLoading);
  await p.clickText("button", "New risk");
  await p.waitFor(`document.querySelectorAll('.modal select').length >= 5`);
  await p.eval(`(() => {
    const m = document.querySelector('.modal');
    const sel = (lbl) => [...m.querySelectorAll('.field')].find(x => x.firstChild.textContent.startsWith(lbl)).querySelector('select');
    const a = sel('Asset'); a.value = [...a.options].find(o => o.textContent.startsWith('HSP-B-MED-001')).value; a.dispatchEvent(new Event('change'));
    const t = sel('Threat'); t.value = [...t.options].find(o => o.textContent.startsWith('T7')).value; t.dispatchEvent(new Event('change'));
    const v = sel('Vulnerability'); v.value = [...v.options].find(o => o.textContent.startsWith('V2')).value; v.dispatchEvent(new Event('change'));
    const tr = sel('Treatment'); tr.value = 'Mitigate'; tr.dispatchEvent(new Event('change'));
    const owner = [...m.querySelectorAll('.field')].find(x => x.firstChild.textContent.startsWith('Owner')).querySelector('input'); owner.value = 'Biomedical Engineering';
    const ratings = m.querySelectorAll('.rating'); [3, 2, 4, 4].forEach((n, i) => ratings[i].querySelectorAll('button')[n - 1].click());
  })()`);
  const pairing = await p.eval(`document.querySelector('.modal').innerText`);
  check("Risk form marks the documented T7/V2 pairing", pairing.includes("Rationale: Vendor VPN accounts"));
  await p.eval(`document.querySelector('.modal .btn-primary').click()`);
  await p.waitFor(`${drawer}.includes('Severity band')`);
  const rd = await p.eval(drawer);
  check("Created risk shows server calculation 3 × 4 = 12 (High)", rd.includes("Score = 3 × 4 = 12") && rd.includes("10–16 → High"));
  await p.eval(`document.querySelector('.drawer [aria-label="Close panel"]').click()`);

  // Create a proposed threat
  await p.eval(`location.hash = '#/catalogue'`);
  await p.waitFor(notLoading);
  await p.clickText("button", "New threat");
  await p.waitFor(`document.querySelector('.modal') !== null`);
  await p.eval(`(() => {
    const m = document.querySelector('.modal');
    const inp = (lbl) => [...m.querySelectorAll('.field')].find(x => x.firstChild.textContent.startsWith(lbl)).querySelector('input,textarea');
    inp('Code').value = 'T9'; inp('Name').value = 'Phishing of clinical staff'; inp('Category').value = 'Social engineering';
    inp('Description').value = 'Proposed scenario: credential phishing targeting clinical staff mailboxes.';
  })()`);
  await p.eval(`document.querySelector('.modal .btn-primary').click()`);
  await p.waitFor(`${drawer}.includes('Phishing of clinical staff')`);
  check("New threat created as Proposed with note", (await p.eval(drawer)).includes("not part of the initial case study"));
  await p.eval(`document.querySelector('.drawer [aria-label="Close panel"]').click()`);

  // Keyboard activation of topology node
  await p.eval(`location.hash = '#/network?branch=B'`);
  await p.waitFor(`document.querySelectorAll('.topo-asset').length === 16`);
  await p.eval(`(() => { const n = [...document.querySelectorAll('.topo-asset')].find(a => a.getAttribute('aria-label').includes('HSP-B-ADM-002')); n.focus(); n.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true})); })()`);
  await p.waitFor(`${drawer}.includes('HSP-B-ADM-002') && ${drawer}.includes('Offline')`);
  check("Keyboard Enter on a topology node opens that asset", true);
  await p.shot("more-02-network-b");

  console.log("\nPROBLEMS:", p.problems.length ? "\n  " + p.problems.join("\n  ") : "none");
  console.log(`\n${results.filter(Boolean).length}/${results.length} checks passed`);
});
