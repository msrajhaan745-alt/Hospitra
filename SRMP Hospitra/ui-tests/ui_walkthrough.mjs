// End-to-end UI walkthrough (spec §19) + form/filter/export checks, verified against the API.
import { ADMIN, apiSession, signIn, withBrowser } from "./cdp.mjs";

const results = [];
const check = (name, ok, detail = "") => { results.push({ name, ok, detail }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`); };
const session = await apiSession(ADMIN);
const apiGet = (p) => session.get(p);
const drawerText = `(document.querySelector('.drawer')?.innerText || '')`;

await withBrowser(async (p) => {
  await signIn(p);
  await p.waitFor(`document.querySelectorAll('.kpi').length === 5`);

  // Step 1 — Command Centre
  const openBefore = await p.eval(`+document.querySelectorAll('.kpi .kpi-value')[1].textContent`);
  const apiOpen = (await apiGet("/incidents?active_only=true&limit=1")).total;
  check("Dashboard open-incident KPI matches API", openBefore === apiOpen, `${openBefore} vs ${apiOpen}`);
  check("Dashboard shows 3 branch cards", (await p.eval(`document.querySelectorAll('.branch-card').length`)) === 3);
  check("Dashboard renders 4 charts", (await p.eval(`document.querySelectorAll('canvas').length`)) === 4);

  // Step 2 — Network Infrastructure, Branch A
  await p.eval(`location.hash = '#/network?branch=A'`);
  await p.waitFor(`document.querySelectorAll('.topo-asset').length === 16`);
  check("Topology: 8 zones and 16 assets for Branch A", (await p.eval(`document.querySelectorAll('.topo-zone').length`)) === 8);
  await p.clickText(".branch-switch button", "Branch C");
  await p.waitFor(`document.querySelector('.topo-asset')?.getAttribute('aria-label').includes('HSP-C-')`);
  check("Branch switch renders Branch C assets", true);
  await p.clickText(".branch-switch button", "Branch A");
  await p.waitFor(`document.querySelector('.topo-asset')?.getAttribute('aria-label').includes('HSP-A-')`);
  await p.click(".topo-zone:nth-of-type(6)"); // zones are drawn after the link/infra groups
  await p.sleep(300);
  const zoneSide = await p.eval(`document.querySelector('.topo-layout .stack').innerText`);
  check("Selecting a zone shows its details", /VLAN \d+ ·/.test(zoneSide), zoneSide.split("\n").find((l) => l.startsWith("VLAN")));
  const assetLabel = await p.eval(`[...document.querySelectorAll('.topo-asset')].find(a => a.getAttribute('aria-label').includes('HSP-A-MED-001')).getAttribute('aria-label')`);
  await p.eval(`[...document.querySelectorAll('.topo-asset')].find(a => a.getAttribute('aria-label').includes('HSP-A-MED-001')).dispatchEvent(new MouseEvent('click', {bubbles:true}))`);
  await p.waitFor(`${drawerText}.includes('HSP-A-MED-001') && ${drawerText}.includes('10.20.50.51')`);
  const ad = await p.eval(drawerText);
  check("Topology node opens the correct asset detail", ad.includes("Biomedical Engineering") && ad.includes("C 3 · I 5 · A 5"), assetLabel);
  check("Selected asset is highlighted", await p.eval(`!!document.querySelector('.topo-asset.is-selected')`));
  await p.shot("walk-02-asset-drawer");
  await p.eval(`document.querySelector('.drawer [aria-label="Close panel"]').click()`);

  // Step 3/4 — trigger S1 on Branch A
  await p.eval(`location.hash = '#/monitoring'`);
  await p.waitFor(`document.querySelectorAll('.scenario').length === 8`);
  await p.clickText(".scenario", "S1");
  await p.eval(`(() => { const s = document.querySelector('.sim-controls select'); s.value = 'A'; s.dispatchEvent(new Event('change')); })()`);
  const eventsBefore = (await apiGet("/events?limit=1")).total;
  await p.clickText(".sim-controls button", "Trigger scenario");
  await p.waitFor(`document.querySelector('.sim-status').dataset.state === 'done'`, 10000);
  const simText = await p.eval(`document.querySelector('.sim-status').innerText`);
  check("Trigger reports completion with an incident", simText.includes("1 incident(s) opened"), simText.slice(0, 110));
  const eventsAfter = (await apiGet("/events?limit=1")).total;
  check("Event persisted in the database", eventsAfter === eventsBefore + 1, `${eventsBefore} → ${eventsAfter}`);
  await p.waitFor(`document.querySelector('.toast-sim') !== null`, 5000);
  check("WebSocket notification toast received", true, await p.eval(`document.querySelector('.toast-sim .t-title').textContent`));
  await p.waitFor(`document.querySelector('table.data tbody tr .badge-sim')?.textContent.includes('S1')`);
  const firstRow = await p.eval(`document.querySelector('#view section:nth-of-type(2) table.data tbody tr').innerText`);
  check("New S1 event at top of stream with scenario marker", firstRow.includes("S1") && firstRow.includes("HSP-A-GST-002") && firstRow.includes("HSP-A-APP-001"));
  await p.shot("walk-04-monitoring");

  // Step 5 — detection explanation
  await p.eval(`document.querySelectorAll('.sim-status .link-btn')[0].click()`);
  await p.waitFor(`${drawerText}.includes('Why the rule matched')`);
  const ev = await p.eval(drawerText);
  check("Event drawer explains the matched rule", ev.includes("R1") && ev.includes("Guest-to-restricted-zone") && ev.includes("internet-only"));
  check("Event drawer shows evidence + source/destination zones", ev.includes("source_zone") && ev.includes("Guest Wi-Fi (VLAN 60)") && ev.includes("Application / Data (VLAN 40)"));
  check("Event drawer shows scenario source", ev.includes("Source: scenario S1"));
  await p.shot("walk-05-event-drawer");

  // Step 6 — risk context
  await p.eval(`[...document.querySelectorAll('.drawer .mini-card')].find(b => b.innerText.includes('RSK-')).click()`);
  await p.waitFor(`${drawerText}.includes('Severity band')`);
  const rk = await p.eval(drawerText);
  check("Risk drawer shows calculation", /Impact = max\(C \d, I \d, A \d\) = \d/.test(rk) && /Score = \d × \d = \d+/.test(rk), rk.match(/Score = [^\n]+/)?.[0]);
  await p.shot("walk-06-risk");
  await p.eval(`document.querySelector('.drawer [aria-label="Back to previous panel"]').click()`);
  await p.waitFor(`${drawerText}.includes('Why the rule matched')`);

  // Step 7/8 — incident lifecycle
  await p.eval(`[...document.querySelectorAll('.drawer .mini-card')].find(b => b.innerText.includes('INC-')).click()`);
  await p.waitFor(`${drawerText}.includes('Move to Investigating')`);
  const incNumber = (await p.eval(drawerText)).match(/INC-\d{4}/)[0];
  check("Auto-created incident opens in Open state", (await p.eval(drawerText)).includes("Permitted next status: Investigating"), incNumber);
  for (const [next, note] of [["Investigating", "Investigation"], ["Contained", "Containment"]]) {
    await p.eval(`(() => { const ta = document.querySelector('.drawer textarea'); ta.value = '${note} note from UI walkthrough.'; const sel = document.querySelector('.drawer select'); sel.value = '${note}'; })()`);
    await p.clickText(".drawer button", "Add note");
    await p.waitFor(`${drawerText}.includes('${note} note from UI walkthrough.')`);
    await p.clickText(".drawer button", `Move to ${next}`);
    await p.waitFor(`document.querySelector('.modal') !== null`);
    const dialog = await p.eval(`document.querySelector('.modal').innerText`);
    if (next === "Contained") check("Containment confirmation explains the status change", dialog.includes("updates the incident status"));
    await p.eval(`document.querySelector('.modal .btn-primary').click()`);
    await p.waitFor(`document.querySelector('.drawer .stepper .current')?.innerText.includes('${next}')`);
  }
  await p.eval(`(() => { const i = document.querySelector('.drawer input[aria-label="Assigned operator label"]'); i.value = 'SOC Tier 1'; })()`);
  await p.clickText(".drawer button", "Save");
  await p.waitFor(`${drawerText}.includes('Assigned: SOC Tier 1')`);
  const incApi = (await apiGet(`/incidents?search=${incNumber}`)).items[0];
  const incDetail = await apiGet(`/incidents/${incApi.id}`);
  check("Incident status/notes/assignee persisted", incDetail.status === "Contained" && incDetail.notes.length === 2 && incDetail.assigned_to === "SOC Tier 1",
    `${incDetail.status}, ${incDetail.notes.length} notes, ${incDetail.assigned_to}`);
  await p.shot("walk-08-incident");
  await p.eval(`document.querySelector('.drawer [aria-label="Close panel"]').click()`);

  // Step 9 — audit history
  await p.eval(`location.hash = '#/reports'`);
  await p.waitFor(`document.querySelectorAll('table.data tbody tr').length > 5 && !document.querySelector('table.data .skeleton')`);
  const audit = await p.eval(`document.querySelector('table.data').innerText`);
  check("Audit log shows incident status changes", audit.includes(`${incNumber}: Investigating → Contained`) && audit.includes(`${incNumber}: Open → Investigating`));
  const auditApi = (await apiGet(`/audit?entity_id=${incApi.id}&limit=50`)).items.map((a) => a.action);
  check("Audit API has created/note/status/assign for incident", ["incident.created", "incident.note_added", "incident.status_changed", "incident.assigned"].every((x) => auditApi.includes(x)));

  // Step 10 — exports
  for (const label of ["Download CSV", "Download PDF"]) {
    await p.eval(`[...document.querySelectorAll('.export-card button')].find(b => b.textContent.includes('${label}')).click()`);
  }
  await p.waitFor(`[...document.querySelectorAll('.ec-result')].filter(e => e.textContent.startsWith('Saved')).length >= 2`, 10000);
  check("Export downloads verified", true, await p.eval(`[...document.querySelectorAll('.ec-result')].map(e => e.textContent).filter(Boolean).join(' | ')`));
  await p.shot("walk-10-reports");

  // Dashboard reflects the new incident (now Contained → still active)
  await p.eval(`location.hash = '#/command'`);
  await p.waitFor(`document.querySelectorAll('.kpi').length === 5`);
  const openAfter = await p.eval(`+document.querySelectorAll('.kpi .kpi-value')[1].textContent`);
  check("Dashboard KPI updated after new incident", openAfter === openBefore + 1, `${openBefore} → ${openAfter}`);

  // Forms — validation and server errors
  await p.eval(`location.hash = '#/assets'`);
  await p.waitFor(`document.querySelectorAll('table.data tbody tr.clickable').length === 25`);
  await p.clickText("button", "New asset");
  await p.waitFor(`document.querySelector('.modal') !== null`);
  await p.eval(`document.querySelector('.modal .btn-primary').click()`);
  await p.sleep(200);
  const errs = await p.eval(`[...document.querySelectorAll('.modal .field-error')].filter(e => !e.hidden).length`);
  check("Empty asset form shows field errors", errs >= 8, `${errs} field errors`);
  await p.eval(`(() => {
    const m = document.querySelector('.modal');
    const set = (lbl, v) => { const f = [...m.querySelectorAll('.field')].find(x => x.firstChild.textContent.startsWith(lbl)); const c = f.querySelector('input,select'); c.value = v; c.dispatchEvent(new Event('change')); };
    set('Asset tag', 'HSP-A-CLN-001'); set('Name', 'Dup test'); set('Asset type', 'Workstation'); set('Owner', 'QA');
    set('IP address', '10.20.30.77'); set('Criticality', 'High'); set('Data classification', 'Restricted');
    const zone = [...m.querySelectorAll('.field')].find(x => x.firstChild.textContent.startsWith('Security zone')).querySelector('select');
    zone.value = [...zone.options].find(o => o.textContent.includes('VLAN 30')).value; zone.dispatchEvent(new Event('change'));
    m.querySelectorAll('.rating').forEach(r => r.querySelectorAll('button')[2].click());
  })()`);
  await p.eval(`document.querySelector('.modal .btn-primary').click()`);
  await p.waitFor(`!document.querySelector('.modal .form-error-banner').hidden && document.querySelector('.modal .form-error-banner').textContent.includes('already in use')`);
  check("Duplicate tag rejected by server and shown", true, await p.eval(`document.querySelector('.modal .form-error-banner').textContent`));
  await p.eval(`(() => { const m = document.querySelector('.modal'); const f = [...m.querySelectorAll('.field')].find(x => x.firstChild.textContent.startsWith('Asset tag')).querySelector('input'); f.value = 'HSP-A-CLN-077'; const ip = [...m.querySelectorAll('.field')].find(x => x.firstChild.textContent.startsWith('IP address')).querySelector('input'); ip.value = '10.20.99.5'; })()`);
  await p.eval(`document.querySelector('.modal .btn-primary').click()`);
  await p.waitFor(`[...document.querySelectorAll('.modal .field-error')].some(e => !e.hidden && e.textContent.includes('10.20.30.0/24'))`);
  check("Out-of-subnet IP rejected by server and mapped to the IP field", true);
  await p.shot("walk-form-errors");
  await p.eval(`document.querySelector('.modal [aria-label="Close dialog"]').click()`);

  // Filters
  await p.eval(`(() => { const s = [...document.querySelectorAll('.toolbar select')].find(x => x.getAttribute('aria-label') === 'Filter by status'); s.value = 'Offline'; s.dispatchEvent(new Event('change')); })()`);
  await p.waitFor(`document.querySelector('.toolbar .count').textContent === '1 asset'`);
  check("Asset status filter returns exactly the offline asset", (await p.eval(`document.querySelector('table.data tbody').innerText`)).includes("HSP-B-ADM-002"));
  await p.eval(`location.hash = '#/risks?severity=Critical'`);
  await p.waitFor(`document.querySelectorAll('table.data tbody tr.clickable').length > 0`);
  // First .sev in each row is the inherent severity (V2 adds a residual severity column).
  const sevs = await p.eval(`[...document.querySelectorAll('table.data tbody tr')].map(r => r.querySelector('.sev')?.textContent)`);
  check("Risk severity deep-link filter", sevs.every((s) => s === "Critical"), sevs.join(","));

  console.log("\nPROBLEMS:", p.problems.length ? "\n  " + p.problems.join("\n  ") : "none");
  const failed = results.filter((r) => !r.ok).length;
  console.log(`\n${results.length - failed}/${results.length} checks passed`);
});
