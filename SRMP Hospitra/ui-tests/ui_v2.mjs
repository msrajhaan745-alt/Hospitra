// V2 checks: first-run setup, sign-in/out, role-based UI, user management, controls and residual risk.
import { randomBytes } from "node:crypto";

import { ADMIN, BASE, apiSession, signIn, withBrowser } from "./cdp.mjs";

const results = [];
const check = (name, ok, detail = "") => { results.push(ok); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`); };
const drawer = `(document.querySelector('.drawer')?.innerText || '')`;
const notLoading = `!document.querySelector('table.data .skeleton')`;
const navPaths = `[...document.querySelectorAll('.nav-link')].map(a => a.dataset.path)`;

// ---- 1. First-run setup (only when the target database has no users yet) -----------------------
const status = await (await fetch(`${BASE}/api/v1/auth/status`)).json();
if (status.bootstrap_required) {
  await withBrowser(async (p) => {
    await p.goto(`${BASE}/#/command`, 800);
    await p.waitFor(`document.querySelector('.auth-card h1')?.textContent === 'First-run setup'`);
    await p.shot("v2-01-first-run");
    await p.eval(`(() => {
      const f = document.querySelector('.auth-card form'); const i = f.querySelectorAll('input');
      i[0].value = ${JSON.stringify(ADMIN.username)}; i[1].value = 'UI Test Administrator';
      i[2].value = ${JSON.stringify(ADMIN.password)}; i[3].value = ${JSON.stringify(ADMIN.password)}; f.requestSubmit();
    })()`);
    await p.waitFor(`document.querySelector('.nav-link') && document.getElementById('auth-root').hidden`, 10000);
    check("First-run setup creates the Admin and signs in", (await p.eval(`document.querySelector('.user-button').innerText`)).includes("Admin"));
  });
} else {
  console.log("(first-run setup already completed on this server — skipped)");
}

const admin = await apiSession(ADMIN);
// Fresh random passwords for the role accounts on every run (never hard-coded).
const roleUsers = {};
for (const role of ["Viewer", "Analyst"]) {
  const username = `ui-${role.toLowerCase()}`;
  const password = `pw-${randomBytes(9).toString("hex")}`;
  const users = (await admin.get("/users?limit=200")).items;
  const existing = users.find((u) => u.username === username);
  const r = existing
    ? await admin.patch(`/users/${existing.id}`, { password, active: true, role })
    : await admin.post("/users", { username, display_name: `UI ${role}`, role, password });
  if (r.status >= 300) throw new Error(`Could not prepare ${username}: ${JSON.stringify(r.body)}`);
  roleUsers[role] = { username, password };
}

// ---- 2. Sign-in errors, sign-out ------------------------------------------------------------------
await withBrowser(async (p) => {
  await p.goto(`${BASE}/#/command`, 800);
  await p.waitFor(`document.querySelector('.auth-card h1')?.textContent === 'Sign in'`);
  await p.eval(`(() => { const f = document.querySelector('.auth-card form'); const i = f.querySelectorAll('input');
    i[0].value = ${JSON.stringify(roleUsers.Viewer.username)}; i[1].value = 'definitely-wrong'; f.requestSubmit(); })()`);
  await p.waitFor(`!document.querySelector('.auth-card .form-error-banner').hidden`);
  check("Wrong password shows a generic error", (await p.eval(`document.querySelector('.auth-card .form-error-banner').textContent`)) === "Invalid username or password.");
  await p.shot("v2-02-login-error");
  check("API is closed without a session", (await fetch(`${BASE}/api/v1/assets`)).status === 401);

  // ---- 3. Viewer: read-only UI ----
  await signIn(p, roleUsers.Viewer);
  const nav = await p.eval(navPaths);
  check("Viewer has no User Management nav", !nav.includes("users") && nav.includes("controls"));
  check("Viewer has no Run scenario button", await p.eval(`document.getElementById('run-scenario-link').hidden`));
  await p.eval(`location.hash = '#/users'`);
  await p.sleep(800);
  check("Viewer is redirected away from #/users", (await p.eval(`location.hash`)) === "#/command");
  await p.eval(`location.hash = '#/monitoring'`);
  await p.waitFor(`document.querySelectorAll('.scenario').length === 8`);
  check("Viewer cannot trigger scenarios", await p.eval(`[...document.querySelectorAll('.sim-controls button')].find(b => b.textContent.includes('Trigger')).disabled`));
  check("Viewer sees no reset button", !(await p.eval(`[...document.querySelectorAll('button')].some(b => b.textContent.includes('Reset data'))`)));
  await p.eval(`location.hash = '#/assets'`);
  await p.waitFor(notLoading);
  check("Viewer has no New asset button", !(await p.eval(`[...document.querySelectorAll('button')].some(b => b.textContent.includes('New asset'))`)));
  await p.eval(`location.hash = '#/risks'`);
  await p.waitFor(`document.querySelectorAll('table.data tbody tr.clickable').length > 0`);
  await p.eval(`document.querySelector('table.data tbody tr.clickable').click()`);
  await p.waitFor(`${drawer}.includes('Residual Score =')`); // section headings are CSS-uppercased in innerText
  const vd = await p.eval(drawer);
  check("Viewer risk drawer is read-only (no edit, no link form)", vd.includes("Read-only for your role") && !vd.includes("Link a control"));
  await p.shot("v2-03-viewer-risk");
  await p.eval(`document.querySelector('.drawer [aria-label="Close panel"]').click()`);

  // Sign out through the user menu.
  await p.eval(`document.querySelector('.user-button').click()`);
  await p.eval(`[...document.querySelectorAll('.menu button')].find(b => b.textContent.includes('Sign out')).click()`);
  await p.waitFor(`document.querySelector('.auth-card h1')?.textContent === 'Sign in'`, 10000);
  check("Sign out returns to the sign-in screen", true);
  console.log("\nPROBLEMS (expected: 401s from the wrong password and unauthenticated probes):", p.problems.length ? "\n  " + p.problems.join("\n  ") : "none");
});

// ---- 4. Analyst: operates, cannot administer ---------------------------------------------------
await withBrowser(async (p) => {
  await signIn(p, roleUsers.Analyst, "#/monitoring");
  const nav = await p.eval(navPaths);
  check("Analyst has no User Management nav", !nav.includes("users"));
  await p.waitFor(`document.querySelectorAll('.scenario').length === 8`);
  check("Analyst can trigger but has no reset", !(await p.eval(`[...document.querySelectorAll('.sim-controls button')].find(b => b.textContent.includes('Trigger')).disabled`))
    && !(await p.eval(`[...document.querySelectorAll('button')].some(b => b.textContent.includes('Reset data'))`)));
  await p.clickText(".scenario", "S3");
  await p.clickText(".sim-controls button", "Trigger scenario");
  await p.waitFor(`document.querySelector('.sim-status').dataset.state === 'done'`, 10000);
  const runs = await admin.get("/simulation/history?limit=1");
  check("Analyst-triggered run is attributed to the analyst", runs.items[0].triggered_by === roleUsers.Analyst.username, runs.items[0].triggered_by);
  console.log("PROBLEMS:", p.problems.length ? "\n  " + p.problems.join("\n  ") : "none");
});

// ---- 5. Admin: users, controls, residual -------------------------------------------------------
await withBrowser(async (p) => {
  await signIn(p, ADMIN, "#/users");
  await p.waitFor(`document.querySelectorAll('table.data tbody tr.clickable').length >= 3`);
  check("Admin sees the user list", (await p.eval(`document.querySelector('table.data').innerText`)).includes(roleUsers.Viewer.username));
  await p.shot("v2-04-users");

  await p.clickText("button", "New user");
  await p.waitFor(`document.querySelector('.modal') !== null`);
  await p.eval(`document.querySelector('.modal .btn-primary').click()`);
  await p.waitFor(`!document.querySelector('.modal .form-error-banner').hidden`);
  check("Invalid new-user form shows server validation", (await p.eval(`[...document.querySelectorAll('.modal .field-error')].filter(e => !e.hidden).length`)) >= 2);
  await p.eval(`document.querySelector('.modal [aria-label="Close dialog"]').click()`);

  // Link a control to a risk with no controls and watch residual change.
  await p.eval(`location.hash = '#/risks'`);
  await p.waitFor(notLoading);
  await p.eval(`(() => { const i = document.querySelector('.toolbar input[type=search]'); i.value = 'HSP-A-NET-001'; i.dispatchEvent(new Event('input')); })()`);
  await p.waitFor(`document.querySelector('.toolbar .count')?.textContent === '1 risk'`);
  await p.eval(`document.querySelector('table.data tbody tr.clickable').click()`);
  await p.waitFor(`${drawer}.includes('Link a control')`);
  const before = await p.eval(`document.querySelector('.drawer .meta').innerText`);
  await p.eval(`(() => {
    const card = [...document.querySelectorAll('.drawer .mini-card')].find(c => c.innerText.includes('Link a control'));
    const [ctrl, status, effect] = card.querySelectorAll('select');
    ctrl.value = [...ctrl.options].find(o => o.textContent.startsWith('C04')).value;
    status.value = 'Implemented'; effect.value = 'Substantial';
    [...card.querySelectorAll('button')].find(b => b.textContent.includes('Link control')).click();
  })()`);
  await p.waitFor(`${drawer}.includes('C04') && ${drawer}.includes('Applied')`);
  const rd = await p.eval(drawer);
  check("Linking an implemented control lowers residual risk", /Residual Score = 1 × 3 = 3/.test(rd), (rd.match(/Residual Score = [^\n]+/) || [])[0]);
  await p.shot("v2-05-residual");

  // Change it to Planned → residual returns to inherent.
  await p.eval(`(() => { const s = document.querySelector('.drawer select[aria-label="C04 implementation status"]'); s.value = 'Planned'; s.dispatchEvent(new Event('change')); })()`);
  await p.waitFor(`${drawer}.includes('Planned — not counted')`);
  check("Planned control does not reduce residual", (await p.eval(drawer)).includes("no reduction — no counted controls"), before.replace(/\s+/g, " "));
  await p.eval(`document.querySelector('.drawer [aria-label="Close panel"]').click()`);

  // Controls library + drawer + deactivate.
  await p.eval(`location.hash = '#/controls'`);
  await p.waitFor(`document.querySelector('.toolbar .count')?.textContent.endsWith('controls')`);
  check("Control library lists 12 seeded controls", (await p.eval(`document.querySelector('.toolbar .count').textContent`)).startsWith("12"));
  await p.shot("v2-06-controls");
  await p.eval(`[...document.querySelectorAll('table.data tbody tr.clickable')].find(r => r.innerText.includes('C05')).click()`);
  await p.waitFor(`${drawer}.includes('Linked risks')`);
  await p.clickText(".drawer-foot button", "Deactivate");
  await p.waitFor(`document.querySelector('.modal') !== null`);
  await p.eval(`document.querySelector('.modal .btn-primary').click()`);
  await p.waitFor(`${drawer}.includes('Inactive')`);
  const risk = (await admin.get("/risks?search=HSP-A-DMZ-001")).items.find((r) => r.threat.code === "T5");
  check("Deactivating C05 restores residual = inherent on its risks", risk.residual_score === risk.risk_score, `${risk.reference}: ${risk.risk_score} → ${risk.residual_score}`);
  await p.clickText(".drawer-foot button", "Activate");
  await p.waitFor(`document.querySelector('.modal') !== null`);
  await p.eval(`document.querySelector('.modal .btn-primary').click()`);
  await p.waitFor(`${drawer}.includes('Deactivate')`);
  await p.eval(`document.querySelector('.drawer [aria-label="Close panel"]').click()`);

  // Dashboard residual toggle.
  await p.eval(`location.hash = '#/command'`);
  await p.waitFor(`[...document.querySelectorAll('.branch-switch button')].some(b => b.textContent === 'Residual')`);
  await p.eval(`[...document.querySelectorAll('.branch-switch button')].find(b => b.textContent === 'Residual').click()`);
  await p.sleep(500);
  check("Dashboard residual toggle switches the chart", await p.eval(`[...document.querySelectorAll('.branch-switch button')].find(b => b.textContent === 'Residual').getAttribute('aria-pressed') === 'true'`));
  await p.shot("v2-07-dashboard-residual");

  // Audit shows user identities and V2 actions.
  const audit = await admin.get("/audit?limit=100");
  const actions = new Set(audit.items.map((a) => a.action));
  check("Audit records sign-ins, control links and control changes",
    ["auth.login", "risk.control_linked", "risk.control_updated", "control.updated"].every((a) => actions.has(a)));
  console.log("PROBLEMS:", p.problems.length ? "\n  " + p.problems.join("\n  ") : "none");
});

console.log(`\n${results.filter(Boolean).length}/${results.length} V2 checks passed`);
