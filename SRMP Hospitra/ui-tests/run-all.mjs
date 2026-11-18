// Runs every UI check against HOSPITRA_UI_BASE (default http://127.0.0.1:8000). Node.js ≥ 22, Chrome or Edge.
//
//   $env:HOSPITRA_UI_USER = "admin"; $env:HOSPITRA_UI_PASSWORD = "<an Admin password>"
//   node run-all.mjs
//
// If the server has no users yet, ui_v2.mjs completes first-run setup with these credentials.
// NOTE: the checks create incidents, risks, controls links, a threat and two test users
// (ui-viewer, ui-analyst), and this runner RESETS the data before and after (user
// accounts are kept). Point it at a throwaway database, not one you care about.
import { ADMIN, BASE, apiSession } from "./cdp.mjs";

if (!ADMIN.username || !ADMIN.password) {
  console.error("Set HOSPITRA_UI_USER and HOSPITRA_UI_PASSWORD (an Admin account) first.");
  process.exit(2);
}

async function reset(label) {
  const status = await (await fetch(`${BASE}/api/v1/auth/status`)).json();
  if (status.bootstrap_required) { console.log(`[reset ${label} skipped: first-run setup pending]`); return; }
  const admin = await apiSession(ADMIN);
  const r = await admin.post("/simulation/reset", { confirm: "RESET" });
  if (r.status !== 200) throw new Error(`Reset (${label}) failed: HTTP ${r.status}`);
  console.log(`[data reset: ${label}]`);
}

await reset("before");
for (const script of ["./ui_v2.mjs", "./ui_routes.mjs", "./ui_walkthrough.mjs", "./ui_more.mjs"]) {
  if (script === "./ui_routes.mjs") await reset("after first-run / V2 checks");
  console.log(`\n===== ${script} =====`);
  await import(script);
}
await reset("after");
