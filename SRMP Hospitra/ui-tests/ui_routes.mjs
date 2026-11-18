import { signIn, withBrowser } from "./cdp.mjs";

const ROUTES = ["command", "network", "assets", "catalogue", "monitoring", "risks", "controls", "incidents", "reports", "users"];

await withBrowser(async (p) => {
  await signIn(p);
  for (const r of ROUTES) {
    await p.eval(`location.hash = "#/${r}"`);
    await p.sleep(1800);
    const info = await p.eval(`({ title: document.getElementById('page-title').textContent,
      current: document.querySelector('.nav-link[aria-current=page]')?.dataset.path,
      rows: document.querySelectorAll('table.data tbody tr').length,
      states: [...document.querySelectorAll('.state h3')].map(e => e.textContent),
      canvases: document.querySelectorAll('canvas').length,
      svg: document.querySelectorAll('.topo-asset').length,
      conn: document.getElementById('conn-status').dataset.state })`);
    console.log(r, JSON.stringify(info));
    console.log("  shot:", await p.shot(`route-${r}`));
  }
  console.log("PROBLEMS:", p.problems.length ? "\n  " + p.problems.join("\n  ") : "none");
});
