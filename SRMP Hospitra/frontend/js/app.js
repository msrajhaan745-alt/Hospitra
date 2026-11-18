// Application bootstrap: sign-in, shell, navigation, hash router, branch context and live updates.
import { api, setUnauthenticatedHandler } from "./core/api.js";
import { clear, h } from "./core/dom.js";
import { icon } from "./core/icons.js";
import { bus, can, loadReferenceData, setBranchContext, state } from "./core/state.js";
import { closeDrawer, errorState, loadingState, toast } from "./core/ui.js";
import { connectLive } from "./core/ws.js";
import { ensureSignedIn, isSigningOut, openChangePassword, signOut } from "./auth.js";
import { openIncidentDrawer } from "./details.js";
import assetsView from "./views/assets.js";
import catalogueView from "./views/catalogue.js";
import controlsView from "./views/controls.js";
import dashboardView from "./views/dashboard.js";
import incidentsView from "./views/incidents.js";
import monitoringView from "./views/monitoring.js";
import networkView from "./views/network.js";
import reportsView from "./views/reports.js";
import risksView from "./views/risks.js";
import usersView from "./views/users.js";

const ROUTES = [
  { path: "command", label: "Command Centre", icon: "dashboard", view: dashboardView },
  { path: "network", label: "Network Infrastructure", icon: "network", view: networkView },
  { path: "assets", label: "Asset Inventory", icon: "server", view: assetsView },
  { path: "catalogue", label: "Threats & Vulnerabilities", icon: "bug", view: catalogueView },
  { path: "monitoring", label: "Threat Monitoring", icon: "activity", view: monitoringView },
  { path: "risks", label: "Risk Register", icon: "list", view: risksView },
  { path: "controls", label: "Security Controls", icon: "shield", view: controlsView },
  { path: "incidents", label: "Incident Management", icon: "siren", view: incidentsView, counter: "incidents" },
  { path: "reports", label: "Reports & Audit", icon: "file", view: reportsView },
  { path: "users", label: "User Management", icon: "user", view: usersView, requires: "admin", section: "Administration" },
];

const viewRoot = document.getElementById("view");
const navRoot = document.getElementById("nav");
const titleEl = document.getElementById("page-title");
const subtitleEl = document.getElementById("page-subtitle");
const counters = {};
let controller = null;

const allowed = (r) => !r.requires || can(r.requires);

function buildNav() {
  clear(navRoot).append(h("div", { class: "nav-section" }, "Operations"));
  let index = 0;
  for (const r of ROUTES.filter(allowed)) {
    index += 1;
    if (r.section) navRoot.append(h("div", { class: "nav-section" }, r.section));
    const count = h("span", { class: "nav-count", "aria-label": "open incidents" });
    count.hidden = true;
    if (r.counter) counters[r.counter] = count;
    navRoot.append(h("a", { class: "nav-link", href: `#/${r.path}`, dataset: { path: r.path } },
      h("span", { class: "nav-index", "aria-hidden": "true" }, String(index).padStart(2, "0")),
      icon(r.icon), h("span", {}, r.label), r.counter ? count : null));
  }
}

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [path, query = ""] = raw.split("?");
  return { path: path || "command", params: new URLSearchParams(query) };
}

function route() {
  const { path, params } = parseHash();
  const def = ROUTES.find((r) => r.path === path);
  if (!def) { location.replace("#/command"); return; }
  if (!allowed(def)) {
    toast({ type: "warn", title: "Not available for your role", message: `${def.label} requires the ${def.requires} permission.` });
    location.replace("#/command");
    return;
  }
  closeDrawer();
  controller?.destroy?.();
  controller = null;
  for (const a of navRoot.querySelectorAll(".nav-link")) {
    if (a.dataset.path === path) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  titleEl.textContent = def.label;
  subtitleEl.textContent = def.view.subtitle || "";
  document.title = `${def.label} · Hospitra`;
  clear(viewRoot);
  try {
    controller = def.view.mount(viewRoot, params) || {};
  } catch (err) {
    console.error(err);
    viewRoot.append(errorState(err, route));
  }
  viewRoot.focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

async function refreshCounters() {
  try {
    const res = await api.get("/incidents", { active_only: true, limit: 1 });
    counters.incidents.textContent = String(res.total);
    counters.incidents.hidden = res.total === 0;
    counters.incidents.setAttribute("aria-label", `${res.total} open incidents`);
  } catch { /* counters are best-effort; views show their own errors */ }
}

function initBranchContext() {
  const select = document.getElementById("branch-context");
  select.replaceChildren(h("option", { value: "" }, "All branches"),
    ...state.branches.map((b) => h("option", { value: b.id }, b.name)));
  select.value = state.branchId;
  select.addEventListener("change", () => setBranchContext(select.value));
  bus.on("branch-context", (id) => {
    select.value = id;
    controller?.onBranch?.(id);
  });
}

function initialsOf(name) {
  return name.split(/\s+/).filter(Boolean).slice(0, 2).map((p) => p[0].toUpperCase()).join("") || "?";
}

function renderUserMenu() {
  const user = state.user;
  const host = document.getElementById("user-menu");
  document.getElementById("sidebar-user").textContent = `${user.username} · ${user.role}`;
  document.getElementById("run-scenario-link").hidden = !can("operate");

  const menu = h("div", { class: "menu", role: "menu" },
    h("div", { class: "menu-head" }, h("div", { style: { fontWeight: 700 } }, user.display_name),
      h("div", { class: "dim mono" }, user.username),
      h("div", { class: `role-badge-${user.role}`, style: { fontSize: "11px", fontWeight: 700, marginTop: "4px" } },
        `${user.role} · ${user.permissions.join(", ")}`)),
    h("button", { type: "button", role: "menuitem", onclick: () => { close(); openChangePassword(); } }, icon("lock"), "Change password"),
    h("button", { type: "button", role: "menuitem", onclick: () => { close(); signOut(); } }, icon("back"), "Sign out"));
  menu.hidden = true;
  const button = h("button", { class: "user-button", type: "button", "aria-haspopup": "menu", "aria-expanded": "false" },
    h("span", { class: "avatar", "aria-hidden": "true" }, initialsOf(user.display_name)),
    h("span", { class: "who" }, h("span", { class: "name" }, user.display_name),
      h("span", { class: `role role-badge-${user.role}` }, user.role)));
  const close = () => { menu.hidden = true; button.setAttribute("aria-expanded", "false"); };
  button.addEventListener("click", (ev) => {
    ev.stopPropagation();
    menu.hidden = !menu.hidden;
    button.setAttribute("aria-expanded", String(!menu.hidden));
    if (!menu.hidden) menu.querySelector("button")?.focus();
  });
  document.addEventListener("click", (ev) => { if (!host.contains(ev.target)) close(); });
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && !menu.hidden) { close(); button.focus(); } });
  clear(host).append(button, menu);
}

function initLiveStatus() {
  const el = document.getElementById("conn-status");
  const label = document.getElementById("conn-label");
  const text = { live: "Live updates: connected", connecting: "Live updates: connecting…", offline: "Live updates: offline — retrying" };
  let wasOffline = false;
  bus.on("ws-status", (s) => {
    el.dataset.state = s;
    label.textContent = text[s] || s;
    if (s === "offline") wasOffline = true;
    // Notifications missed while disconnected are not replayed: re-read from the REST API instead.
    if (s === "live" && wasOffline) {
      wasOffline = false;
      bus.emit("data-changed", { entity: "reconnect" });
    }
  });
}

function initLiveUpdates() {
  bus.on("live", (msg) => {
    if (msg.type === "simulation.completed") {
      const d = msg.data;
      const inc = d.incidents?.[0];
      toast({
        type: "sim",
        title: `Scenario ${d.scenario_id} completed (Branch ${d.branch_code})`,
        message: d.summary,
        action: inc ? { label: `Open ${inc.incident_number}`, onClick: () => openIncidentDrawer(inc.id) } : null,
      });
    } else if (msg.type === "data.reset") {
      toast({ type: "warn", title: "Data was reset", message: "All views now show the freshly seeded dataset." });
      loadReferenceData().catch(() => {});
    }
    refreshCounters();
    controller?.onLive?.(msg);
  });
  bus.on("data-changed", (payload) => {
    refreshCounters();
    controller?.onDataChanged?.(payload);
  });
}

let expiredHandled = false;
function onSessionExpired() {
  if (expiredHandled || isSigningOut()) return;
  expiredHandled = true;
  toast({ type: "warn", title: "Your session has ended", message: "Please sign in again.", timeout: 0 });
  setTimeout(() => location.reload(), 1500);
}

async function boot() {
  initLiveStatus();
  setUnauthenticatedHandler(onSessionExpired);
  bus.on("ws-unauthenticated", onSessionExpired);
  viewRoot.append(loadingState("Connecting to the Hospitra server…"));
  try {
    state.user = await ensureSignedIn();
    await loadReferenceData();
  } catch (err) {
    clear(viewRoot).append(errorState(err, () => location.reload()));
    return;
  }
  if (!state.branches.length) {
    clear(viewRoot).append(errorState(new Error("No branches found. Seed the data: python -m app.seed.cli seed"), () => location.reload()));
    return;
  }
  buildNav();
  renderUserMenu();
  initBranchContext();
  initLiveUpdates();
  connectLive();
  refreshCounters();
  window.addEventListener("hashchange", route);
  route();
}

boot();
