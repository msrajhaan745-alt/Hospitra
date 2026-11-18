// Reports & Audit — verified CSV/PDF exports, audit history and the controlled data reset.
import { describeAudit } from "../audit-format.js";
import { api } from "../core/api.js";
import { dateInput, selectInput } from "../core/controls.js";
import { clear, debounce, h } from "../core/dom.js";
import { fmtBytes, fmtDateTime, shortId, toIsoEndOfDay, toIsoStartOfDay } from "../core/format.js";
import { icon } from "../core/icons.js";
import { can } from "../core/state.js";
import { createPager, createTable } from "../core/table.js";
import { toast, toastError, withBusy } from "../core/ui.js";
import { openAssetDrawer, openControlDrawer, openEventDrawer, openIncidentDrawer, openRiskDrawer, openThreatDrawer, openVulnerabilityDrawer } from "../details.js";
import { resetData } from "../reset.js";

const EXPORTS = [
  { type: "CSV", title: "Asset inventory", desc: "All assets with zone, IP, owner, CIA ratings and status.", path: "/api/v1/exports/assets.csv" },
  { type: "CSV", title: "Risk register", desc: "Inherent and residual scores, severities and applied controls.", path: "/api/v1/exports/risks.csv" },
  { type: "CSV", title: "Security events", desc: "Security events with detection status and matched rules.", path: "/api/v1/exports/events.csv" },
  { type: "CSV", title: "Incidents", desc: "Incident lifecycle, assignment and resolution notes.", path: "/api/v1/exports/incidents.csv" },
  { type: "PDF", title: "Summary report", desc: "Formatted overview of posture, risks, detections and incidents.", path: "/api/v1/exports/summary.pdf" },
];

const ENTITY_LABELS = {
  asset: "Asset", threat: "Threat", vulnerability: "Vulnerability", risk: "Risk", security_event: "Security event",
  detection: "Detection", incident: "Incident", simulation_run: "Simulation run", system: "System",
  control: "Security control", user: "User",
};

function exportCard(def) {
  const result = h("div", { class: "ec-result", "aria-live": "polite" });
  const btn = h("button", { class: "btn btn-primary btn-sm", type: "button" }, icon("download"), `Download ${def.type}`);
  btn.addEventListener("click", () => withBusy(btn, async () => {
    try {
      const file = await api.download(def.path);
      result.textContent = `Saved ${file.filename} (${fmtBytes(file.size)})`;
      toast({ type: "success", title: `${def.title} exported`, message: `${file.filename} · ${fmtBytes(file.size)}` });
    } catch (err) {
      result.textContent = `Failed: ${err.message}`;
      toastError(err, "Export failed");
    }
  }));
  return h("div", { class: "export-card" }, h("span", { class: "ec-type" }, def.type), h("div", { class: "ec-title" }, def.title),
    h("div", { class: "ec-desc" }, def.desc), btn, result);
}

function openEntity(a) {
  const d = a.details || {};
  const map = { asset: openAssetDrawer, incident: openIncidentDrawer, security_event: openEventDrawer, risk: openRiskDrawer,
    threat: openThreatDrawer, vulnerability: openVulnerabilityDrawer, control: openControlDrawer };
  if (map[a.entity_type] && a.entity_id) return map[a.entity_type](a.entity_id);
  if (a.entity_type === "detection" && d.event_id) return openEventDrawer(d.event_id);
  return null;
}

export default {
  subtitle: "Verified CSV/PDF exports and the append-only audit history of important actions",
  mount(root) {
    let alive = true;
    const q = { entity_type: "", action: "", since: "", until: "", offset: 0 };
    const count = h("span", { class: "count" });
    const entitySel = selectInput({ options: [], allLabel: "All entity types", label: "Filter by entity type", onChange: (v) => set({ entity_type: v }) });
    const actionSel = selectInput({ options: [], allLabel: "All actions", label: "Filter by action", onChange: (v) => set({ action: v }) });

    const table = createTable({
      caption: "Audit history",
      compact: true,
      onRowClick: (row) => { if (!openEntity(row)) toggleDetails(row.id); },
      empty: { title: "No audit records match", icon: "file" },
      columns: [
        { key: "timestamp", label: "Timestamp (UTC)", render: (a) => h("span", { class: "nowrap mono" }, fmtDateTime(a.timestamp)) },
        { key: "actor", label: "Actor", render: (a) => h("span", { class: "mono" }, a.actor) },
        { key: "action", label: "Action", render: (a) => h("span", { class: "mono" }, a.action) },
        { key: "entity", label: "Entity", render: (a) => h("div", {}, ENTITY_LABELS[a.entity_type] || a.entity_type,
          a.entity_id ? h("div", { class: "cell-sub mono" }, shortId(a.entity_id)) : null) },
        { key: "summary", label: "Summary", render: (a) => h("div", {}, describeAudit(a)) },
        { key: "details", label: "Details", render: (a) => detailsCell(a) },
      ],
    });
    const pager = createPager({ onChange: (offset) => { q.offset = offset; load(); } });

    const expanded = new Set();
    function detailsCell(a) {
      const pre = h("pre", { class: "json-block", style: { marginTop: "6px", maxWidth: "420px" } }, JSON.stringify(a.details, null, 2));
      pre.hidden = !expanded.has(a.id);
      const btn = h("button", { class: "link-btn details-toggle", type: "button", "aria-expanded": String(expanded.has(a.id)) }, expanded.has(a.id) ? "Hide JSON" : "Show JSON");
      btn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        if (expanded.has(a.id)) expanded.delete(a.id); else expanded.add(a.id);
        pre.hidden = !expanded.has(a.id);
        btn.textContent = expanded.has(a.id) ? "Hide JSON" : "Show JSON";
        btn.setAttribute("aria-expanded", String(expanded.has(a.id)));
      });
      return h("div", { dataset: { auditId: a.id } }, btn, pre);
    }
    function toggleDetails(id) {
      root.querySelector(`[data-audit-id="${id}"] button`)?.click();
    }

    const resetBtn = can("admin") ? h("button", { class: "btn btn-danger", type: "button" }, icon("reset"), "Reset data…") : null;
    resetBtn?.addEventListener("click", () => resetData(resetBtn));

    root.append(h("div", { class: "stack" },
      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", {}, icon("download"), "Exports", h("span", { class: "sub" }, "generated on demand from the database · each file is checked before saving"))),
        h("div", { class: "panel-body" }, h("div", { class: "export-grid" }, EXPORTS.map(exportCard)))),
      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", {}, icon("file"), "Audit history", h("span", { class: "sub" }, "append-only · UTC · click a row to open the related record"))),
        h("div", { class: "toolbar" }, entitySel, actionSel,
          h("span", { class: "muted", style: { fontSize: "12px" } }, "From"), dateInput({ label: "From date (UTC)", onChange: (v) => set({ since: v }) }),
          h("span", { class: "muted", style: { fontSize: "12px" } }, "to"), dateInput({ label: "To date (UTC)", onChange: (v) => set({ until: v }) }),
          h("span", { class: "spacer" }), count),
        table.el, pager.el),
      can("admin") ? h("section", { class: "panel danger-zone" },
        h("div", { class: "panel-head" }, h("h2", {}, icon("alert"), "Reset data"), resetBtn),
        h("div", { class: "panel-body" }, h("p", { class: "muted" },
          "Resetting deletes every record in the database (including this audit log, but not user accounts) and reseeds the original dataset in one transaction. ",
          "A single data.reset entry records the operation. Command line equivalent: python -m app.seed.cli reset"))) : null));

    function set(patch) { Object.assign(q, patch, { offset: 0 }); load(); }

    async function loadFacets() {
      try {
        const facets = await api.get("/audit/facets");
        if (!alive) return;
        const keepE = entitySel.value;
        const keepA = actionSel.value;
        clear(entitySel).append(h("option", { value: "" }, "All entity types"), ...facets.entity_types.map((t) => h("option", { value: t }, ENTITY_LABELS[t] || t)));
        clear(actionSel).append(h("option", { value: "" }, "All actions"), ...facets.actions.map((t) => h("option", { value: t }, t)));
        entitySel.value = keepE;
        actionSel.value = keepA;
      } catch { /* filters remain usable with "All" */ }
    }

    let seq = 0;
    async function load() {
      const mySeq = ++seq;
      table.setLoading();
      try {
        const res = await api.get("/audit", { entity_type: q.entity_type, action: q.action, since: toIsoStartOfDay(q.since),
          until: toIsoEndOfDay(q.until), limit: 25, offset: q.offset });
        if (!alive || mySeq !== seq) return;
        table.setRows(res.items);
        pager.update(res.total, res.limit, res.offset);
        count.textContent = `${res.total} record${res.total === 1 ? "" : "s"}`;
      } catch (err) {
        if (!alive || mySeq !== seq) return;
        table.setError(err, load);
      }
    }

    loadFacets();
    load();
    const reload = debounce(() => { loadFacets(); load(); }, 300);
    return { destroy() { alive = false; }, onLive: reload, onDataChanged: reload };
  },
};
