// Incident Management — lifecycle Open → Investigating → Contained → Resolved → Closed.
import { api } from "../core/api.js";
import { searchInput, selectInput } from "../core/controls.js";
import { debounce, h } from "../core/dom.js";
import { fmtDateTime, fmtRelative } from "../core/format.js";
import { icon } from "../core/icons.js";
import { state } from "../core/state.js";
import { createPager, createTable } from "../core/table.js";
import { incidentStatusBadge, severityBadge, toastError, withBusy } from "../core/ui.js";
import { openIncidentDrawer } from "../details.js";

const PAGE = 25;
const LIFECYCLE = ["Open", "Investigating", "Contained", "Resolved", "Closed"];

function progress(status) {
  const idx = LIFECYCLE.indexOf(status);
  return h("div", { title: `Lifecycle: ${LIFECYCLE.join(" → ")}`, style: { display: "flex", gap: "3px", marginTop: "4px" } },
    LIFECYCLE.map((s, i) => h("span", { "aria-hidden": "true", style: { width: "14px", height: "4px", borderRadius: "2px", background: i <= idx ? "var(--accent)" : "var(--border-strong)" } })));
}

export default {
  subtitle: "Incidents are opened automatically for High/Critical detections · containment is recorded only",
  mount(root, params) {
    let alive = true;
    const q = {
      search: "",
      status: params.get("status") || "",
      severity: params.get("severity") || "",
      branch_id: state.branchId || "",
      active_only: params.get("active") === "1",
      offset: 0,
    };
    const count = h("span", { class: "count" });
    const branchSel = selectInput({ options: state.branches.map((b) => ({ value: b.id, label: b.name })), value: q.branch_id, allLabel: "All branches", label: "Filter by branch", onChange: (v) => set({ branch_id: v }) });
    const statusSel = selectInput({
      options: [{ value: "__active", label: "Active (Open/Investigating/Contained)" }, ...LIFECYCLE.map((s) => ({ value: s, label: s }))],
      value: q.active_only ? "__active" : q.status, allLabel: "Any status", label: "Filter by status",
      onChange: (v) => set(v === "__active" ? { active_only: true, status: "" } : { active_only: false, status: v }),
    });

    const table = createTable({
      caption: "Incidents",
      onRowClick: (row) => openIncidentDrawer(row.id),
      empty: { title: "No incidents match these filters", message: "Incidents are created automatically when a High or Critical rule matches.", icon: "siren" },
      columns: [
        { key: "incident_number", label: "Incident", render: (i) => h("span", { class: "mono cell-main" }, i.incident_number) },
        { key: "title", label: "Title", render: (i) => h("div", {}, h("div", { class: "cell-main truncate", title: i.title, style: { maxWidth: "380px" } }, i.title),
          h("div", { class: "cell-sub" }, `Rule ${i.rule_id} · ${i.event_count} event(s)`)) },
        { key: "severity", label: "Severity", render: (i) => severityBadge(i.severity) },
        { key: "status", label: "Status", render: (i) => h("div", {}, incidentStatusBadge(i.status), progress(i.status)) },
        { key: "assigned_to", label: "Assigned", render: (i) => i.assigned_to || h("span", { class: "dim" }, "Unassigned") },
        { key: "branch", label: "Branch", render: (i) => (i.branch_code ? `Branch ${i.branch_code}` : "—") },
        { key: "assets", label: "Assets", render: (i) => (i.asset_tags.length ? h("span", { class: "mono", title: i.asset_tags.join(", ") }, i.asset_tags.length > 2 ? `${i.asset_tags.slice(0, 2).join(", ")} +${i.asset_tags.length - 2}` : i.asset_tags.join(", ")) : h("span", { class: "dim" }, "—")) },
        { key: "created_at", label: "Created (UTC)", render: (i) => h("div", { class: "nowrap" }, h("div", {}, fmtDateTime(i.created_at, { seconds: false })), h("div", { class: "cell-sub" }, fmtRelative(i.created_at))) },
        { key: "updated_at", label: "Updated", render: (i) => h("span", { class: "nowrap", title: fmtDateTime(i.updated_at) }, fmtRelative(i.updated_at)) },
      ],
    });
    const pager = createPager({ onChange: (offset) => { q.offset = offset; load(); } });

    const exportBtn = h("button", { class: "btn", type: "button" }, icon("download"), "Export CSV");
    exportBtn.addEventListener("click", () => withBusy(exportBtn, async () => {
      try { await api.download("/api/v1/exports/incidents.csv"); } catch (err) { toastError(err, "Export failed"); }
    }));

    root.append(h("div", { class: "stack" },
      h("div", { class: "callout callout-info" }, icon("info"), h("div", {},
        h("strong", {}, "Creation policy: "), "Low and Moderate detections remain alerts in Threat Monitoring; High and Critical detections open exactly one incident each. ",
        h("strong", {}, "Lifecycle: "), "Open → Investigating → Contained → Resolved → Closed, one step at a time. Containment is recorded only — no host, account or network change is made.")),
      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", {}, icon("siren"), "Incidents"), exportBtn),
        h("div", { class: "toolbar" },
          searchInput({ placeholder: "Search number, title or assignee…", onInput: (v) => set({ search: v }), label: "Search incidents" }),
          statusSel,
          selectInput({ options: ["Critical", "High", "Moderate", "Low"], value: q.severity, allLabel: "Any severity", label: "Filter by severity", onChange: (v) => set({ severity: v }) }),
          branchSel, h("span", { class: "spacer" }), count),
        table.el, pager.el)));

    function set(patch) { Object.assign(q, patch, { offset: 0 }); load(); }

    let seq = 0;
    async function load() {
      const mySeq = ++seq;
      table.setLoading();
      try {
        const res = await api.get("/incidents", { search: q.search, status: q.status, severity: q.severity, branch_id: q.branch_id,
          active_only: q.active_only || undefined, limit: PAGE, offset: q.offset });
        if (!alive || mySeq !== seq) return;
        table.setRows(res.items);
        pager.update(res.total, res.limit, res.offset);
        count.textContent = `${res.total} incident${res.total === 1 ? "" : "s"}`;
      } catch (err) {
        if (!alive || mySeq !== seq) return;
        table.setError(err, load);
      }
    }

    load();
    if (params.get("id")) openIncidentDrawer(params.get("id"));
    const reload = debounce(load, 300);
    return {
      destroy() { alive = false; },
      onLive: reload,
      onDataChanged: reload,
      onBranch: (id) => { branchSel.value = id; set({ branch_id: id }); },
    };
  },
};
