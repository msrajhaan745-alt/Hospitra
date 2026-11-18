// Risk Register — transparent qualitative model: Score = Likelihood × max(C, I, A).
import { api } from "../core/api.js";
import { searchInput, selectInput } from "../core/controls.js";
import { debounce, h } from "../core/dom.js";
import { icon } from "../core/icons.js";
import { can, state } from "../core/state.js";
import { createPager, createTable } from "../core/table.js";
import { riskStatusBadge, severityBadge, toastError, withBusy } from "../core/ui.js";
import { openAssetDrawer, openRiskDrawer } from "../details.js";
import { openRiskForm } from "../forms.js";

const PAGE = 25;
const num = (v) => h("span", { class: "num mono" }, String(v));

export default {
  subtitle: "Inherent = Likelihood × max(C, I, A) · Residual applies implemented controls · bands 1–4 / 5–9 / 10–16 / 17–25",
  mount(root, params) {
    let alive = true;
    const q = {
      search: "",
      branch_id: state.branchId || "",
      severity: params.get("severity") || "",
      residual_severity: params.get("residual_severity") || "",
      status: "",
      treatment: "",
      sort: "risk_score",
      order: "desc",
      offset: 0,
    };
    const count = h("span", { class: "count" });
    const branchSel = selectInput({ options: state.branches.map((b) => ({ value: b.id, label: b.name })), value: q.branch_id, allLabel: "All branches", label: "Filter by branch", onChange: (v) => set({ branch_id: v }) });

    const table = createTable({
      caption: "Risk register",
      sort: q.sort,
      order: q.order,
      onSort: (sort, order) => set({ sort, order }),
      onRowClick: (row) => openRiskDrawer(row.id),
      empty: { title: "No risks match these filters", message: "Clear a filter or record a new risk.", icon: "list" },
      columns: [
        { key: "reference", label: "Risk ID", sortKey: "reference", render: (r) => h("span", { class: "mono cell-main nowrap" }, r.reference) },
        { key: "asset", label: "Asset", sortKey: "asset", render: (r) => h("div", {},
          h("button", { class: "link-btn mono", type: "button", onclick: () => openAssetDrawer(r.asset.id) }, r.asset.asset_tag),
          h("div", { class: "cell-sub" }, r.asset.name)) },
        { key: "threat", label: "Threat", render: (r) => h("div", { title: r.threat.name }, h("span", { class: "mono dim" }, r.threat.code), " ", r.threat.name) },
        { key: "vuln", label: "Vulnerability", render: (r) => h("div", { title: r.vulnerability.name }, h("span", { class: "mono dim" }, r.vulnerability.code), " ", r.vulnerability.name) },
        { key: "likelihood", label: "L", sortKey: "likelihood", defaultOrder: "desc", align: "center", render: (r) => num(r.likelihood) },
        { key: "c", label: "C", align: "center", render: (r) => num(r.confidentiality_impact) },
        { key: "i", label: "I", align: "center", render: (r) => num(r.integrity_impact) },
        { key: "a", label: "A", align: "center", render: (r) => num(r.availability_impact) },
        { key: "overall_impact", label: "Impact", sortKey: "overall_impact", defaultOrder: "desc", align: "center", render: (r) => num(r.overall_impact) },
        { key: "risk_score", label: "Score", sortKey: "risk_score", defaultOrder: "desc", align: "center",
          render: (r) => h("span", { class: "mono cell-main", title: r.calculation.score_expression }, String(r.risk_score)) },
        { key: "severity", label: "Severity", sortKey: "severity", defaultOrder: "desc", render: (r) => severityBadge(r.severity) },
        { key: "residual_score", label: "Residual", sortKey: "residual_score", defaultOrder: "desc", align: "center",
          render: (r) => h("span", { class: `mono cell-main${r.residual_score < r.risk_score ? "" : " dim"}`, title: r.residual_calculation.score_expression }, String(r.residual_score)) },
        { key: "residual_severity", label: "Res. severity", sortKey: "residual_severity", defaultOrder: "desc", render: (r) => severityBadge(r.residual_severity) },
        { key: "controls", label: "Controls", align: "center", render: (r) => {
          const counted = r.controls.filter((c) => c.counted).length;
          return r.controls.length
            ? h("span", { class: "num", title: `${counted} implemented of ${r.controls.length} linked` }, `${counted}/${r.controls.length}`)
            : h("span", { class: "dim" }, "—");
        } },
        { key: "treatment", label: "Treatment", sortKey: "treatment" },
        { key: "owner", label: "Owner", sortKey: "owner", render: (r) => h("span", { class: "nowrap" }, r.owner) },
        { key: "status", label: "Status", sortKey: "status", render: (r) => riskStatusBadge(r.status) },
      ],
    });
    const pager = createPager({ onChange: (offset) => { q.offset = offset; load(); } });

    const newBtn = can("operate")
      ? h("button", { class: "btn btn-primary", type: "button", onclick: () => openRiskForm({ onSaved: (r) => { load(); openRiskDrawer(r.id); } }) }, icon("plus"), "New risk")
      : null;
    const exportBtn = h("button", { class: "btn", type: "button" }, icon("download"), "Export CSV");
    exportBtn.addEventListener("click", () => withBusy(exportBtn, async () => {
      try { await api.download("/api/v1/exports/risks.csv"); } catch (err) { toastError(err, "Export failed"); }
    }));

    root.append(h("div", { class: "stack" },
      h("div", { class: "callout callout-info" }, icon("info"), h("div", {},
        "Each record links an asset, a threat and a vulnerability. Inherent score = Likelihood × max(C, I, A); residual score applies the implemented controls.")),
      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", {}, icon("list"), "Risk register"), h("div", { style: { display: "flex", gap: "8px" } }, exportBtn, newBtn)),
        h("div", { class: "toolbar" },
          searchInput({ placeholder: "Search ID, asset, threat, owner…", onInput: (v) => set({ search: v }), label: "Search risks" }),
          branchSel,
          selectInput({ options: ["Critical", "High", "Moderate", "Low"], value: q.severity, allLabel: "Any inherent severity", label: "Filter by inherent severity", onChange: (v) => set({ severity: v }) }),
          selectInput({ options: ["Critical", "High", "Moderate", "Low"], value: q.residual_severity, allLabel: "Any residual severity", label: "Filter by residual severity", onChange: (v) => set({ residual_severity: v }) }),
          selectInput({ options: ["Open", "In Treatment", "Closed"], allLabel: "Any status", label: "Filter by status", onChange: (v) => set({ status: v }) }),
          selectInput({ options: ["Mitigate", "Accept", "Transfer", "Avoid"], allLabel: "Any treatment", label: "Filter by treatment", onChange: (v) => set({ treatment: v }) }),
          h("span", { class: "spacer" }), count),
        table.el, pager.el)));

    function set(patch) { Object.assign(q, patch, { offset: 0 }); load(); }

    let seq = 0;
    async function load() {
      const mySeq = ++seq;
      table.setLoading();
      try {
        const res = await api.get("/risks", { search: q.search, branch_id: q.branch_id, severity: q.severity, residual_severity: q.residual_severity, status: q.status,
          treatment: q.treatment, sort: q.sort, order: q.order, limit: PAGE, offset: q.offset });
        if (!alive || mySeq !== seq) return;
        table.setRows(res.items);
        pager.update(res.total, res.limit, res.offset);
        count.textContent = `${res.total} risk${res.total === 1 ? "" : "s"}`;
      } catch (err) {
        if (!alive || mySeq !== seq) return;
        table.setError(err, load);
      }
    }

    load();
    if (params.get("id")) openRiskDrawer(params.get("id"));
    const reload = debounce(load, 300);
    return {
      destroy() { alive = false; },
      onDataChanged: reload,
      onLive: (msg) => { if (msg.type === "risk.changed" || msg.type === "data.reset") reload(); },
      onBranch: (id) => { branchSel.value = id; set({ branch_id: id }); },
    };
  },
};
