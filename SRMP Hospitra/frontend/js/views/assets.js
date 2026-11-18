// Asset Inventory — searchable, filterable, sortable; create and edit with validation.
import { api } from "../core/api.js";
import { searchInput, selectInput } from "../core/controls.js";
import { clear, debounce, h } from "../core/dom.js";
import { fmtDateTime, fmtRelative } from "../core/format.js";
import { ASSET_TYPE_ICONS, icon } from "../core/icons.js";
import { branchByCode, can, state } from "../core/state.js";
import { createPager, createTable } from "../core/table.js";
import { assetStatusBadge, criticalityBadge, toastError, withBusy } from "../core/ui.js";
import { openAssetDrawer } from "../details.js";
import { openAssetForm } from "../forms.js";

const ZONE_TYPES = [
  ["management", "Network Management"], ["staff", "Staff / Administration"], ["clinical", "Clinical Workstations"],
  ["application", "Application / Data"], ["medical", "Medical Devices"], ["guest", "Guest Wi-Fi"],
  ["security", "Security Services"], ["dmz", "DMZ"],
];
const ASSET_TYPES = Object.keys(ASSET_TYPE_ICONS);
const PAGE = 25;

export default {
  subtitle: "Inventory of network assets across the three hospital branches",
  mount(root, params) {
    let alive = true;
    const paramBranch = params.get("branch") && branchByCode(params.get("branch"));
    const q = {
      search: params.get("search") || "",
      branch_id: paramBranch?.id || state.branchId || "",
      zone_type: params.get("zone_type") || "",
      asset_type: params.get("asset_type") || "",
      criticality: params.get("criticality") || "",
      status: params.get("status") || "",
      sort: "asset_tag",
      order: "asc",
      offset: 0,
    };

    const count = h("span", { class: "count" });
    const branchSel = selectInput({ options: state.branches.map((b) => ({ value: b.id, label: b.name })), value: q.branch_id, allLabel: "All branches", label: "Filter by branch", onChange: (v) => set({ branch_id: v }) });
    const toolbar = h("div", { class: "toolbar" },
      searchInput({ placeholder: "Search name, tag or IP…", value: q.search, onInput: (v) => set({ search: v }), label: "Search assets" }),
      branchSel,
      selectInput({ options: ZONE_TYPES.map(([value, label]) => ({ value, label })), value: q.zone_type, allLabel: "All zones", label: "Filter by zone", onChange: (v) => set({ zone_type: v }) }),
      selectInput({ options: ASSET_TYPES, value: q.asset_type, allLabel: "All types", label: "Filter by asset type", onChange: (v) => set({ asset_type: v }) }),
      selectInput({ options: ["Critical", "High", "Medium", "Low"], value: q.criticality, allLabel: "Any criticality", label: "Filter by criticality", onChange: (v) => set({ criticality: v }) }),
      selectInput({ options: ["Active", "Warning", "Offline", "Maintenance"], value: q.status, allLabel: "Any status", label: "Filter by status", onChange: (v) => set({ status: v }) }),
      h("span", { class: "spacer" }), count);

    const table = createTable({
      caption: "Asset inventory",
      sort: q.sort,
      order: q.order,
      onSort: (sort, order) => set({ sort, order }),
      onRowClick: (row) => openAssetDrawer(row.id),
      empty: { title: "No assets match these filters", message: "Clear a filter or broaden the search." },
      columns: [
        { key: "asset_tag", label: "Asset tag", sortKey: "asset_tag", render: (a) => h("span", { class: "mono cell-main" }, a.asset_tag) },
        { key: "name", label: "Asset name", sortKey: "name", render: (a) => h("span", { class: "cell-main" }, a.name) },
        { key: "asset_type", label: "Type", sortKey: "asset_type", render: (a) => h("span", { style: { display: "inline-flex", gap: "6px", alignItems: "center" } }, icon(ASSET_TYPE_ICONS[a.asset_type] || "server"), a.asset_type) },
        { key: "branch", label: "Branch", sortKey: "branch", render: (a) => `Branch ${a.branch_code}` },
        { key: "zone", label: "Zone", sortKey: "zone", render: (a) => h("div", {}, h("div", {}, a.zone_name), h("div", { class: "cell-sub" }, `VLAN ${a.vlan_id}`)) },
        { key: "ip_address", label: "IP address", sortKey: "ip_address", render: (a) => h("span", { class: "mono" }, a.ip_address) },
        { key: "owner", label: "Owner", sortKey: "owner" },
        { key: "criticality", label: "Criticality", sortKey: "criticality", render: (a) => criticalityBadge(a.criticality) },
        { key: "data_classification", label: "Classification", sortKey: "data_classification" },
        { key: "status", label: "Status", sortKey: "status", render: (a) => assetStatusBadge(a.status) },
        { key: "last_seen_at", label: "Last seen", sortKey: "last_seen_at", render: (a) => h("span", { title: fmtDateTime(a.last_seen_at), class: "nowrap" }, a.last_seen_at ? fmtRelative(a.last_seen_at) : "—") },
      ],
    });
    const pager = createPager({ onChange: (offset) => { q.offset = offset; load(); } });

    const newBtn = can("operate")
      ? h("button", { class: "btn btn-primary", type: "button", onclick: () => openAssetForm({ onSaved: (a) => { load(); openAssetDrawer(a.id); } }) }, icon("plus"), "New asset")
      : null;
    const exportBtn = h("button", { class: "btn", type: "button" }, icon("download"), "Export CSV");
    exportBtn.addEventListener("click", () => withBusy(exportBtn, async () => {
      try { await api.download("/api/v1/exports/assets.csv"); } catch (err) { toastError(err, "Export failed"); }
    }));

    root.append(h("section", { class: "panel" },
      h("div", { class: "panel-head" }, h("h2", {}, icon("server"), "Asset inventory", h("span", { class: "sub" }, "logical records · deletion disabled to preserve history")),
        h("div", { style: { display: "flex", gap: "8px" } }, exportBtn, newBtn)),
      toolbar, table.el, pager.el));

    function set(patch) {
      Object.assign(q, patch, { offset: 0 });
      load();
    }

    let seq = 0;
    async function load() {
      const mySeq = ++seq;
      table.setLoading();
      try {
        const res = await api.get("/assets", {
          search: q.search, branch_id: q.branch_id, zone_type: q.zone_type, asset_type: q.asset_type,
          criticality: q.criticality, status: q.status, sort: q.sort, order: q.order, limit: PAGE, offset: q.offset,
        });
        if (!alive || mySeq !== seq) return;
        table.setRows(res.items);
        pager.update(res.total, res.limit, res.offset);
        count.textContent = `${res.total} asset${res.total === 1 ? "" : "s"}`;
      } catch (err) {
        if (!alive || mySeq !== seq) return;
        table.setError(err, load);
        count.textContent = "";
      }
    }

    load();
    if (params.get("id")) openAssetDrawer(params.get("id"));
    const reload = debounce(load, 300);
    return {
      destroy() { alive = false; clear(root); },
      onLive: reload,
      onDataChanged: reload,
      onBranch: (id) => { branchSel.value = id; set({ branch_id: id }); },
    };
  },
};
