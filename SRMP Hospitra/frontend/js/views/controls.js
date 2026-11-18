// Security Controls (V2) — the control library that drives residual risk.
import { api } from "../core/api.js";
import { searchInput, selectInput } from "../core/controls.js";
import { debounce, h } from "../core/dom.js";
import { icon } from "../core/icons.js";
import { can } from "../core/state.js";
import { createPager, createTable } from "../core/table.js";
import { activeBadge } from "../core/ui.js";
import { openControlDrawer, openVulnerabilityDrawer } from "../details.js";
import { openControlForm } from "../forms.js";

const AXIS = { likelihood: "Likelihood", impact: "Impact" };

export default {
  subtitle: "Control library · implemented controls lower residual likelihood (preventive) or impact (detective/corrective)",
  mount(root, params) {
    let alive = true;
    const q = { search: "", control_type: "", category: "", active: "", offset: 0 };
    const count = h("span", { class: "count" });
    const categorySel = selectInput({ options: [], allLabel: "All categories", label: "Filter by category", onChange: (v) => set({ category: v }) });

    const table = createTable({
      caption: "Security controls",
      onRowClick: (row) => openControlDrawer(row.id),
      empty: { title: "No controls match these filters", icon: "shield" },
      columns: [
        { key: "code", label: "Code", render: (c) => h("span", { class: "mono cell-main" }, c.code), width: "64px" },
        { key: "name", label: "Control", render: (c) => h("div", {}, h("div", { class: "cell-main" }, c.name),
          h("div", { class: "cell-sub truncate", title: c.description, style: { maxWidth: "360px" } }, c.description)) },
        { key: "type", label: "Type", render: (c) => c.control_type },
        { key: "axis", label: "Reduces", render: (c) => h("span", { class: "badge badge-info" }, AXIS[c.axis]) },
        { key: "category", label: "Category", render: (c) => c.category },
        { key: "vulns", label: "Addresses", render: (c) => c.vulnerabilities.length
          ? h("span", {}, c.vulnerabilities.map((v, i) => [i ? " · " : "",
            h("button", { class: "link-btn mono", type: "button", title: v.name, onclick: () => openVulnerabilityDrawer(v.id) }, v.code)]))
          : h("span", { class: "dim" }, "—") },
        { key: "links", label: "Linked risks", align: "num", render: (c) => h("span", { class: "num", title: "implemented / total links" },
          `${c.implemented_link_count} / ${c.linked_risk_count}`) },
        { key: "active", label: "Status", render: (c) => activeBadge(c.active) },
      ],
    });
    const pager = createPager({ onChange: (offset) => { q.offset = offset; load(); } });
    const newBtn = can("operate")
      ? h("button", { class: "btn btn-primary", type: "button", onclick: () => openControlForm({ onSaved: (c) => { load(); openControlDrawer(c.id); } }) }, icon("plus"), "New control")
      : null;

    root.append(h("div", { class: "stack" },
      h("div", { class: "callout callout-info" }, icon("info"), h("div", {},
        h("strong", {}, "Residual model: "),
        "only Implemented controls count. Preventive → likelihood, detective/corrective → impact. Partial lowers 1 level, Substantial 2. ",
        "Only the strongest control per axis is applied (no stacking); values never drop below 1. Link controls to risks from the Risk Register.")),
      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", {}, icon("shield"), "Control library"), newBtn),
        h("div", { class: "toolbar" },
          searchInput({ placeholder: "Search code, name or description…", onInput: (v) => set({ search: v }), label: "Search controls" }),
          selectInput({ options: ["Preventive", "Detective", "Corrective"], allLabel: "All types", label: "Filter by type", onChange: (v) => set({ control_type: v }) }),
          categorySel,
          selectInput({ options: [{ value: "true", label: "Active" }, { value: "false", label: "Inactive" }], allLabel: "Active & inactive", label: "Filter by status", onChange: (v) => set({ active: v }) }),
          h("span", { class: "spacer" }), count),
        table.el, pager.el)));

    function set(patch) { Object.assign(q, patch, { offset: 0 }); load(); }

    async function loadCategories() {
      try {
        const cats = await api.get("/controls/categories");
        const keep = categorySel.value;
        categorySel.replaceChildren(h("option", { value: "" }, "All categories"), ...cats.map((c) => h("option", { value: c }, c)));
        categorySel.value = keep;
      } catch { /* filter stays at "All" */ }
    }

    let seq = 0;
    async function load() {
      const mySeq = ++seq;
      table.setLoading();
      try {
        const res = await api.get("/controls", { ...q, limit: 50 });
        if (!alive || mySeq !== seq) return;
        table.setRows(res.items);
        pager.update(res.total, res.limit, res.offset);
        count.textContent = `${res.total} control${res.total === 1 ? "" : "s"}`;
      } catch (err) {
        if (!alive || mySeq !== seq) return;
        table.setError(err, load);
      }
    }

    loadCategories();
    load();
    if (params.get("id")) openControlDrawer(params.get("id"));
    const reload = debounce(() => { loadCategories(); load(); }, 300);
    return { destroy() { alive = false; }, onDataChanged: reload, onLive: (m) => { if (m.type === "risk.changed" || m.type === "data.reset") reload(); } };
  },
};
