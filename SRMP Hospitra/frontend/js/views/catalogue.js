// Threats & Vulnerabilities — catalogue with case-study vs proposed labelling.
import { api } from "../core/api.js";
import { searchInput, selectInput } from "../core/controls.js";
import { debounce, h } from "../core/dom.js";
import { icon } from "../core/icons.js";
import { can } from "../core/state.js";
import { createPager, createTable } from "../core/table.js";
import { activeBadge, sourceTypeBadge } from "../core/ui.js";
import { openThreatDrawer, openVulnerabilityDrawer } from "../details.js";
import { openCatalogueForm } from "../forms.js";

function catalogueTable(kind) {
  const isThreat = kind === "threat";
  const path = isThreat ? "/threats" : "/vulnerabilities";
  const q = { search: "", source_type: "", active: "", offset: 0 };
  const count = h("span", { class: "count" });
  const open = (row) => (isThreat ? openThreatDrawer(row.id) : openVulnerabilityDrawer(row.id));

  const table = createTable({
    caption: isThreat ? "Threat catalogue" : "Vulnerability catalogue",
    onRowClick: open,
    empty: { title: "No catalogue entries match", message: "Clear the filters to see all entries." },
    columns: [
      { key: "code", label: "ID", render: (r) => h("span", { class: "mono cell-main" }, r.code), width: "64px" },
      { key: "name", label: isThreat ? "Threat" : "Vulnerability", render: (r) => h("div", {}, h("div", { class: "cell-main" }, r.name), h("div", { class: "cell-sub truncate", title: r.description }, r.description)) },
      { key: "type", label: isThreat ? "Category" : "Weakness type", render: (r) => (isThreat ? r.category : r.weakness_type) },
      { key: "pairs", label: isThreat ? "Documented vulnerability pairings" : "Documented threat pairings",
        render: (r) => {
          const pairs = isThreat ? r.related_vulnerabilities : r.related_threats;
          return pairs.length ? h("span", { class: "mono" }, pairs.map((p) => p.code).join(" · ")) : h("span", { class: "dim" }, "none");
        } },
      { key: "risk_count", label: "Risks", align: "num", render: (r) => String(r.risk_count) },
      { key: "source_type", label: "Source", render: (r) => sourceTypeBadge(r.source_type) },
      { key: "active", label: "Status", render: (r) => activeBadge(r.active) },
    ],
  });
  const pager = createPager({ onChange: (offset) => { q.offset = offset; load(); } });

  let seq = 0;
  async function load() {
    const mySeq = ++seq;
    table.setLoading();
    try {
      const res = await api.get(path, { search: q.search, source_type: q.source_type, active: q.active, limit: 50, offset: q.offset });
      if (mySeq !== seq) return;
      table.setRows(res.items);
      pager.update(res.total, res.limit, res.offset);
      count.textContent = `${res.total} entr${res.total === 1 ? "y" : "ies"}`;
    } catch (err) {
      if (mySeq !== seq) return;
      table.setError(err, load);
    }
  }
  const set = (patch) => { Object.assign(q, patch, { offset: 0 }); load(); };

  const el = h("div", {},
    h("div", { class: "toolbar" },
      searchInput({ placeholder: `Search ${isThreat ? "threats" : "vulnerabilities"}…`, onInput: (v) => set({ search: v }) }),
      selectInput({ options: [{ value: "Case Study", label: "Initial case study" }, { value: "Proposed", label: "Proposed scenario" }], allLabel: "All sources", label: "Filter by source", onChange: (v) => set({ source_type: v }) }),
      selectInput({ options: [{ value: "true", label: "Active" }, { value: "false", label: "Inactive" }], allLabel: "Active & inactive", label: "Filter by status", onChange: (v) => set({ active: v }) }),
      h("span", { class: "spacer" }), count,
      can("operate")
        ? h("button", { class: "btn btn-primary", type: "button", onclick: () => openCatalogueForm({ kind, onSaved: (rec) => { load(); open(rec); } }) },
          icon("plus"), isThreat ? "New threat" : "New vulnerability")
        : null),
    table.el, pager.el);
  return { el, load };
}

export default {
  subtitle: "Structured threat and vulnerability catalogue · only plausible pairings are documented",
  mount(root, params) {
    const threats = catalogueTable("threat");
    const vulns = catalogueTable("vulnerability");
    let active = params.get("tab") === "vulnerabilities" ? "vulnerabilities" : "threats";
    const tabThreats = h("button", { class: "tab", role: "tab", type: "button", id: "tab-threats", "aria-controls": "tp-threats" }, icon("bug"), "Threat catalogue");
    const tabVulns = h("button", { class: "tab", role: "tab", type: "button", id: "tab-vulns", "aria-controls": "tp-vulns" }, icon("shield"), "Vulnerability catalogue");
    const panelThreats = h("div", { role: "tabpanel", id: "tp-threats", "aria-labelledby": "tab-threats" }, threats.el);
    const panelVulns = h("div", { role: "tabpanel", id: "tp-vulns", "aria-labelledby": "tab-vulns" }, vulns.el);

    function show(tab) {
      active = tab;
      tabThreats.setAttribute("aria-selected", String(tab === "threats"));
      tabVulns.setAttribute("aria-selected", String(tab === "vulnerabilities"));
      panelThreats.hidden = tab !== "threats";
      panelVulns.hidden = tab !== "vulnerabilities";
    }
    tabThreats.addEventListener("click", () => show("threats"));
    tabVulns.addEventListener("click", () => show("vulnerabilities"));

    root.append(h("div", { class: "stack" },
      h("div", { class: "callout callout-info" }, icon("info"), h("div", {},
        "Entries describe possible threats and weaknesses for the hospital network. ",
        h("span", { class: "badge badge-accent" }, "Case study"), " marks the initial case-study entries (T1–T7, V1–V8); ",
        h("span", { class: "badge badge-warn" }, "Proposed"), " marks additional proposed scenarios. Threats are not automatically paired with every vulnerability.")),
      h("section", { class: "panel" }, h("div", { class: "tabs", role: "tablist", "aria-label": "Catalogue" }, tabThreats, tabVulns), panelThreats, panelVulns)));
    show(active);
    threats.load();
    vulns.load();
    const reload = debounce(() => { threats.load(); vulns.load(); }, 300);
    return { onDataChanged: reload, onLive: (msg) => { if (msg.type === "data.reset") reload(); } };
  },
};
