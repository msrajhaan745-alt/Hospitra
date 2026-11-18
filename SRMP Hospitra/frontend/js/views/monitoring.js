// Threat Monitoring — simulation console + live event stream with detection context.
import { api } from "../core/api.js";
import { dateInput, searchInput, selectInput } from "../core/controls.js";
import { append, clear, debounce, h } from "../core/dom.js";
import { EVENT_TYPE_LABELS, eventTypeLabel, fmtDateTime, fmtRelative, shortId, toIsoEndOfDay, toIsoStartOfDay } from "../core/format.js";
import { icon } from "../core/icons.js";
import { bus, can, state } from "../core/state.js";
import { createPager, createTable } from "../core/table.js";
import { detectionStatusBadge, emptyState, errorState, loadingState, severityBadge, simBadge, toastError, withBusy } from "../core/ui.js";
import { wsStatus } from "../core/ws.js";
import { openEventDrawer, openIncidentDrawer } from "../details.js";
import { resetData } from "../reset.js";

const PAGE = 25;

function zoneCell(zone) {
  return zone ? h("div", {}, h("div", {}, zone.name), h("div", { class: "cell-sub" }, `VLAN ${zone.vlan_id}`)) : h("span", { class: "dim" }, "external");
}

function assetCell(asset, ip) {
  return asset
    ? h("div", {}, h("div", { class: "mono" }, asset.asset_tag), h("div", { class: "cell-sub" }, asset.name))
    : h("div", {}, h("div", { class: "mono dim" }, ip || "—"), h("div", { class: "cell-sub" }, ip ? "unregistered / external" : ""));
}

export default {
  subtitle: "Operator-triggered scenarios → rule-based detection",
  mount(root, params) {
    let alive = true;
    const highlight = new Set();
    const ctxBranch = state.branches.find((b) => b.id === state.branchId);
    const q = {
      search: "",
      severity: "",
      event_type: "",
      branch_id: state.branchId || "",
      detection_status: params.get("detected") ? "detected" : "",
      asset_id: params.get("asset") || "",
      since: params.get("since") || "",
      until: params.get("until") || "",
      offset: 0,
    };

    /* ---------- simulation console ---------- */
    let scenarios = [];
    let selected = "S1";
    let target = ctxBranch?.code || "A";
    const scenarioGrid = h("div", { class: "sim-grid", role: "radiogroup", "aria-label": "Predefined scenarios" });
    const scenarioDesc = h("div", { class: "sim-desc" });
    const simStatus = h("div", { class: "sim-status", "aria-live": "polite", dataset: { state: "idle" } }, icon("info"), "Select a scenario and trigger it. Events are persisted before they appear.");
    const historyHost = h("div");
    const branchTarget = selectInput({ options: state.branches.map((b) => ({ value: b.code, label: `Target: ${b.name}` })), value: target, label: "Target branch", onChange: (v) => { target = v; } });
    const triggerBtn = h("button", { class: "btn btn-primary", type: "button", disabled: !can("operate"),
      title: can("operate") ? null : "Your role is read-only (Analyst or Admin required)" }, icon("play"), "Trigger scenario");
    const resetBtn = can("admin")
      ? h("button", { class: "btn btn-danger btn-sm", type: "button", title: "Delete all data and reseed (user accounts are kept)" }, icon("reset"), "Reset data")
      : null;
    resetBtn?.addEventListener("click", () => resetData(resetBtn));
    if (!can("operate")) {
      simStatus.replaceChildren(icon("lock"), "Read-only for your role: scenarios can be viewed but only Analysts and Admins can trigger them.");
    }

    function renderScenarios() {
      clear(scenarioGrid).append(...scenarios.map((sc) => {
        const btn = h("button", { class: "scenario", type: "button", role: "radio", "aria-checked": String(sc.scenario_id === selected) },
          h("span", { class: "sc-id" }, sc.scenario_id),
          h("span", { class: "sc-name" }, sc.name),
          h("span", { class: "sc-meta" }, severityBadge(sc.expected_severity),
            sc.creates_incident ? h("span", { class: "badge badge-danger" }, "→ incident") : h("span", { class: "badge badge-neutral" }, "alert only")));
        btn.addEventListener("click", () => { selected = sc.scenario_id; renderScenarios(); });
        return btn;
      }));
      const sc = scenarios.find((x) => x.scenario_id === selected);
      if (sc) {
        clear(scenarioDesc).append(
          h("div", {}, h("strong", {}, `${sc.scenario_id} — ${sc.name}. `), sc.description),
          h("div", { class: "dim", style: { marginTop: "4px" } },
            `Source: ${sc.source_description} → Destination: ${sc.destination_description} · ${sc.event_count} event(s) · `,
            `expected rule ${sc.expected_rule_id} “${sc.expected_rule_name}” (${sc.expected_severity}) · `,
            sc.creates_incident ? "High/Critical: an incident is created automatically." : "Below High: recorded as an alert, no incident."));
      }
    }

    async function loadConsole() {
      clear(scenarioGrid).append(loadingState("Loading scenarios…", true));
      try {
        scenarios = await api.get("/simulation/scenarios");
        if (!alive) return;
        renderScenarios();
      } catch (err) {
        clear(scenarioGrid).append(errorState(err, loadConsole, true));
      }
      loadHistory();
    }

    async function loadHistory() {
      try {
        const res = await api.get("/simulation/history", { limit: 6 });
        if (!alive) return;
        clear(historyHost).append(res.items.length
          ? h("table", { class: "data compact" },
            h("thead", {}, h("tr", {}, ["Started (UTC)", "Scenario", "Branch", "Events", "Matches", "Incidents", "By"].map((t) => h("th", {}, t)))),
            h("tbody", {}, res.items.map((r) => h("tr", {},
              h("td", { class: "nowrap", title: fmtDateTime(r.started_at) }, fmtRelative(r.started_at)),
              h("td", {}, h("span", { class: "mono" }, r.scenario_id), " ", r.scenario_name),
              h("td", {}, r.branch_code),
              h("td", { class: "num" }, String(r.event_count)),
              h("td", { class: "num" }, String(r.matched_detection_count)),
              h("td", { class: "num" }, String(r.incident_count)),
              h("td", { class: "mono dim" }, r.triggered_by)))))
          : emptyState({ title: "No simulation runs yet", compact: true }));
      } catch (err) {
        clear(historyHost).append(errorState(err, loadHistory, true));
      }
    }

    function setSimStatus(stateName, ...content) {
      simStatus.dataset.state = stateName;
      append(clear(simStatus), content); // flattening helper: content may contain nested arrays
    }

    triggerBtn.addEventListener("click", () => withBusy(triggerBtn, async () => {
      const sc = scenarios.find((x) => x.scenario_id === selected);
      setSimStatus("running", h("span", { class: "spinner", style: { width: "14px", height: "14px" } }), `Running ${selected} on Branch ${target}…`);
      try {
        const res = await api.post("/simulation/trigger", { scenario_id: selected, branch_code: target });
        res.event_ids.forEach((id) => highlight.add(id));
        const lastEvent = res.event_ids[res.event_ids.length - 1];
        setSimStatus("done", icon(res.incident_ids.length ? "siren" : "check"), h("span", {}, res.summary, " "),
          h("button", { class: "link-btn", type: "button", onclick: () => openEventDrawer(lastEvent) }, "Inspect event"),
          res.incident_ids.length ? [" · ", h("button", { class: "link-btn", type: "button", onclick: () => openIncidentDrawer(res.incident_ids[0]) }, "Open incident")] : null);
        // Show the triggered branch so the new events are visible.
        const b = state.branches.find((x) => x.code === target);
        if (q.branch_id && b && q.branch_id !== b.id) { q.branch_id = ""; branchSel.value = ""; }
        q.offset = 0;
        loadEvents();
        loadHistory();
        bus.emit("data-changed", { entity: "simulation", scenario: sc?.scenario_id });
      } catch (err) {
        setSimStatus("error", icon("alert"), `Scenario failed: ${err.message}`);
        toastError(err, "Simulation failed");
      }
    }));

    /* ---------- events ---------- */
    const count = h("span", { class: "count" });
    const livePill = h("span", { class: "live-pill", dataset: { state: wsStatus() } }, wsStatus() === "live" ? "Live" : "Live updates offline");
    const offWs = bus.on("ws-status", (s) => { livePill.dataset.state = s; livePill.textContent = s === "live" ? "Live" : "Live updates offline"; });
    const branchSel = selectInput({ options: state.branches.map((b) => ({ value: b.id, label: b.name })), value: q.branch_id, allLabel: "All branches", label: "Filter by branch", onChange: (v) => set({ branch_id: v }) });
    const assetChip = h("span");

    const table = createTable({
      caption: "Security events",
      onRowClick: (row) => openEventDrawer(row.id),
      empty: { title: "No events match these filters", message: "Adjust the filters or trigger a scenario.", icon: "activity" },
      columns: [
        { key: "id", label: "Event ID", render: (e) => h("span", { class: "mono cell-main nowrap" }, shortId(e.id)) },
        { key: "occurred_at", label: "Timestamp (UTC)", render: (e) => h("div", { class: "nowrap" }, h("div", {}, fmtDateTime(e.occurred_at)), h("div", { class: "cell-sub" }, fmtRelative(e.occurred_at))) },
        { key: "event_type", label: "Event type", render: (e) => h("span", { class: "nowrap" }, eventTypeLabel(e.event_type)) },
        { key: "src", label: "Source asset", render: (e) => assetCell(e.source_asset, e.source_ip) },
        { key: "src_zone", label: "Source zone", render: (e) => zoneCell(e.source_zone) },
        { key: "dst", label: "Destination asset", render: (e) => assetCell(e.destination_asset, e.destination_ip) },
        { key: "dst_zone", label: "Destination zone", render: (e) => zoneCell(e.destination_zone) },
        { key: "severity", label: "Severity", render: (e) => severityBadge(e.severity) },
        { key: "detection", label: "Detection", render: (e) => detectionStatusBadge(e) },
        { key: "sim", label: "Simulation", render: (e) => simBadge(e.scenario_id) },
        { key: "message", label: "Description", render: (e) => h("div", { class: "truncate", title: e.message, style: { maxWidth: "300px" } }, e.message) },
      ],
    });
    const pager = createPager({ onChange: (offset) => { q.offset = offset; loadEvents(); } });

    function renderAssetChip() {
      clear(assetChip);
      if (!q.asset_id) return;
      assetChip.append(h("span", { class: "badge badge-accent" }, "Filtered to one asset",
        h("button", { class: "link-btn", type: "button", "aria-label": "Clear asset filter", style: { marginLeft: "6px" }, onclick: () => { q.asset_id = ""; renderAssetChip(); set({}); } }, "×")));
    }

    const toolbar = h("div", { class: "toolbar" },
      searchInput({ placeholder: "Search description, IP or asset tag…", onInput: (v) => set({ search: v }), label: "Search events" }),
      selectInput({ options: ["Critical", "High", "Moderate", "Low"], allLabel: "Any severity", label: "Filter by severity", onChange: (v) => set({ severity: v }) }),
      selectInput({ options: Object.entries(EVENT_TYPE_LABELS).map(([value, label]) => ({ value, label })), allLabel: "All event types", label: "Filter by event type", onChange: (v) => set({ event_type: v }) }),
      branchSel,
      selectInput({ options: [{ value: "detected", label: "Detected (rule matched)" }, { value: "no_match", label: "Evaluated, no match" }, { value: "not_evaluated", label: "Not evaluated" }], value: q.detection_status, allLabel: "Any detection status", label: "Filter by detection status", onChange: (v) => set({ detection_status: v }) }),
      h("span", { class: "muted", style: { fontSize: "12px" } }, "From"), dateInput({ value: q.since, label: "From date (UTC)", onChange: (v) => set({ since: v }) }),
      h("span", { class: "muted", style: { fontSize: "12px" } }, "to"), dateInput({ value: q.until, label: "To date (UTC)", onChange: (v) => set({ until: v }) }),
      assetChip, h("span", { class: "spacer" }), count);

    function set(patch) {
      Object.assign(q, patch, { offset: 0 });
      loadEvents();
    }

    let seq = 0;
    async function loadEvents() {
      const mySeq = ++seq;
      table.setLoading();
      try {
        const res = await api.get("/events", {
          search: q.search, severity: q.severity, event_type: q.event_type, branch_id: q.branch_id,
          detection_status: q.detection_status, asset_id: q.asset_id, since: toIsoStartOfDay(q.since), until: toIsoEndOfDay(q.until),
          limit: PAGE, offset: q.offset,
        });
        if (!alive || mySeq !== seq) return;
        table.setRows(res.items, { highlight });
        pager.update(res.total, res.limit, res.offset);
        count.textContent = `${res.total} event${res.total === 1 ? "" : "s"}`;
        setTimeout(() => highlight.clear(), 2500);
      } catch (err) {
        if (!alive || mySeq !== seq) return;
        table.setError(err, loadEvents);
      }
    }

    const consolePanel = h("section", { class: "panel", id: "simulation-console" },
      h("div", { class: "panel-head" }, h("h2", {}, icon("flask"), "Simulation console", h("span", { class: "sub" }, "predefined scenarios")), resetBtn),
      h("div", { class: "panel-body stack" },
        scenarioGrid, scenarioDesc,
        h("div", { class: "sim-controls" }, branchTarget, triggerBtn, simStatus),
        h("div", {}, h("div", { class: "field-label", style: { marginBottom: "6px" } }, "Recent simulation runs"), historyHost)));

    root.append(h("div", { class: "stack" },
      consolePanel,
      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", {}, icon("activity"), "Security event stream", h("span", { class: "sub" }, "click a row for rule evidence and risk context")), livePill),
        toolbar, table.el, pager.el)));

    renderAssetChip();
    loadConsole();
    loadEvents();
    if (params.get("simulate")) setTimeout(() => consolePanel.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
    if (params.get("event")) openEventDrawer(params.get("event"));

    const reloadAll = debounce(() => { loadEvents(); loadHistory(); }, 250);
    return {
      destroy() { alive = false; offWs(); },
      onLive: (msg) => {
        if (msg.type === "simulation.completed") (msg.data.event_ids || []).forEach((id) => highlight.add(id));
        if (msg.type === "data.reset") { loadConsole(); }
        reloadAll();
      },
      onDataChanged: reloadAll,
      onBranch: (id) => { branchSel.value = id; set({ branch_id: id }); const b = state.branches.find((x) => x.id === id); if (b) { target = b.code; branchTarget.value = b.code; } },
    };
  },
};
