// Security Command Centre — every value is read from the backend.
import { describeAudit, auditTone } from "../audit-format.js";
import { api } from "../core/api.js";
import { SEVERITY_ORDER, chartAvailable, makeChart, severityColours, themeColours } from "../core/charts.js";
import { clear, debounce, h } from "../core/dom.js";
import { fmtDate, fmtDateTime, fmtNumber, fmtRelative } from "../core/format.js";
import { icon } from "../core/icons.js";
import { state } from "../core/state.js";
import { emptyState, errorState, loadingState, severityBadge } from "../core/ui.js";
import { openAssetDrawer, openEventDrawer, openIncidentDrawer, openRiskDrawer } from "../details.js";

function kpi({ label, iconName, value, breakdown, href }) {
  return h("button", { class: "kpi", type: "button", onclick: () => { location.hash = href; } },
    h("div", { class: "kpi-label" }, icon(iconName), label),
    h("div", { class: "kpi-value" }, fmtNumber(value)),
    h("div", { class: "kpi-breakdown" }, breakdown.map(([k, v]) => h("span", {}, `${k} `, h("b", {}, fmtNumber(v))))));
}

const POSTURE_ICON = { Normal: "check", Elevated: "alert", Critical: "siren" };

function branchCard(b) {
  return h("button", { class: "branch-card", type: "button", dataset: { posture: b.posture }, onclick: () => { location.hash = `#/network?branch=${b.code}`; },
    "aria-label": `${b.name}: status ${b.posture}. Open network view.` },
    h("div", { class: "bc-head" },
      h("div", {}, h("div", { class: "bc-name" }, b.name), h("div", { class: "bc-role" }, `${b.role} · site ${b.site_id} · 10.${b.site_id}.x.0/24`)),
      h("span", { class: "posture" }, icon(POSTURE_ICON[b.posture]), b.posture)),
    h("div", { class: "bc-reason" }, b.posture_reason),
    h("div", { class: "bc-stats" },
      h("div", { class: "bc-stat" }, h("b", {}, b.assets_total), "Assets"),
      h("div", { class: "bc-stat" }, h("b", {}, b.open_incidents), "Open incidents"),
      h("div", { class: "bc-stat" }, h("b", {}, b.detections_24h), "Detections 24 h"),
      h("div", { class: "bc-stat" }, h("b", {}, b.assets_by_status.Warning + b.assets_by_status.Offline), "Warn / offline")));
}

function panel(title, sub, body, actions) {
  return h("section", { class: "panel" },
    h("div", { class: "panel-head" }, h("h2", {}, title, sub ? h("span", { class: "sub" }, sub) : null), actions || null),
    body);
}

function chartBox(tall = false) {
  const canvas = h("canvas", { role: "img" });
  return { box: h("div", { class: `chart-box${tall ? " tall" : ""}` }, canvas), canvas };
}

function activityItem(a) {
  const tone = auditTone(a.action);
  const open = () => {
    const d = a.details || {};
    if (a.entity_type === "incident") openIncidentDrawer(a.entity_id);
    else if (a.entity_type === "security_event") openEventDrawer(a.entity_id);
    else if (a.entity_type === "detection" && d.event_id) openEventDrawer(d.event_id);
    else if (a.entity_type === "risk") openRiskDrawer(a.entity_id);
    else if (a.entity_type === "asset") openAssetDrawer(a.entity_id);
    else location.hash = "#/reports";
  };
  return h("button", { class: "feed-item", type: "button", onclick: open },
    h("span", { class: `act-icon ${tone.cls}` }, icon(tone.icon)),
    h("div", { style: { minWidth: 0 } }, h("div", { class: "fi-title" }, describeAudit(a)), h("div", { class: "fi-sub" }, `${a.actor} · ${a.action}`)),
    h("span", { class: "fi-time", title: fmtDateTime(a.timestamp) }, fmtRelative(a.timestamp)));
}

function detectionItem(d) {
  return h("button", { class: "feed-item", type: "button", onclick: () => openEventDrawer(d.event_id) },
    severityBadge(d.severity),
    h("div", { style: { minWidth: 0 } },
      h("div", { class: "fi-title" }, `${d.rule_id} · ${d.rule_name}`),
      h("div", { class: "fi-sub" }, `Branch ${d.event.branch_code} · ${d.asset_tag || "unregistered device"} · ${d.incident_number ? d.incident_number : "alert only (no incident)"}`)),
    h("span", { class: "fi-time", title: fmtDateTime(d.event.occurred_at) }, fmtRelative(d.event.occurred_at)));
}

export default {
  subtitle: "Live security posture of the three hospital branches",
  mount(root) {
    let charts = [];
    let alive = true;
    let riskMode = "inherent";
    const destroyCharts = () => { charts.forEach((c) => c?.destroy()); charts = []; };

    async function load() {
      const branchId = state.branchId || undefined;
      if (!root.childElementCount) root.append(loadingState("Loading Command Centre…"));
      let summary, trends, dist;
      try {
        [summary, trends, dist] = await Promise.all([
          api.get("/dashboard/summary", { branch_id: branchId }),
          api.get("/dashboard/event-trends", { days: 7, branch_id: branchId }),
          api.get("/dashboard/risk-distribution", { branch_id: branchId }),
        ]);
      } catch (err) {
        if (!alive) return;
        destroyCharts();
        clear(root).append(errorState(err, load));
        return;
      }
      if (!alive) return;
      render(summary, trends, dist, branchId);
    }

    function render(s, trends, dist, branchId) {
      destroyCharts();
      const sev = severityColours();
      const theme = themeColours();
      const scope = branchId ? state.branches.find((b) => b.id === branchId)?.name : "All branches";

      const kpis = h("div", { class: "kpis" },
        kpi({ label: "Assets", iconName: "server", value: s.assets.total, href: "#/assets",
          breakdown: [["Active", s.assets.active], ["Warning", s.assets.warning], ["Offline", s.assets.offline], ["Maint.", s.assets.maintenance]] }),
        kpi({ label: "Open incidents", iconName: "siren", value: s.incidents.open_total, href: "#/incidents?active=1",
          breakdown: SEVERITY_ORDER.slice().reverse().map((k) => [k, s.incidents.open_by_severity[k]]) }),
        kpi({ label: "Security events", iconName: "activity", value: s.events.total, href: "#/monitoring",
          breakdown: [["Last 24 h", s.events.last_24h]] }),
        kpi({ label: "Detections", iconName: "alert", value: s.detections.matched_total, href: "#/monitoring?detected=1",
          breakdown: [["Last 24 h", s.detections.matched_last_24h], ["Alert only", s.detections.alerts_without_incident]] }),
        kpi({ label: "Risks", iconName: "list", value: s.risks.total, href: "#/risks",
          breakdown: [["Critical", s.risks.by_severity.Critical], ["High", s.risks.by_severity.High],
            ["Residual Crit.", s.risks.residual_by_severity.Critical], ["Residual High", s.risks.residual_by_severity.High]] }));

      const branches = h("div", { class: "branch-cards" }, s.branches.map(branchCard));

      const evChart = chartBox(true);
      const riskChart = chartBox(true);
      const incChart = chartBox();
      const assetChart = chartBox();

      const riskToggle = h("div", { class: "branch-switch", role: "group", "aria-label": "Inherent or residual risk" },
        ["inherent", "residual"].map((mode) => {
          const b = h("button", { type: "button", "aria-pressed": String(riskMode === mode) }, mode === "inherent" ? "Inherent" : "Residual");
          b.addEventListener("click", () => {
            riskMode = mode;
            riskToggle.querySelectorAll("button").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
            if (chartAvailable()) drawRiskChart();
          });
          return b;
        }));
      const trendTotal = trends.series.reduce((n, d) => n + d.total, 0);
      const detections = s.recent_detections.length
        ? h("div", { class: "feed" }, s.recent_detections.map(detectionItem))
        : emptyState({ title: "No detections yet", message: "Trigger a scenario to generate events.", compact: true });
      const activity = s.recent_activity.length
        ? h("div", { class: "feed" }, s.recent_activity.map(activityItem))
        : emptyState({ title: "No activity recorded", compact: true });

      clear(root).append(h("div", { class: "stack" },
        kpis,
        panel("Branch status", `${scope} context · derived from open incidents, asset status and 24 h detections`, h("div", { class: "panel-body" }, branches)),
        h("div", { class: "grid-main-side" },
          panel("Security events over time", "last 7 UTC days · click a day to filter Threat Monitoring",
            h("div", { class: "panel-body" }, trendTotal ? evChart.box : emptyState({ title: "No events in the last 7 days", compact: true }))),
          panel("Risk severity distribution", `${dist.total} risks · click to filter`,
            h("div", { class: "panel-body" }, dist.total ? riskChart.box : emptyState({ title: "No risks recorded", compact: true })),
            riskToggle)),
        h("div", { class: "grid-2" },
          panel("Incidents by severity", "open vs. all-time · click to filter",
            h("div", { class: "panel-body" }, s.incidents.total ? incChart.box : emptyState({ title: "No incidents", message: "High and Critical detections open incidents automatically.", compact: true }))),
          panel(branchId ? "Assets by zone" : "Assets by branch & status", branchId ? scope : "click to filter the inventory",
            h("div", { class: "panel-body" }, assetChart.box))),
        h("div", { class: "grid-2" },
          panel("Recent detections", "matched rules",
            h("div", { class: "panel-body flush" }, detections), h("a", { href: "#/monitoring?detected=1", class: "btn btn-sm btn-ghost" }, "View all")),
          panel("Recent activity", "audit trail", h("div", { class: "panel-body flush" }, activity), h("a", { href: "#/reports", class: "btn btn-sm btn-ghost" }, "Audit log"))),
        h("p", { class: "chart-note" }, `Generated ${fmtDateTime(s.generated_at)} from the Hospitra database.`)));

      if (!chartAvailable()) {
        for (const box of [evChart, riskChart, incChart, assetChart]) {
          box.box.replaceChildren(errorState(new Error("Chart library failed to load (vendor/chart.umd.js).")));
        }
        return;
      }

      if (trendTotal) {
        charts.push(makeChart(evChart.canvas, {
          type: "bar",
          data: {
            labels: trends.series.map((d) => fmtDate(d.date)),
            datasets: [
              ...SEVERITY_ORDER.map((k) => ({ type: "bar", label: `${k} events`, data: trends.series.map((d) => d[k]), backgroundColor: sev[k], stack: "events", borderRadius: 2, maxBarThickness: 46 })),
              { type: "line", label: "Matched detections", data: trends.series.map((d) => d.detections), borderColor: theme.text, backgroundColor: theme.text, pointRadius: 3, tension: 0.25, borderWidth: 1.5 },
            ],
          },
          options: {
            interaction: { mode: "index", intersect: false },
            scales: { x: { stacked: true, grid: { display: false } }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } },
            onClick: (_e, elements) => {
              if (!elements.length) return;
              const day = trends.series[elements[0].index].date;
              location.hash = `#/monitoring?since=${day}&until=${day}`;
            },
          },
        }));
        evChart.canvas.setAttribute("aria-label", `Security events per day for the last 7 days; ${trendTotal} events in total.`);
      }

      let riskChartInstance = null;
      function drawRiskChart() {
        if (!dist.total) return;
        const counts = riskMode === "residual" ? dist.residual_by_severity : dist.by_severity;
        const param = riskMode === "residual" ? "residual_severity" : "severity";
        if (riskChartInstance) { riskChartInstance.destroy(); charts = charts.filter((c) => c !== riskChartInstance); }
        riskChartInstance = makeChart(riskChart.canvas, {
          type: "doughnut",
          data: {
            labels: SEVERITY_ORDER.map((k) => `${k} (${counts[k]})`),
            datasets: [{ data: SEVERITY_ORDER.map((k) => counts[k]), backgroundColor: SEVERITY_ORDER.map((k) => sev[k]), borderColor: theme.panel, borderWidth: 3 }],
          },
          options: {
            cutout: "62%",
            plugins: { legend: { position: "right" }, title: { display: true, text: riskMode === "residual" ? "Residual (after implemented controls)" : "Inherent (before controls)", color: theme.muted } },
            onClick: (_e, elements) => { if (elements.length) location.hash = `#/risks?${param}=${SEVERITY_ORDER[elements[0].index]}`; },
          },
        });
        charts.push(riskChartInstance);
        riskChart.canvas.setAttribute("aria-label", `${riskMode} risk severity distribution: ${SEVERITY_ORDER.map((k) => `${k} ${counts[k]}`).join(", ")}.`);
      }
      drawRiskChart();

      if (s.incidents.total) {
        const order = SEVERITY_ORDER;
        charts.push(makeChart(incChart.canvas, {
          type: "bar",
          data: {
            labels: order,
            datasets: [
              { label: "Open", data: order.map((k) => s.incidents.open_by_severity[k]), backgroundColor: order.map((k) => sev[k]), borderRadius: 3, maxBarThickness: 34 },
              { label: "All-time", data: order.map((k) => s.incidents.by_severity[k]), backgroundColor: "rgba(148,166,189,0.28)", borderRadius: 3, maxBarThickness: 34 },
            ],
          },
          options: {
            scales: { x: { grid: { display: false } }, y: { beginAtZero: true, ticks: { precision: 0 } } },
            onClick: (_e, elements) => {
              if (!elements.length) return;
              const el = elements[0];
              location.hash = `#/incidents?severity=${order[el.index]}${el.datasetIndex === 0 ? "&active=1" : ""}`;
            },
          },
        }));
        incChart.canvas.setAttribute("aria-label", `Open incidents by severity: ${order.map((k) => `${k} ${s.incidents.open_by_severity[k]}`).join(", ")}.`);
      }

      if (branchId) {
        const zones = s.asset_distribution.by_zone;
        charts.push(makeChart(assetChart.canvas, {
          type: "bar",
          data: { labels: zones.map((z) => `VLAN ${z.vlan_id} ${z.zone}`), datasets: [{ label: "Assets", data: zones.map((z) => z.count), backgroundColor: theme.accent, borderRadius: 3, maxBarThickness: 18 }] },
          options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } }, y: { grid: { display: false } } },
            onClick: () => { location.hash = "#/assets"; } },
        }));
      } else {
        const statuses = [["Active", theme.ok], ["Warning", theme.warn], ["Offline", theme.danger], ["Maintenance", theme.info]];
        charts.push(makeChart(assetChart.canvas, {
          type: "bar",
          data: {
            labels: s.branches.map((b) => b.name),
            datasets: statuses.map(([st, colour]) => ({ label: st, data: s.branches.map((b) => b.assets_by_status[st]), backgroundColor: colour, stack: "a", maxBarThickness: 26 })),
          },
          options: {
            indexAxis: "y",
            scales: { x: { stacked: true, beginAtZero: true, ticks: { precision: 0 } }, y: { stacked: true, grid: { display: false } } },
            onClick: (_e, elements) => {
              if (!elements.length) return;
              const b = s.branches[elements[0].index];
              location.hash = `#/assets?branch=${b.code}&status=${statuses[elements[0].datasetIndex][0]}`;
            },
          },
        }));
      }
      assetChart.canvas.setAttribute("aria-label", "Asset distribution chart");
    }

    const reload = debounce(load, 300);
    load();
    return {
      destroy() { alive = false; destroyCharts(); },
      onLive: reload,
      onDataChanged: reload,
      onBranch: () => { clear(root); load(); },
    };
  },
};
