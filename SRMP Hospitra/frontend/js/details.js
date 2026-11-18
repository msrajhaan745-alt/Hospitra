// Shared detail panels (drawer content). Opened from any view so cross-links work everywhere.
import { api } from "./core/api.js";
import { h } from "./core/dom.js";
import { eventTypeLabel, fmtDateTime, fmtRelative, shortId } from "./core/format.js";
import { ASSET_TYPE_ICONS, icon } from "./core/icons.js";
import { bus, can } from "./core/state.js";
import {
  activeBadge,
  assetStatusBadge,
  confirmDialog,
  criticalityBadge,
  detectionStatusBadge,
  emptyState,
  incidentStatusBadge,
  openDrawer,
  riskStatusBadge,
  severityBadge,
  simBadge,
  sourceTypeBadge,
  toast,
  toastError,
  withBusy,
} from "./core/ui.js";
import { openAssetForm, openCatalogueForm, openControlForm, openRiskForm } from "./forms.js";

const readOnlyNote = () => h("span", { class: "dim", style: { fontSize: "12px" } }, "Read-only for your role");

/* ---------------- shared render helpers ---------------- */
export function section(title, ...children) {
  return h("section", { class: "section" }, h("h3", {}, title), ...children);
}

export function kv(rows) {
  return h("dl", { class: "kv" }, rows.filter(Boolean).flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v ?? "—")]));
}

export function assetLink(asset, fallback = "—") {
  if (!asset) return h("span", { class: "dim" }, fallback);
  return h("button", { class: "link-btn", type: "button", onclick: () => openAssetDrawer(asset.id) },
    h("span", { class: "mono" }, asset.asset_tag), " ", h("span", { class: "muted" }, asset.name));
}

export function zoneLabel(zone) {
  if (!zone) return h("span", { class: "dim" }, "External / none");
  return `${zone.name} (VLAN ${zone.vlan_id})`;
}

function ciaText(c, i, a) {
  return h("span", { class: "mono" }, `C ${c} · I ${i} · A ${a}`);
}

export function riskCard(risk) {
  return h("button", { class: "mini-card", type: "button", onclick: () => openRiskDrawer(risk.id) },
    h("div", { class: "row" }, h("span", { class: "mono dim" }, risk.reference), severityBadge(risk.severity),
      h("span", { class: "mono num" }, `Score ${risk.risk_score}`),
      h("span", { class: "dim" }, "→ residual"), severityBadge(risk.residual_severity),
      h("span", { class: "mono num" }, String(risk.residual_score)), riskStatusBadge(risk.status)),
    h("div", { class: "title", style: { marginTop: "4px" } },
      `${risk.threat.code} ${risk.threat.name} × ${risk.vulnerability.code} ${risk.vulnerability.name}`),
    h("div", { class: "desc" }, `${risk.asset.asset_tag} · L ${risk.likelihood} × Impact ${risk.overall_impact} · ${risk.treatment}`));
}

function eventCard(ev) {
  return h("button", { class: "mini-card", type: "button", onclick: () => openEventDrawer(ev.id) },
    h("div", { class: "row" }, h("span", { class: "mono dim" }, `EVT ${shortId(ev.id)}`), severityBadge(ev.severity),
      simBadge(ev.scenario_id), h("span", { class: "dim" }, fmtDateTime(ev.occurred_at))),
    h("div", { class: "desc" }, ev.message));
}

export function riskContextSection(risks, intro) {
  return section(`Risk context (${risks.length})`,
    intro ? h("p", { class: "muted", style: { fontSize: "12px", marginBottom: "8px" } }, intro) : null,
    risks.length
      ? h("div", { class: "card-list" }, risks.map(riskCard))
      : emptyState({ title: "No related risk", message: "No risk record links the affected asset(s) to this rule's related threats or vulnerabilities.", compact: true }));
}

export function evidenceTable(evidence) {
  const rows = Object.entries(evidence || {});
  if (!rows.length) return h("p", { class: "dim" }, "No evidence fields recorded.");
  return h("table", { class: "evidence" }, h("tbody", {}, rows.map(([k, v]) =>
    h("tr", {}, h("td", {}, k), h("td", {}, formatEvidence(k, v))))));
}

function formatEvidence(key, value) {
  if (value === null || value === undefined || value === "") return h("span", { class: "dim" }, "—");
  if (Array.isArray(value)) {
    if (key.endsWith("event_ids")) {
      return h("span", {}, value.map((id, i) => [i ? ", " : "",
        h("button", { class: "link-btn mono", type: "button", onclick: () => openEventDrawer(id) }, shortId(id))]));
    }
    return value.join(", ");
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function detectionCard(detection, rule) {
  const matched = detection.matched;
  return h("div", { class: `detect-card${matched ? " matched" : ""}` },
    h("div", { class: "dc-head" },
      h("span", { class: "mono", style: { fontWeight: 700 } }, detection.rule_id),
      h("strong", {}, detection.rule_name),
      matched
        ? h("span", { class: "badge badge-danger" }, icon("alert"), "Rule matched")
        : h("span", { class: "badge badge-neutral" }, icon("check"), "Not matched"),
      severityBadge(detection.severity),
      detection.incident_number
        ? h("button", { class: "link-btn", type: "button", onclick: () => openIncidentDrawer(detection.incident_id), style: { marginLeft: "auto" } },
          `${detection.incident_number} →`)
        : null),
    h("div", { class: "dc-body" },
      h("div", {}, h("div", { class: "field-label", style: { marginBottom: "4px" } }, matched ? "Why the rule matched" : "Evaluation result"),
        h("p", { class: "why" }, detection.explanation)),
      rule ? h("div", {}, h("div", { class: "field-label", style: { marginBottom: "4px" } }, "Rule conditions"),
        h("ul", { class: "conditions" }, rule.conditions.map((c) => h("li", {}, c)))) : null,
      h("div", {}, h("div", { class: "field-label", style: { marginBottom: "4px" } }, "Evidence"), evidenceTable(detection.evidence))));
}

/* ---------------- Asset ---------------- */
export function openAssetDrawer(assetId) {
  openDrawer({
    eyebrow: "Asset",
    title: "Loading…",
    render: async (ctx) => {
      const a = await api.get(`/assets/${assetId}`);
      ctx.setEyebrow(`Asset · ${a.asset_tag}`);
      ctx.setTitle(a.name);
      ctx.setMeta(assetStatusBadge(a.status), criticalityBadge(a.criticality),
        h("span", { class: "badge badge-outline" }, a.data_classification), h("span", { class: "badge badge-outline" }, `Branch ${a.branch_code}`));
      ctx.setFooter(...(can("operate") ? [
        h("button", { class: "btn", type: "button", onclick: () => openRiskForm({ presetAssetId: a.id, onSaved: (r) => { ctx.reload(); openRiskDrawer(r.id); } }) }, icon("plus"), "Add risk"),
        h("button", { class: "btn btn-primary", type: "button", onclick: () => openAssetForm({ asset: a, onSaved: () => ctx.reload() }) }, icon("edit"), "Edit asset"),
      ] : [readOnlyNote()]));
      return [
        section("Identity", kv([
          ["Asset tag", h("span", { class: "mono" }, a.asset_tag)],
          ["Name", a.name],
          ["Type", h("span", { style: { display: "inline-flex", gap: "6px", alignItems: "center" } }, icon(ASSET_TYPE_ICONS[a.asset_type] || "server"), a.asset_type)],
          ["Branch", `${a.branch_name}`],
          ["Zone", `${a.zone_name} (VLAN ${a.vlan_id})`],
          ["IP address", h("span", { class: "mono" }, a.ip_address)],
          ["Operating system", a.operating_system || "—"],
          ["Owner", a.owner],
          ["Status", assetStatusBadge(a.status)],
          ["Last seen", a.last_seen_at ? `${fmtDateTime(a.last_seen_at)} (${fmtRelative(a.last_seen_at)})` : "—"],
        ])),
        section("Security profile", kv([
          ["Criticality", criticalityBadge(a.criticality)],
          ["Data classification", h("span", {}, a.data_classification, h("span", { class: "dim" }, "  (stored separately from CIA)"))],
          ["CIA ratings", ciaText(a.confidentiality, a.integrity, a.availability)],
        ])),
        section(`Risks (${a.risks.length})`,
          a.risks.length
            ? h("div", { class: "card-list" }, a.risks.map((r) =>
              h("button", { class: "mini-card", type: "button", onclick: () => openRiskDrawer(r.id) },
                h("div", { class: "row" }, h("span", { class: "mono dim" }, r.reference), severityBadge(r.severity),
                  h("span", { class: "mono" }, `Score ${r.risk_score}`), riskStatusBadge(r.status)),
                h("div", { class: "desc" }, `${r.threat_code} ${r.threat_name} × ${r.vulnerability_code} ${r.vulnerability_name}`))))
            : emptyState({ title: "No risks recorded", message: "Use “Add risk” to record a risk for this asset.", compact: true })),
        section("Activity", kv([
          ["Security events", h("span", {}, `${a.event_count} `,
            a.event_count ? h("a", { href: `#/monitoring?asset=${a.id}`, onclick: () => ctx.close() }, "View in Threat Monitoring →") : null)],
          ["Open incidents", String(a.open_incident_count)],
          ["Record created", fmtDateTime(a.created_at)],
          ["Record updated", fmtDateTime(a.updated_at)],
        ])),
      ];
    },
  });
}

/* ---------------- Event ---------------- */
export function openEventDrawer(eventId) {
  openDrawer({
    eyebrow: "Security event",
    title: "Loading…",
    wide: true,
    render: async (ctx) => {
      const e = await api.get(`/events/${eventId}`);
      ctx.setEyebrow(`Security event · EVT ${shortId(e.id)}`);
      ctx.setTitle(`${eventTypeLabel(e.event_type)} — Branch ${e.branch_code}`);
      ctx.setMeta(severityBadge(e.severity), simBadge(e.scenario_id), detectionStatusBadge(e));
      const rulesById = Object.fromEntries((e.rules || []).map((r) => [r.rule_id, r]));
      const matched = e.detections.filter((d) => d.matched);
      let incidentSection = null;
      if (e.incident) {
        incidentSection = section("Incident",
          h("button", { class: "mini-card", type: "button", onclick: () => openIncidentDrawer(e.incident.id) },
            h("div", { class: "row" }, h("span", { class: "mono" }, e.incident.incident_number), severityBadge(e.incident.severity),
              incidentStatusBadge(e.incident.status)),
            h("div", { class: "desc" }, e.incident.title)));
      } else if (matched.length) {
        incidentSection = section("Incident", h("div", { class: "callout" }, icon("info"),
          h("div", {}, `No incident was created: the matched detection severity (${matched.map((d) => d.severity).join(", ")}) is below the automatic incident threshold (High or Critical). The alert remains visible here.`)));
      }
      return [
        h("div", { class: "callout callout-sim" }, icon("flask"), h("div", {},
          h("strong", {}, "Source: "),
          e.scenario_id === "BASELINE"
            ? "routine baseline activity from the seeded history."
            : `scenario ${e.scenario_id}${e.simulation_run_id ? ` (run ${shortId(e.simulation_run_id)})` : ""}.`)),
        section("Event context", kv([
          ["Event ID", h("span", { class: "mono" }, e.id)],
          ["Occurred", `${fmtDateTime(e.occurred_at)} (${fmtRelative(e.occurred_at)})`],
          ["Event type", eventTypeLabel(e.event_type)],
          ["Source asset", assetLink(e.source_asset, e.source_asset ? "" : "Unregistered / external")],
          ["Source zone", zoneLabel(e.source_zone)],
          ["Source IP", h("span", { class: "mono" }, e.source_ip || "—")],
          ["Destination asset", assetLink(e.destination_asset, "None / external")],
          ["Destination zone", zoneLabel(e.destination_zone)],
          ["Destination IP", h("span", { class: "mono" }, e.destination_ip || "—")],
          ["Description", e.message],
        ])),
        section(`Detection (${e.detections.length} rule evaluation${e.detections.length === 1 ? "" : "s"})`,
          e.detections.length
            ? h("div", { class: "card-list" }, e.detections.map((d) => detectionCard(d, rulesById[d.rule_id])))
            : emptyState({ title: "Not evaluated", message: "No detection rule applies to this event type.", compact: true })),
        incidentSection,
        matched.length ? riskContextSection(e.risk_context, "Risks on the affected asset(s) that relate to the matched rule's threats or vulnerabilities.") : null,
        section("Event metadata", h("pre", { class: "json-block" }, JSON.stringify(e.metadata, null, 2))),
      ];
    },
  });
}

/* ---------------- Risk ---------------- */
export function riskCalculation(r) {
  const inputs = [
    ["Likelihood", r.likelihood, false],
    ["Confidentiality", r.confidentiality_impact, r.confidentiality_impact === r.overall_impact],
    ["Integrity", r.integrity_impact, r.integrity_impact === r.overall_impact],
    ["Availability", r.availability_impact, r.availability_impact === r.overall_impact],
  ];
  return h("div", { class: "calc" },
    h("div", { class: "calc-inputs" }, inputs.map(([label, value, isMax]) =>
      h("div", { class: `calc-input${isMax ? " is-max" : ""}`, title: isMax ? "Highest CIA rating — determines impact" : null },
        h("div", { class: "ci-label" }, label), h("div", { class: "ci-value" }, String(value))))),
    h("div", { class: "calc-steps" },
      h("div", {}, r.calculation.impact_expression),
      h("div", {}, r.calculation.score_expression),
      h("div", { class: "result", style: { display: "flex", gap: "8px", alignItems: "center" } },
        `Severity band ${r.calculation.severity_band}`, severityBadge(r.severity))),
    h("div", { class: "calc-formula" }, `${r.calculation.formula}. Bands: 1–4 Low · 5–9 Moderate · 10–16 High · 17–25 Critical. Calculated by the server.`));
}

const AXIS_TEXT = { likelihood: "lowers likelihood", impact: "lowers impact" };

export function residualCalculation(r) {
  const rc = r.residual_calculation;
  const reduced = r.residual_score < r.risk_score;
  return h("div", { class: "calc" },
    h("div", { class: "calc-inputs" },
      h("div", { class: "calc-input" }, h("div", { class: "ci-label" }, "Inherent L"), h("div", { class: "ci-value" }, String(r.likelihood))),
      h("div", { class: `calc-input${r.residual_likelihood < r.likelihood ? " is-max" : ""}` }, h("div", { class: "ci-label" }, "Residual L"), h("div", { class: "ci-value" }, String(r.residual_likelihood))),
      h("div", { class: "calc-input" }, h("div", { class: "ci-label" }, "Inherent impact"), h("div", { class: "ci-value" }, String(r.overall_impact))),
      h("div", { class: `calc-input${r.residual_impact < r.overall_impact ? " is-max" : ""}` }, h("div", { class: "ci-label" }, "Residual impact"), h("div", { class: "ci-value" }, String(r.residual_impact)))),
    h("div", { class: "calc-steps" },
      h("div", {}, rc.likelihood_expression),
      h("div", {}, rc.impact_expression),
      h("div", {}, rc.score_expression),
      h("div", { class: "result", style: { display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" } },
        `Severity band ${rc.severity_band}`, severityBadge(r.residual_severity),
        h("span", { class: "dim", style: { fontWeight: 400 } }, reduced ? `(inherent ${r.risk_score} ${r.severity})` : "(no reduction — no counted controls)"))),
    h("div", { class: "calc-formula" }, `${rc.rule} Calculated by the server.`));
}

async function controlsSection(r, ctx) {
  const editable = can("operate");
  const refresh = () => { bus.emit("data-changed", { entity: "risk", id: r.id }); ctx.reload(); };
  const patchLink = async (controlId, body, el) => {
    el.disabled = true;
    try {
      const updated = await api.patch(`/risks/${r.id}/controls/${controlId}`, body);
      toast({ type: "success", title: "Control updated", message: `Residual ${updated.residual_score} (${updated.residual_severity})` });
      refresh();
    } catch (err) { toastError(err, "Update rejected"); el.disabled = false; }
  };

  const rows = r.controls.map((c) => {
    let status;
    let effect;
    if (editable) {
      status = h("select", { class: "select", "aria-label": `${c.code} implementation status`, style: { height: "28px" } },
        ["Planned", "Implemented"].map((v) => h("option", { value: v }, v)));
      status.value = c.implementation_status;
      status.addEventListener("change", () => patchLink(c.control_id, { implementation_status: status.value }, status));
      effect = h("select", { class: "select", "aria-label": `${c.code} effectiveness`, style: { height: "28px" } },
        ["Partial", "Substantial"].map((v) => h("option", { value: v }, `${v} (−${v === "Partial" ? 1 : 2})`)));
      effect.value = c.effectiveness;
      effect.addEventListener("change", () => patchLink(c.control_id, { effectiveness: effect.value }, effect));
    } else {
      status = h("span", { class: "badge badge-outline" }, c.implementation_status);
      effect = h("span", { class: "badge badge-outline" }, `${c.effectiveness} (−${c.reduction})`);
    }
    const state = c.applied
      ? h("span", { class: "badge badge-ok", title: "Strongest counted control on its axis — used in the calculation" }, icon("check"), "Applied")
      : c.counted
        ? h("span", { class: "badge badge-neutral", title: "Counted, but a stronger or equal control on the same axis is applied (no stacking)" }, "Not strongest")
        : h("span", { class: "badge badge-outline", title: c.control_active ? "Planned controls do not reduce residual risk" : "Inactive controls do not count" },
          c.control_active ? "Planned — not counted" : "Inactive control");
    const unlink = editable ? h("button", { class: "btn btn-ghost btn-sm btn-icon", type: "button", "aria-label": `Unlink ${c.code}` }, icon("x")) : null;
    unlink?.addEventListener("click", async () => {
      if (!(await confirmDialog({ title: `Unlink ${c.code}?`, message: `Remove ${c.code} ${c.name} from ${r.reference}? The control itself is kept; residual risk is recalculated.`, confirmLabel: "Unlink" }))) return;
      try { await api.delete(`/risks/${r.id}/controls/${c.control_id}`); toast({ type: "success", title: `${c.code} unlinked` }); refresh(); } catch (err) { toastError(err); }
    });
    return h("div", { class: "mini-card" },
      h("div", { class: "row" },
        h("button", { class: "link-btn mono", type: "button", onclick: () => openControlDrawer(c.control_id) }, c.code),
        h("span", { class: "title" }, c.name), h("span", { style: { marginLeft: "auto" } }, unlink)),
      h("div", { class: "row", style: { marginTop: "6px" } },
        h("span", { class: "badge badge-info" }, `${c.control_type} · ${AXIS_TEXT[c.axis]}`), status, effect, state));
  });

  let addForm = null;
  if (editable) {
    const library = (await api.get("/controls", { active: true, limit: 200 })).items;
    const linked = new Set(r.controls.map((c) => c.control_id));
    const available = library.filter((c) => !linked.has(c.id));
    if (available.length) {
      const suggests = (c) => c.vulnerabilities.some((v) => v.id === r.vulnerability.id);
      const select = h("select", { class: "select", "aria-label": "Control to link" },
        h("option", { value: "" }, "Select a control…"),
        available.sort((a, b) => Number(suggests(b)) - Number(suggests(a)))
          .map((c) => h("option", { value: c.id }, `${c.code} — ${c.name} (${c.control_type})${suggests(c) ? `  ✓ addresses ${r.vulnerability.code}` : ""}`)));
      const status = h("select", { class: "select", "aria-label": "Implementation status" }, h("option", { value: "Implemented" }, "Implemented"), h("option", { value: "Planned" }, "Planned"));
      const effect = h("select", { class: "select", "aria-label": "Effectiveness" }, h("option", { value: "Partial" }, "Partial (−1)"), h("option", { value: "Substantial" }, "Substantial (−2)"));
      const add = h("button", { class: "btn", type: "button" }, icon("plus"), "Link control");
      add.addEventListener("click", () => {
        if (!select.value) { select.setAttribute("aria-invalid", "true"); select.focus(); return; }
        withBusy(add, async () => {
          try {
            const updated = await api.post(`/risks/${r.id}/controls`, { control_id: select.value, implementation_status: status.value, effectiveness: effect.value });
            toast({ type: "success", title: "Control linked", message: `Residual ${updated.residual_score} (${updated.residual_severity})` });
            refresh();
          } catch (err) { toastError(err, "Link rejected"); }
        });
      });
      addForm = h("div", { class: "mini-card", style: { display: "grid", gap: "8px" } },
        h("div", { class: "field-label" }, "Link a control"), select,
        h("div", { style: { display: "flex", gap: "8px", flexWrap: "wrap" } }, status, effect, add));
    }
  }

  return section(`Controls (${r.controls.length})`,
    h("div", { class: "card-list" },
      rows.length ? rows : emptyState({ title: "No controls linked", message: "Residual risk equals inherent risk until an implemented control is linked.", compact: true }),
      addForm));
}

export function openRiskDrawer(riskId) {
  openDrawer({
    eyebrow: "Risk",
    title: "Loading…",
    render: async (ctx) => {
      const r = await api.get(`/risks/${riskId}`);
      ctx.setEyebrow(`Risk · ${r.reference}`);
      ctx.setTitle(`${r.threat.name} × ${r.vulnerability.name}`);
      ctx.setMeta(h("span", { class: "dim", style: { fontSize: "11px" } }, "Inherent"), severityBadge(r.severity),
        h("span", { class: "badge badge-outline mono" }, `${r.risk_score}`),
        h("span", { class: "dim", style: { fontSize: "11px" } }, "Residual"), severityBadge(r.residual_severity),
        h("span", { class: "badge badge-outline mono" }, `${r.residual_score}`),
        h("span", { class: "badge badge-outline" }, r.treatment), riskStatusBadge(r.status));
      ctx.setFooter(can("operate")
        ? h("button", { class: "btn btn-primary", type: "button", onclick: () => openRiskForm({ risk: r, onSaved: () => ctx.reload() }) }, icon("edit"), "Edit risk")
        : readOnlyNote());
      return [
        section("Inherent risk", riskCalculation(r)),
        section("Residual risk", residualCalculation(r)),
        await controlsSection(r, ctx),
        section("Related asset", h("div", { class: "card-list" },
          h("button", { class: "mini-card", type: "button", onclick: () => openAssetDrawer(r.asset.id) },
            h("div", { class: "row" }, h("span", { class: "mono" }, r.asset.asset_tag), criticalityBadge(r.asset.criticality),
              h("span", { class: "badge badge-outline" }, r.asset.data_classification)),
            h("div", { class: "desc" }, `${r.asset.name} · Branch ${r.asset.branch_code} · ${r.asset.zone_name}`)))),
        section("Threat & vulnerability", kv([
          ["Threat", h("button", { class: "link-btn", type: "button", onclick: () => openThreatDrawer(r.threat.id) }, `${r.threat.code} — ${r.threat.name}`)],
          ["Vulnerability", h("button", { class: "link-btn", type: "button", onclick: () => openVulnerabilityDrawer(r.vulnerability.id) }, `${r.vulnerability.code} — ${r.vulnerability.name}`)],
          ["Pairing rationale", r.pairing_rationale || h("span", { class: "dim" }, "No documented pairing rationale for this combination — treat as a proposed relationship.")],
        ])),
        section("Record", kv([
          ["Treatment", r.treatment],
          ["Owner", r.owner],
          ["Status", riskStatusBadge(r.status)],
          ["Created", fmtDateTime(r.created_at)],
          ["Updated", fmtDateTime(r.updated_at)],
        ])),
      ];
    },
  });
}

/* ---------------- Incident ---------------- */
const LIFECYCLE = ["Open", "Investigating", "Contained", "Resolved", "Closed"];

function stepper(status) {
  const idx = LIFECYCLE.indexOf(status);
  return h("div", { class: "stepper", role: "list", "aria-label": "Incident lifecycle" }, LIFECYCLE.map((s, i) =>
    h("div", { class: `step${i < idx ? " done" : ""}${i === idx ? " current" : ""}`, role: "listitem", "aria-current": i === idx ? "step" : null },
      h("span", { class: "dot" }, i < idx ? icon("check") : null), s)));
}

const AUDIT_LABELS = {
  "incident.created": "Incident created",
  "incident.status_changed": "Status changed",
  "incident.assigned": "Assignment changed",
  "incident.note_added": "Note added",
};

export function openIncidentDrawer(incidentId) {
  openDrawer({
    eyebrow: "Incident",
    title: "Loading…",
    wide: true,
    render: async (ctx) => {
      const inc = await api.get(`/incidents/${incidentId}`);
      ctx.setEyebrow(`Incident · ${inc.incident_number}`);
      ctx.setTitle(inc.title);
      ctx.setMeta(severityBadge(inc.severity), incidentStatusBadge(inc.status),
        inc.branch_code ? h("span", { class: "badge badge-outline" }, `Branch ${inc.branch_code}`) : null,
        h("span", { class: "badge badge-outline" }, inc.assigned_to ? `Assigned: ${inc.assigned_to}` : "Unassigned"));
      ctx.setFooter();

      const update = async (button, body, successTitle) => {
        await withBusy(button, async () => {
          try {
            await api.patch(`/incidents/${inc.id}`, body);
            toast({ type: "success", title: successTitle, message: inc.incident_number });
            bus.emit("data-changed", { entity: "incident", id: inc.id });
            ctx.reload();
          } catch (err) {
            toastError(err, "Incident update rejected");
          }
        });
      };

      const viewerOnly = !can("operate");
      const closed = inc.status === "Closed" || viewerOnly; // disables every control below
      const next = viewerOnly ? null : inc.allowed_next_status;
      const advanceBtn = next ? h("button",{ class: "btn btn-primary", type: "button" }, icon("arrow"), `Move to ${next}`) : null;
      advanceBtn?.addEventListener("click", async () => {
        const message = next === "Contained"
          ? `Record ${inc.incident_number} as Contained? This updates the incident status; status changes cannot be reversed.`
          : `Move ${inc.incident_number} from ${inc.status} to ${next}? Status changes are one step at a time and cannot be reversed.`;
        if (await confirmDialog({ title: `Move to ${next}`, message, confirmLabel: `Move to ${next}` })) {
          update(advanceBtn, { status: next }, `Status changed to ${next}`);
        }
      });

      const assignInput = h("input", { class: "input", type: "text", value: inc.assigned_to || "", placeholder: "e.g. SOC Tier 1", maxlength: "80", "aria-label": "Assigned operator label", disabled: closed });
      const assignBtn = h("button", { class: "btn", type: "button", disabled: closed }, "Save");
      assignBtn.addEventListener("click", () => {
        const value = assignInput.value.trim();
        if (!value) { assignInput.setAttribute("aria-invalid", "true"); toast({ type: "warn", title: "Enter an operator label to assign" }); return; }
        update(assignBtn, { assigned_to: value }, "Assignment saved");
      });

      const defaultNote = { Open: "Investigation", Investigating: "Investigation", Contained: "Containment", Resolved: "Resolution" }[inc.status] || "Investigation";
      const noteType = h("select", { class: "select", "aria-label": "Note type", disabled: closed },
        ["Investigation", "Containment", "Resolution"].map((t) => h("option", { value: t }, `${t} note`)));
      noteType.value = defaultNote;
      const noteBody = h("textarea", { class: "textarea", rows: "3", maxlength: "4000", placeholder: "Add an investigation, containment or resolution note…", "aria-label": "Note text", disabled: closed });
      const noteBtn = h("button", { class: "btn", type: "button", disabled: closed }, icon("note"), "Add note");
      noteBtn.addEventListener("click", () => {
        const body = noteBody.value.trim();
        if (!body) { noteBody.setAttribute("aria-invalid", "true"); noteBody.focus(); return; }
        update(noteBtn, { note: { note_type: noteType.value, body } }, `${noteType.value} note added`);
      });

      return [
        h("div", { class: "panel" }, h("div", { class: "panel-body stack" },
          stepper(inc.status),
          h("div", { style: { display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap" } },
            advanceBtn || h("span", { class: "muted" }, viewerOnly
              ? `Read-only for your role (next status would be ${inc.allowed_next_status || "—"}).`
              : closed ? "Closed — this incident can no longer be modified." : ""),
            next ? h("span", { class: "dim", style: { fontSize: "12px" } }, `Permitted next status: ${next} (one step at a time)`) : null),
          h("div", { class: "form-grid" },
            h("div", { class: "field" }, h("label", {}, "Assigned operator label"), h("div", { style: { display: "flex", gap: "8px" } }, assignInput, assignBtn)),
            h("div", { class: "field" }, h("label", {}, "Note type"), noteType),
            h("div", { class: "field span-2" }, noteBody, h("div", { style: { display: "flex", justifyContent: "flex-end" } }, noteBtn))))),
        section("Summary", kv([
          ["Description", h("span", { style: { whiteSpace: "pre-wrap" } }, inc.description)],
          ["Created", fmtDateTime(inc.created_at)],
          ["Updated", fmtDateTime(inc.updated_at)],
          ["Resolved", fmtDateTime(inc.resolved_at)],
          ["Closed", fmtDateTime(inc.closed_at)],
          ["Resolution notes", inc.resolution_notes ? h("span", { style: { whiteSpace: "pre-wrap" } }, inc.resolution_notes) : "—"],
        ])),
        section("Triggering detection", detectionCard(inc.detection),
          h("div", { style: { marginTop: "8px" } }, h("button", { class: "link-btn", type: "button", onclick: () => openEventDrawer(inc.detection.event_id) }, "Open triggering event →"))),
        section(`Associated events (${inc.events.length})`, h("div", { class: "card-list" }, inc.events.map(eventCard))),
        section(`Affected assets (${inc.assets.length})`, inc.assets.length
          ? h("div", { class: "card-list" }, inc.assets.map((a) =>
            h("button", { class: "mini-card", type: "button", onclick: () => openAssetDrawer(a.id) },
              h("div", { class: "row" }, h("span", { class: "mono" }, a.asset_tag), assetStatusBadge(a.status), criticalityBadge(a.criticality)),
              h("div", { class: "desc" }, `${a.name} · ${a.zone_name} (VLAN ${a.vlan_id}) · ${a.ip_address}`))))
          : emptyState({ title: "No registered asset", compact: true })),
        riskContextSection(inc.risk_context),
        section(`Notes (${inc.notes.length})`, inc.notes.length
          ? h("div", { class: "timeline" }, inc.notes.map((n) => h("div", { class: "tl-item", style: { "--tl": "var(--accent)" } },
            h("span", { class: "tl-dot" }),
            h("div", {}, h("div", { class: "tl-title" }, `${n.note_type} note`), h("div", { class: "tl-meta" }, `${n.author} · ${fmtDateTime(n.created_at)}`),
              h("div", { class: "tl-body" }, n.body)))))
          : emptyState({ title: "No notes yet", compact: true })),
        section(`Audit history (${inc.history.length})`, h("div", { class: "timeline" }, inc.history.map((a) => {
          const d = a.details || {};
          const text = a.action === "incident.status_changed" ? `${d.from} → ${d.to}${d.note ? ` · ${d.note}` : ""}`
            : a.action === "incident.assigned" ? `${d.from || "unassigned"} → ${d.to || "unassigned"}`
              : a.action === "incident.note_added" ? `${d.note_type} note`
                : a.action === "incident.created" ? `${d.policy || ""} (rule ${d.rule_id})` : "";
          return h("div", { class: "tl-item" }, h("span", { class: "tl-dot" }),
            h("div", {}, h("div", { class: "tl-title" }, AUDIT_LABELS[a.action] || a.action),
              h("div", { class: "tl-meta" }, `${a.actor} · ${fmtDateTime(a.timestamp)}`), text ? h("div", { class: "tl-body" }, text) : null));
        }))),
      ];
    },
  });
}

/* ---------------- Threats & vulnerabilities ---------------- */
function catalogueDrawer(kind, id) {
  const isThreat = kind === "threat";
  const path = isThreat ? "threats" : "vulnerabilities";
  openDrawer({
    eyebrow: isThreat ? "Threat" : "Vulnerability",
    title: "Loading…",
    render: async (ctx) => {
      const [rec, risks] = await Promise.all([
        api.get(`/${path}/${id}`),
        api.get("/risks", { [isThreat ? "threat_id" : "vulnerability_id"]: id, limit: 50 }),
      ]);
      ctx.setEyebrow(`${isThreat ? "Threat" : "Vulnerability"} · ${rec.code}`);
      ctx.setTitle(rec.name);
      ctx.setMeta(sourceTypeBadge(rec.source_type), activeBadge(rec.active));
      const toggleBtn = h("button", { class: "btn", type: "button" }, rec.active ? "Deactivate" : "Activate");
      toggleBtn.addEventListener("click", () => withBusy(toggleBtn, async () => {
        try {
          await api.patch(`/${path}/${rec.id}`, { active: !rec.active });
          toast({ type: "success", title: `${rec.code} ${rec.active ? "deactivated" : "activated"}` });
          bus.emit("data-changed", { entity: kind });
          ctx.reload();
        } catch (err) { toastError(err); }
      }));
      ctx.setFooter(...(can("operate")
        ? [toggleBtn, h("button", { class: "btn btn-primary", type: "button", onclick: () => openCatalogueForm({ kind, record: rec, onSaved: () => ctx.reload() }) }, icon("edit"), "Edit")]
        : [readOnlyNote()]));
      const pairs = isThreat ? rec.related_vulnerabilities : rec.related_threats;
      return [
        rec.source_type === "Proposed"
          ? h("div", { class: "callout callout-info" }, icon("info"), h("div", {}, "Additional proposed entry — not part of the initial case study."))
          : null,
        section("Description", h("p", { style: { lineHeight: 1.6 } }, rec.description)),
        section("Details", kv([
          [isThreat ? "Category" : "Weakness type", isThreat ? rec.category : rec.weakness_type],
          ["Source", sourceTypeBadge(rec.source_type)],
          ["Status", activeBadge(rec.active)],
          ["Created", fmtDateTime(rec.created_at)],
        ])),
        section(`Documented ${isThreat ? "vulnerability" : "threat"} pairings (${pairs.length})`,
          h("p", { class: "muted", style: { fontSize: "12px", marginBottom: "8px" } }, "Only technically plausible pairings are documented — not every threat is paired with every vulnerability."),
          pairs.length
            ? h("div", { class: "card-list" }, pairs.map((p) => h("button", { class: "mini-card", type: "button", onclick: () => (isThreat ? openVulnerabilityDrawer(p.id) : openThreatDrawer(p.id)) },
              h("div", { class: "row" }, h("span", { class: "mono" }, p.code), h("span", { class: "title" }, p.name)),
              h("div", { class: "desc" }, p.rationale))))
            : emptyState({ title: "No documented pairings", compact: true })),
        section(`Related risks (${risks.total})`, risks.items.length
          ? h("div", { class: "card-list" }, risks.items.map(riskCard))
          : emptyState({ title: "No risks reference this record", compact: true })),
      ];
    },
  });
}

export const openThreatDrawer = (id) => catalogueDrawer("threat", id);
export const openVulnerabilityDrawer = (id) => catalogueDrawer("vulnerability", id);

/* ---------------- Security control (V2) ---------------- */
export function openControlDrawer(controlId) {
  openDrawer({
    eyebrow: "Security control",
    title: "Loading…",
    render: async (ctx) => {
      const [c, risks] = await Promise.all([
        api.get(`/controls/${controlId}`),
        api.get("/risks", { control_id: controlId, limit: 200, sort: "residual_score", order: "desc" }),
      ]);
      ctx.setEyebrow(`Security control · ${c.code}`);
      ctx.setTitle(c.name);
      ctx.setMeta(h("span", { class: "badge badge-info" }, `${c.control_type} · ${AXIS_TEXT[c.axis]}`),
        h("span", { class: "badge badge-outline" }, c.category), activeBadge(c.active));
      if (can("operate")) {
        const toggle = h("button", { class: "btn", type: "button" }, c.active ? "Deactivate" : "Activate");
        toggle.addEventListener("click", async () => {
          const message = c.active
            ? `Deactivate ${c.code}? Inactive controls no longer reduce residual risk; ${c.implemented_link_count} implemented link(s) will be recalculated.`
            : `Activate ${c.code}? Its implemented links will reduce residual risk again.`;
          if (!(await confirmDialog({ title: `${c.active ? "Deactivate" : "Activate"} ${c.code}`, message, confirmLabel: c.active ? "Deactivate" : "Activate" }))) return;
          withBusy(toggle, async () => {
            try {
              await api.patch(`/controls/${c.id}`, { active: !c.active });
              toast({ type: "success", title: `${c.code} ${c.active ? "deactivated" : "activated"}`, message: "Residual risk recalculated." });
              bus.emit("data-changed", { entity: "control" });
              ctx.reload();
            } catch (err) { toastError(err); }
          });
        });
        ctx.setFooter(toggle, h("button", { class: "btn btn-primary", type: "button", onclick: () => openControlForm({ control: c, onSaved: () => ctx.reload() }) }, icon("edit"), "Edit"));
      } else {
        ctx.setFooter(readOnlyNote());
      }
      return [
        h("div", { class: "callout callout-info" }, icon("info"), h("div", {},
          `A ${c.control_type.toLowerCase()} control ${AXIS_TEXT[c.axis]} by 1 level (Partial) or 2 levels (Substantial) on risks where it is Implemented. Only the strongest control per axis counts.`)),
        section("Description", h("p", { style: { lineHeight: 1.6 } }, c.description)),
        section("Details", kv([
          ["Type", `${c.control_type} (${AXIS_TEXT[c.axis]})`],
          ["Category", c.category],
          ["Status", activeBadge(c.active)],
          ["Linked risks", `${c.linked_risk_count} (${c.implemented_link_count} implemented)`],
          ["Addresses", c.vulnerabilities.length
            ? h("span", {}, c.vulnerabilities.map((v, i) => [i ? ", " : "",
              h("button", { class: "link-btn", type: "button", onclick: () => openVulnerabilityDrawer(v.id) }, `${v.code} ${v.name}`)]))
            : h("span", { class: "dim" }, "No specific vulnerability")],
          ["Updated", fmtDateTime(c.updated_at)],
        ])),
        section(`Linked risks (${risks.total})`, risks.items.length
          ? h("div", { class: "card-list" }, risks.items.map(riskCard))
          : emptyState({ title: "Not linked to any risk", compact: true })),
      ];
    },
  });
}
