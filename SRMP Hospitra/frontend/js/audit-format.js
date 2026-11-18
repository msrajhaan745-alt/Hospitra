// Human-readable descriptions for audit entries (shared by Command Centre and Reports & Audit).
import { shortId } from "./core/format.js";

const ACTION_TEXT = {
  "asset.created": (d) => `Asset ${d.asset_tag} created`,
  "asset.updated": (d) => `Asset ${d.asset_tag} updated (${Object.keys(d.changes || {}).join(", ")})`,
  "threat.created": (d) => `Threat ${d.code} created (${d.source_type})`,
  "threat.updated": (d) => `Threat ${d.code} updated (${Object.keys(d.changes || {}).join(", ")})`,
  "vulnerability.created": (d) => `Vulnerability ${d.code} created (${d.source_type})`,
  "vulnerability.updated": (d) => `Vulnerability ${d.code} updated (${Object.keys(d.changes || {}).join(", ")})`,
  "risk.created": (d) => `Risk ${d.reference} created — score ${d.risk_score} (${d.severity})`,
  "risk.updated": (d) => `Risk ${d.reference} updated${d.recalculated ? ` — score ${d.recalculated.risk_score.from} → ${d.recalculated.risk_score.to}` : ""}`,
  "event.created": (d) => `${capitalise(String(d.event_type).replaceAll("_", " "))} event (${d.scenario_id}, Branch ${d.branch})`,
  "detection.matched": (d) => `Rule ${d.rule_id} matched (${d.severity})`,
  "detection.no_match": (d) => `Rule ${d.rule_id} evaluated — no match`,
  "incident.created": (d) => `${d.incident_number} opened (${d.severity}, rule ${d.rule_id})`,
  "incident.status_changed": (d) => `${d.incident_number}: ${d.from} → ${d.to}`,
  "incident.assigned": (d) => `${d.incident_number} assigned to ${d.to || "nobody"}`,
  "incident.note_added": (d) => `${d.incident_number}: ${d.note_type} note added`,
  "simulation.triggered": (d) => `Scenario ${d.scenario_id} triggered on Branch ${d.branch} — ${d.event_count} event(s), ${d.matched_detections} match(es)`,
  "seed.applied": () => "Dataset seeded",
  "data.reset": () => "Data reset and reseeded",
  "demo.reset": () => "Data reset and reseeded", // entries written before the rename
  // V2
  "control.created": (d) => `Control ${d.code} created (${d.control_type})`,
  "control.updated": (d) => `Control ${d.code} updated (${Object.keys(d.changes || {}).join(", ")})${d.residual_recalculated?.length ? ` — ${d.residual_recalculated.length} risk(s) recalculated` : ""}`,
  "risk.control_linked": (d) => `${d.control} linked to ${d.reference} (${d.implementation_status}, ${d.effectiveness})${residualText(d)}`,
  "risk.control_updated": (d) => `${d.control} on ${d.reference} updated (${Object.keys(d.changes || {}).join(", ")})${residualText(d)}`,
  "risk.control_unlinked": (d) => `${d.control} unlinked from ${d.reference}${residualText(d)}`,
  "auth.login": (d) => `${d.username} signed in`,
  "auth.logout": (d) => `${d.username} signed out`,
  "auth.login_failed": (d) => `Failed sign-in attempt for '${d.username}'`,
  "user.bootstrap": (d) => `First administrator '${d.username}' created`,
  "user.created": (d) => `User '${d.username}' created (${d.role})`,
  "user.updated": (d) => `User '${d.username}' updated (${Object.keys(d.changes || {}).join(", ")})`,
  "user.password_changed": (d) => `${d.username} changed their password`,
};

function capitalise(text) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function residualText(d) {
  const r = d.recalculated?.residual_score;
  return r ? ` — residual ${r.from} → ${r.to}` : "";
}

export function describeAudit(entry) {
  const fn = ACTION_TEXT[entry.action];
  try {
    if (fn) return fn(entry.details || {});
  } catch { /* fall through to generic text */ }
  return `${entry.action} ${entry.entity_type}${entry.entity_id ? ` ${shortId(entry.entity_id)}` : ""}`;
}

export function auditTone(action) {
  if (action.startsWith("incident.")) return { cls: "t-incident", icon: "siren" };
  if (action === "detection.matched") return { cls: "t-detection", icon: "alert" };
  if (action.startsWith("detection.")) return { cls: "", icon: "check" };
  if (action.startsWith("simulation.") || action.startsWith("event.")) return { cls: "t-sim", icon: "flask" };
  if (action.startsWith("risk.control")) return { cls: "t-ok", icon: "shield" };
  if (action.startsWith("risk.")) return { cls: "", icon: "list" };
  if (action.startsWith("asset.")) return { cls: "t-ok", icon: "server" };
  if (action.startsWith("data.") || action.startsWith("demo.") || action.startsWith("seed.")) return { cls: "", icon: "reset" };
  if (action.startsWith("control.")) return { cls: "t-ok", icon: "shield" };
  if (action === "auth.login_failed") return { cls: "t-detection", icon: "lock" };
  if (action.startsWith("auth.") || action.startsWith("user.")) return { cls: "", icon: "user" };
  return { cls: "", icon: "info" };
}
