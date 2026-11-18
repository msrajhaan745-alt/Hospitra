// Create/edit forms (modals). The server is authoritative for validation; client checks are
// only for fast feedback. Derived risk values are never sent or computed here.
import { api } from "./core/api.js";
import { applyFieldErrors, field, ratingInput, selectInput } from "./core/controls.js";
import { h } from "./core/dom.js";
import { bus, state, zonesForBranch } from "./core/state.js";
import { openModal, toast, withBusy } from "./core/ui.js";

const ASSET_TYPES = ["Network Device", "Server", "Database Server", "Workstation", "Medical Device", "Access Point",
  "Endpoint", "Security Appliance", "Web Server", "VPN Gateway"];
const CRITICALITY = ["Low", "Medium", "High", "Critical"];
const CLASSIFICATION = ["Public", "Internal", "Confidential", "Restricted"];
const ASSET_STATUS = ["Active", "Warning", "Offline", "Maintenance"];
const TREATMENTS = ["Mitigate", "Accept", "Transfer", "Avoid"];
const RISK_STATUS = ["Open", "In Treatment", "Closed"];

const TAG_RE = /^[A-Za-z0-9][A-Za-z0-9-]{2,31}$/;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function textInput(value = "", attrs = {}) {
  return h("input", { class: "input", type: "text", value: value ?? "", autocomplete: "off", ...attrs });
}

function errorBanner() {
  const el = h("div", { class: "form-error-banner", role: "alert" });
  el.hidden = true;
  return {
    el,
    show(msg) { el.textContent = msg; el.hidden = !msg; },
  };
}

function diff(original, next) {
  const out = {};
  for (const [k, v] of Object.entries(next)) if (original[k] !== v) out[k] = v;
  return out;
}

/* ---------------- Asset ---------------- */
export function openAssetForm({ asset = null, onSaved } = {}) {
  const editing = Boolean(asset);
  const branchOptions = state.branches.map((b) => ({ value: b.id, label: b.name }));
  const initialBranch = asset?.branch_id || state.branchId || state.branches[0]?.id || "";

  const c = {
    asset_tag: textInput(asset?.asset_tag, { placeholder: "HSP-A-CLN-003", maxlength: "32" }),
    name: textInput(asset?.name, { maxlength: "120" }),
    asset_type: selectInput({ options: ASSET_TYPES, value: asset?.asset_type || "", allLabel: "Select type…", label: "Asset type" }),
    branch_id: selectInput({ options: branchOptions, value: initialBranch, label: "Branch" }),
    zone_id: selectInput({ options: [], label: "Zone" }),
    ip_address: textInput(asset?.ip_address, { placeholder: "10.20.30.40", inputmode: "decimal" }),
    operating_system: textInput(asset?.operating_system, { maxlength: "80" }),
    owner: textInput(asset?.owner, { maxlength: "120" }),
    criticality: selectInput({ options: CRITICALITY, value: asset?.criticality || "", allLabel: "Select…", label: "Criticality" }),
    data_classification: selectInput({ options: CLASSIFICATION, value: asset?.data_classification || "", allLabel: "Select…", label: "Data classification" }),
    status: selectInput({ options: ASSET_STATUS, value: asset?.status || "Active", label: "Status" }),
  };
  const cia = {
    confidentiality: ratingInput({ value: asset?.confidentiality ?? null, label: "Confidentiality" }),
    integrity: ratingInput({ value: asset?.integrity ?? null, label: "Integrity" }),
    availability: ratingInput({ value: asset?.availability ?? null, label: "Availability" }),
  };
  const subnetHint = h("span");

  function fillZones(branchId, selected) {
    const zones = zonesForBranch(branchId);
    c.zone_id.replaceChildren(h("option", { value: "" }, "Select zone…"),
      ...zones.map((z) => h("option", { value: z.id }, `VLAN ${z.vlan_id} · ${z.name}`)));
    c.zone_id.value = selected && zones.some((z) => z.id === selected) ? selected : "";
    updateHint();
  }
  function updateHint() {
    const zone = state.zones.find((z) => z.id === c.zone_id.value);
    subnetHint.textContent = zone ? `Must be inside ${zone.subnet_cidr}` : "Select a zone to see its subnet.";
  }
  c.branch_id.addEventListener("change", () => fillZones(c.branch_id.value, null));
  c.zone_id.addEventListener("change", updateHint);
  fillZones(initialBranch, asset?.zone_id);

  const f = {
    asset_tag: field({ label: "Asset tag", control: c.asset_tag, required: true, hint: "Unique. Letters, digits and hyphens." }),
    name: field({ label: "Name", control: c.name, required: true }),
    asset_type: field({ label: "Asset type", control: c.asset_type, required: true }),
    owner: field({ label: "Owner", control: c.owner, required: true }),
    branch_id: field({ label: "Branch", control: c.branch_id, required: true }),
    zone_id: field({ label: "Security zone", control: c.zone_id, required: true }),
    ip_address: field({ label: "IP address", control: c.ip_address, required: true, hint: subnetHint }),
    operating_system: field({ label: "Operating system", control: c.operating_system }),
    criticality: field({ label: "Criticality", control: c.criticality, required: true }),
    data_classification: field({ label: "Data classification", control: c.data_classification, required: true }),
    status: field({ label: "Status", control: c.status, required: true }),
    confidentiality: field({ label: "Confidentiality (1–5)", control: cia.confidentiality.el, required: true }),
    integrity: field({ label: "Integrity (1–5)", control: cia.integrity.el, required: true }),
    availability: field({ label: "Availability (1–5)", control: cia.availability.el, required: true }),
  };
  const banner = errorBanner();
  const body = h("form", { class: "stack", novalidate: true, onsubmit: (ev) => ev.preventDefault() },
    banner.el,
    h("div", { class: "form-grid" }, Object.values(f).map((x) => x.el)),
    h("p", { class: "field-hint" }, "Data classification is recorded separately from the CIA ratings."));

  function collect() {
    return {
      asset_tag: c.asset_tag.value.trim().toUpperCase(),
      name: c.name.value.trim(),
      asset_type: c.asset_type.value,
      branch_id: c.branch_id.value,
      zone_id: c.zone_id.value,
      ip_address: c.ip_address.value.trim(),
      operating_system: c.operating_system.value.trim(),
      owner: c.owner.value.trim(),
      criticality: c.criticality.value,
      data_classification: c.data_classification.value,
      status: c.status.value,
      confidentiality: cia.confidentiality.value,
      integrity: cia.integrity.value,
      availability: cia.availability.value,
    };
  }

  function validate(data) {
    const errors = {};
    for (const key of ["asset_tag", "name", "asset_type", "branch_id", "zone_id", "ip_address", "owner", "criticality",
      "data_classification", "status", "confidentiality", "integrity", "availability"]) {
      if (data[key] === "" || data[key] === null || data[key] === undefined) errors[key] = "Required.";
    }
    if (data.asset_tag && !TAG_RE.test(data.asset_tag)) errors.asset_tag = "3–32 characters: letters, digits and hyphens.";
    if (data.ip_address && !IPV4_RE.test(data.ip_address)) errors.ip_address = "Enter a valid IPv4 address.";
    for (const [k, fh] of Object.entries(f)) fh.setError(errors[k] || "");
    return !Object.keys(errors).length;
  }

  openModal({
    title: editing ? `Edit asset ${asset.asset_tag}` : "New asset",
    body,
    actions: [
      { label: "Cancel", variant: "btn-ghost", onClick: ({ close }) => close() },
      {
        label: editing ? "Save changes" : "Create asset", variant: "btn-primary", submit: true,
        onClick: ({ close, button }) => {
          banner.show("");
          const data = collect();
          if (!validate(data)) { banner.show("Please correct the highlighted fields."); return; }
          withBusy(button, async () => {
            try {
              let saved;
              if (editing) {
                const changes = diff(asset, data);
                if (!Object.keys(changes).length) { close(); toast({ type: "info", title: "No changes to save" }); return; }
                saved = await api.patch(`/assets/${asset.id}`, changes);
              } else {
                saved = await api.post("/assets", data);
              }
              close();
              toast({ type: "success", title: editing ? "Asset updated" : "Asset created", message: `${saved.asset_tag} · ${saved.name}` });
              bus.emit("data-changed", { entity: "asset", id: saved.id });
              onSaved?.(saved);
            } catch (err) {
              const unmatched = applyFieldErrors(err, f);
              banner.show(unmatched.length ? `${err.message} ${unmatched.join(" ")}` : err.message);
            }
          });
        },
      },
    ],
  });
}

/* ---------------- Risk ---------------- */
export async function openRiskForm({ risk = null, presetAssetId = null, onSaved } = {}) {
  const editing = Boolean(risk);
  let assets = [];
  let threats = [];
  let vulns = [];
  try {
    const [a, t, v] = await Promise.all([
      editing ? Promise.resolve({ items: [] }) : api.get("/assets", { limit: 200, sort: "asset_tag" }),
      editing ? Promise.resolve({ items: [] }) : api.get("/threats", { limit: 200, active: true }),
      editing ? Promise.resolve({ items: [] }) : api.get("/vulnerabilities", { limit: 200, active: true }),
    ]);
    assets = a.items; threats = t.items; vulns = v.items;
  } catch (err) {
    toast({ type: "error", title: "Could not load form data", message: err.message });
    return;
  }

  const ratings = {
    likelihood: ratingInput({ value: risk?.likelihood ?? null, label: "Likelihood" }),
    confidentiality_impact: ratingInput({ value: risk?.confidentiality_impact ?? null, label: "Confidentiality impact" }),
    integrity_impact: ratingInput({ value: risk?.integrity_impact ?? null, label: "Integrity impact" }),
    availability_impact: ratingInput({ value: risk?.availability_impact ?? null, label: "Availability impact" }),
  };
  const treatment = selectInput({ options: TREATMENTS, value: risk?.treatment || "", allLabel: "Select…", label: "Treatment" });
  const status = selectInput({ options: RISK_STATUS, value: risk?.status || "Open", label: "Status" });
  const owner = textInput(risk?.owner, { maxlength: "120" });

  const f = {};
  let assetSel; let threatSel; let vulnSel;
  if (editing) {
    f.context = field({ label: "Asset · Threat · Vulnerability (fixed)", span2: true,
      control: h("div", { class: "mini-card" }, h("div", { class: "title" }, `${risk.asset.asset_tag} — ${risk.asset.name}`),
        h("div", { class: "desc" }, `${risk.threat.code} ${risk.threat.name} × ${risk.vulnerability.code} ${risk.vulnerability.name}`)) });
  } else {
    const groups = state.branches.map((b) => ({
      group: b.name,
      options: assets.filter((a) => a.branch_id === b.id).map((a) => ({ value: a.id, label: `${a.asset_tag} — ${a.name}` })),
    }));
    assetSel = selectInput({ options: groups, value: presetAssetId || "", allLabel: "Select asset…", label: "Asset" });
    threatSel = selectInput({ options: threats.map((t) => ({ value: t.id, label: `${t.code} — ${t.name}${t.source_type === "Proposed" ? " (proposed)" : ""}` })), allLabel: "Select threat…", label: "Threat" });
    vulnSel = selectInput({ options: [], label: "Vulnerability" });
    const pairingNote = h("span");
    const relabel = () => {
      const threat = threats.find((t) => t.id === threatSel.value);
      const paired = new Set((threat?.related_vulnerabilities || []).map((p) => p.id));
      const current = vulnSel.value;
      vulnSel.replaceChildren(h("option", { value: "" }, "Select vulnerability…"),
        ...vulns.map((v) => h("option", { value: v.id }, `${v.code} — ${v.name}${paired.has(v.id) ? "  ✓ documented pairing" : ""}`)));
      vulnSel.value = current;
      const pair = threat?.related_vulnerabilities.find((p) => p.id === vulnSel.value);
      pairingNote.textContent = !threat || !vulnSel.value ? "Documented, plausible pairings are marked ✓."
        : pair ? `Rationale: ${pair.rationale}` : "No documented pairing for this combination — it will be recorded as a proposed relationship.";
    };
    threatSel.addEventListener("change", relabel);
    vulnSel.addEventListener("change", relabel);
    relabel();
    f.asset_id = field({ label: "Asset", control: assetSel, required: true, span2: true });
    f.threat_id = field({ label: "Threat", control: threatSel, required: true });
    f.vulnerability_id = field({ label: "Vulnerability", control: vulnSel, required: true });
    f.pairing = field({ label: "Pairing", control: h("div", { class: "field-hint", style: { fontSize: "12px" } }, pairingNote), span2: true });
  }
  f.likelihood = field({ label: "Likelihood (1–5)", control: ratings.likelihood.el, required: true });
  f.confidentiality_impact = field({ label: "Confidentiality impact (1–5)", control: ratings.confidentiality_impact.el, required: true });
  f.integrity_impact = field({ label: "Integrity impact (1–5)", control: ratings.integrity_impact.el, required: true });
  f.availability_impact = field({ label: "Availability impact (1–5)", control: ratings.availability_impact.el, required: true });
  f.treatment = field({ label: "Treatment", control: treatment, required: true });
  f.status = field({ label: "Status", control: status, required: true });
  f.owner = field({ label: "Owner", control: owner, required: true, span2: true });

  const banner = errorBanner();
  const body = h("form", { class: "stack", novalidate: true, onsubmit: (ev) => ev.preventDefault() },
    banner.el,
    h("div", { class: "callout callout-info" }, h("div", {},
      "Impact, score and severity are calculated by the server when you save: Score = Likelihood × max(C, I, A). ",
      "Bands: 1–4 Low · 5–9 Moderate · 10–16 High · 17–25 Critical.")),
    h("div", { class: "form-grid" }, Object.values(f).map((x) => x.el)));

  function collect() {
    const data = {
      likelihood: ratings.likelihood.value,
      confidentiality_impact: ratings.confidentiality_impact.value,
      integrity_impact: ratings.integrity_impact.value,
      availability_impact: ratings.availability_impact.value,
      treatment: treatment.value,
      status: status.value,
      owner: owner.value.trim(),
    };
    if (!editing) Object.assign(data, { asset_id: assetSel.value, threat_id: threatSel.value, vulnerability_id: vulnSel.value });
    return data;
  }

  openModal({
    title: editing ? `Edit risk ${risk.reference}` : "New risk",
    body,
    actions: [
      { label: "Cancel", variant: "btn-ghost", onClick: ({ close }) => close() },
      {
        label: editing ? "Save changes" : "Create risk", variant: "btn-primary", submit: true,
        onClick: ({ close, button }) => {
          banner.show("");
          const data = collect();
          let ok = true;
          for (const [k, v] of Object.entries(data)) {
            const missing = v === "" || v === null || v === undefined;
            f[k]?.setError(missing ? "Required." : "");
            if (missing) ok = false;
          }
          if (!ok) { banner.show("Please complete the highlighted fields."); return; }
          withBusy(button, async () => {
            try {
              let saved;
              if (editing) {
                const changes = diff(risk, data);
                if (!Object.keys(changes).length) { close(); toast({ type: "info", title: "No changes to save" }); return; }
                saved = await api.patch(`/risks/${risk.id}`, changes);
              } else {
                saved = await api.post("/risks", data);
              }
              close();
              toast({ type: "success", title: editing ? "Risk updated" : "Risk created",
                message: `${saved.reference}: score ${saved.risk_score} (${saved.severity}) — ${saved.calculation.score_expression}` });
              bus.emit("data-changed", { entity: "risk", id: saved.id });
              onSaved?.(saved);
            } catch (err) {
              const unmatched = applyFieldErrors(err, f);
              banner.show(unmatched.length ? `${err.message} ${unmatched.join(" ")}` : err.message);
            }
          });
        },
      },
    ],
  });
}

/* ---------------- Security control (V2) ---------------- */
export async function openControlForm({ control = null, onSaved } = {}) {
  const editing = Boolean(control);
  let vulns = [];
  let categories = [];
  try {
    [vulns, categories] = await Promise.all([
      api.get("/vulnerabilities", { limit: 200 }).then((r) => r.items),
      api.get("/controls/categories"),
    ]);
  } catch (err) {
    toast({ type: "error", title: "Could not load form data", message: err.message });
    return;
  }
  const code = textInput(control?.code, { maxlength: "16", placeholder: "C13", disabled: editing });
  const name = textInput(control?.name, { maxlength: "120" });
  const type = selectInput({ options: [
    { value: "Preventive", label: "Preventive — lowers likelihood" },
    { value: "Detective", label: "Detective — lowers impact" },
    { value: "Corrective", label: "Corrective — lowers impact" },
  ], value: control?.control_type || "", allLabel: "Select type…", label: "Control type" });
  const listId = `cat-${Math.random().toString(36).slice(2, 8)}`;
  const category = textInput(control?.category, { maxlength: "60", list: listId });
  const datalist = h("datalist", { id: listId }, categories.map((c) => h("option", { value: c })));
  const description = h("textarea", { class: "textarea", rows: "4", maxlength: "4000" });
  description.value = control?.description || "";
  const selected = new Set((control?.vulnerabilities || []).map((v) => v.id));
  const vulnBoxes = h("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px 12px" } },
    vulns.map((v) => {
      const cb = h("input", { type: "checkbox", value: v.id, checked: selected.has(v.id) });
      return h("label", { style: { display: "flex", gap: "6px", alignItems: "flex-start", fontSize: "12.5px", cursor: "pointer" } },
        cb, h("span", {}, h("span", { class: "mono" }, v.code), ` ${v.name}`));
    }));

  const f = {
    code: field({ label: "Code", control: code, required: true, hint: editing ? "Codes cannot be changed." : "Unique, e.g. C13." }),
    control_type: field({ label: "Control type", control: type, required: true, hint: "Determines which risk axis it reduces." }),
    name: field({ label: "Name", control: name, required: true, span2: true }),
    category: field({ label: "Category", control: h("div", {}, category, datalist), required: true, span2: true }),
    description: field({ label: "Description", control: description, required: true, span2: true }),
    vulnerability_ids: field({ label: "Addresses vulnerabilities (used to suggest the control)", control: vulnBoxes, span2: true }),
  };
  const banner = errorBanner();
  const body = h("form", { class: "stack", novalidate: true, onsubmit: (ev) => ev.preventDefault() },
    banner.el,
    editing && control.linked_risk_count
      ? h("div", { class: "callout callout-info" }, h("div", {}, `Changing the type recalculates residual risk on the ${control.linked_risk_count} linked risk(s).`))
      : null,
    h("div", { class: "form-grid" }, Object.values(f).map((x) => x.el)));

  openModal({
    title: editing ? `Edit control ${control.code}` : "New security control",
    body,
    actions: [
      { label: "Cancel", variant: "btn-ghost", onClick: ({ close }) => close() },
      {
        label: editing ? "Save changes" : "Create control", variant: "btn-primary", submit: true,
        onClick: ({ close, button }) => {
          banner.show("");
          const data = {
            name: name.value.trim(), control_type: type.value, category: category.value.trim(), description: description.value.trim(),
            vulnerability_ids: [...vulnBoxes.querySelectorAll("input:checked")].map((cb) => cb.value),
          };
          if (!editing) data.code = code.value.trim().toUpperCase();
          let ok = true;
          for (const k of ["code", "name", "control_type", "category", "description"]) {
            if (k === "code" && editing) continue;
            f[k].setError(data[k] ? "" : "Required.");
            if (!data[k]) ok = false;
          }
          if (!ok) { banner.show("Please complete the highlighted fields."); return; }
          withBusy(button, async () => {
            try {
              let saved;
              if (editing) {
                const changes = diff(control, data);
                const before = [...selected].sort().join(",");
                if (before === [...data.vulnerability_ids].sort().join(",")) delete changes.vulnerability_ids;
                if (!Object.keys(changes).length) { close(); toast({ type: "info", title: "No changes to save" }); return; }
                saved = await api.patch(`/controls/${control.id}`, changes);
              } else {
                saved = await api.post("/controls", data);
              }
              close();
              toast({ type: "success", title: editing ? "Control updated" : "Control created", message: `${saved.code} — ${saved.name}` });
              bus.emit("data-changed", { entity: "control", id: saved.id });
              onSaved?.(saved);
            } catch (err) {
              const unmatched = applyFieldErrors(err, f);
              banner.show(unmatched.length ? `${err.message} ${unmatched.join(" ")}` : err.message);
            }
          });
        },
      },
    ],
  });
}

/* ---------------- User (V2, Admin) ---------------- */
export function openUserForm({ user = null, onSaved } = {}) {
  const editing = Boolean(user);
  const isSelf = editing && user.id === state.user?.id;
  const username = textInput(user?.username, { maxlength: "40", disabled: editing, autocomplete: "off" });
  const displayName = textInput(user?.display_name, { maxlength: "80" });
  const role = selectInput({ options: [
    { value: "Viewer", label: "Viewer — read and export" },
    { value: "Analyst", label: "Analyst — read, export and operate" },
    { value: "Admin", label: "Admin — everything, incl. users and reset" },
  ], value: user?.role || "Viewer", label: "Role" });
  const active = selectInput({ options: [{ value: "true", label: "Active" }, { value: "false", label: "Deactivated" }],
    value: String(user?.active ?? true), label: "Status" });
  active.disabled = !editing || isSelf;
  const password = h("input", { class: "input", type: "password", autocomplete: "new-password", maxlength: "128" });
  const f = {
    username: field({ label: "Username", control: username, required: true, hint: editing ? "Usernames cannot be changed (audit identity)." : "3–40 characters: a–z, 0–9, '.', '_' or '-'." }),
    display_name: field({ label: "Display name", control: displayName, required: true }),
    role: field({ label: "Role", control: role, required: true }),
    active: field({ label: "Status", control: active, hint: isSelf ? "You cannot deactivate yourself." : null }),
    password: field({ label: editing ? "Reset password (optional)" : "Initial password", control: password, required: !editing, span2: true,
      hint: "At least 10 characters. Share it securely; the user can change it after signing in." }),
  };
  const banner = errorBanner();
  const body = h("form", { class: "stack", novalidate: true, onsubmit: (ev) => ev.preventDefault() }, banner.el,
    editing ? h("div", { class: "callout callout-info" }, h("div", {}, "Changing the role, deactivating or resetting the password signs the user out of all sessions.")) : null,
    h("div", { class: "form-grid" }, Object.values(f).map((x) => x.el)));

  openModal({
    title: editing ? `Edit user ${user.username}` : "New user",
    body,
    actions: [
      { label: "Cancel", variant: "btn-ghost", onClick: ({ close }) => close() },
      {
        label: editing ? "Save changes" : "Create user", variant: "btn-primary", submit: true,
        onClick: ({ close, button }) => {
          banner.show("");
          Object.values(f).forEach((x) => x.setError(""));
          withBusy(button, async () => {
            try {
              let saved;
              if (editing) {
                const changes = diff(user, { display_name: displayName.value.trim(), role: role.value, active: active.value === "true" });
                if (password.value) changes.password = password.value;
                if (!Object.keys(changes).length) { close(); toast({ type: "info", title: "No changes to save" }); return; }
                saved = await api.patch(`/users/${user.id}`, changes);
              } else {
                saved = await api.post("/users", { username: username.value.trim(), display_name: displayName.value.trim(),
                  role: role.value, password: password.value });
              }
              close();
              toast({ type: "success", title: editing ? "User updated" : "User created", message: `${saved.username} · ${saved.role}` });
              onSaved?.(saved);
            } catch (err) {
              const unmatched = applyFieldErrors(err, f);
              banner.show(unmatched.length ? `${err.message} ${unmatched.join(" ")}` : err.message);
            }
          });
        },
      },
    ],
  });
}

/* ---------------- Threat / vulnerability ---------------- */
export function openCatalogueForm({ kind, record = null, onSaved } = {}) {
  const isThreat = kind === "threat";
  const editing = Boolean(record);
  const path = isThreat ? "/threats" : "/vulnerabilities";
  const typeKey = isThreat ? "category" : "weakness_type";

  const code = textInput(record?.code, { maxlength: "16", placeholder: isThreat ? "T9" : "V9", disabled: editing });
  const name = textInput(record?.name, { maxlength: "120" });
  const type = textInput(record?.[typeKey], { maxlength: "60" });
  const description = h("textarea", { class: "textarea", rows: "5", maxlength: "4000" });
  description.value = record?.description || "";
  const source = selectInput({ options: [{ value: "Proposed", label: "Proposed (additional scenario)" }, { value: "Case Study", label: "Case study (initial)" }],
    value: record?.source_type || "Proposed", label: "Source" });
  source.disabled = editing;

  const f = {
    code: field({ label: "Code", control: code, required: true, hint: editing ? "Codes cannot be changed." : "Unique, e.g. T9." }),
    source_type: field({ label: "Source", control: source, hint: editing ? "Fixed at creation." : "New entries are normally Proposed." }),
    name: field({ label: "Name", control: name, required: true, span2: true }),
    [typeKey]: field({ label: isThreat ? "Category" : "Weakness type", control: type, required: true, span2: true }),
    description: field({ label: "Description", control: description, required: true, span2: true,
      hint: "Explain the weakness/threat and its relevance to the hospital environment." }),
  };
  const banner = errorBanner();
  const body = h("form", { class: "stack", novalidate: true, onsubmit: (ev) => ev.preventDefault() },
    banner.el, h("div", { class: "form-grid" }, Object.values(f).map((x) => x.el)));

  openModal({
    title: editing ? `Edit ${record.code}` : `New ${isThreat ? "threat" : "vulnerability"}`,
    body,
    actions: [
      { label: "Cancel", variant: "btn-ghost", onClick: ({ close }) => close() },
      {
        label: editing ? "Save changes" : "Create", variant: "btn-primary", submit: true,
        onClick: ({ close, button }) => {
          banner.show("");
          const data = { name: name.value.trim(), description: description.value.trim(), [typeKey]: type.value.trim() };
          if (!editing) Object.assign(data, { code: code.value.trim().toUpperCase(), source_type: source.value });
          let ok = true;
          for (const [k, v] of Object.entries(data)) { f[k]?.setError(v ? "" : "Required."); if (!v) ok = false; }
          if (!ok) { banner.show("Please complete the highlighted fields."); return; }
          withBusy(button, async () => {
            try {
              let saved;
              if (editing) {
                const changes = diff(record, data);
                if (!Object.keys(changes).length) { close(); toast({ type: "info", title: "No changes to save" }); return; }
                saved = await api.patch(`${path}/${record.id}`, changes);
              } else {
                saved = await api.post(path, data);
              }
              close();
              toast({ type: "success", title: editing ? "Saved" : "Created", message: `${saved.code} — ${saved.name}` });
              bus.emit("data-changed", { entity: kind, id: saved.id });
              onSaved?.(saved);
            } catch (err) {
              const unmatched = applyFieldErrors(err, f);
              banner.show(unmatched.length ? `${err.message} ${unmatched.join(" ")}` : err.message);
            }
          });
        },
      },
    ],
  });
}
