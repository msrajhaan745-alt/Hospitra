// Filter and form controls.
import { debounce, h } from "./dom.js";
import { icon } from "./icons.js";

export function searchInput({ placeholder = "Search…", value = "", onInput, label = "Search" }) {
  const input = h("input", { class: "input", type: "search", placeholder, value, "aria-label": label, autocomplete: "off" });
  input.addEventListener("input", debounce(() => onInput(input.value.trim()), 280));
  return h("div", { class: "search-box" }, icon("search"), input);
}

/** options: [{value, label}] or strings. `allLabel` adds an empty "all" option. */
export function selectInput({ options, value = "", onChange, label, allLabel, id, name, required = false }) {
  const select = h("select", { class: "select", "aria-label": label, id, name, required });
  if (allLabel !== undefined) select.append(h("option", { value: "" }, allLabel));
  for (const opt of options) {
    const o = typeof opt === "string" ? { value: opt, label: opt } : opt;
    if (o.group) {
      const og = h("optgroup", { label: o.group });
      for (const sub of o.options) og.append(h("option", { value: sub.value }, sub.label));
      select.append(og);
    } else {
      select.append(h("option", { value: o.value }, o.label));
    }
  }
  select.value = value ?? "";
  if (onChange) select.addEventListener("change", () => onChange(select.value));
  return select;
}

export function dateInput({ value = "", onChange, label }) {
  const input = h("input", { class: "input", type: "date", value, "aria-label": label, style: { width: "150px" } });
  input.addEventListener("change", () => onChange(input.value));
  return input;
}

/** Labelled form field with an error slot. */
export function field({ label, control, required = false, hint, span2 = false, id }) {
  const labelable = Boolean(control.matches?.("input, select, textarea"));
  if (labelable && !control.id) control.id = id || `f-${Math.random().toString(36).slice(2, 9)}`;
  const error = h("div", { class: "field-error", role: "alert" });
  error.hidden = true;
  const el = h("div", { class: `field${span2 ? " span-2" : ""}` },
    h(labelable ? "label" : "div", { class: labelable ? null : "field-label", for: labelable ? control.id : null },
      label, required ? h("span", { class: "req", "aria-hidden": "true" }, "*") : null),
    control,
    hint ? h("div", { class: "field-hint" }, hint) : null,
    error);
  return {
    el,
    setError(message) {
      error.textContent = message || "";
      error.hidden = !message;
      const target = control.matches?.("input, select, textarea") ? control : control.querySelector?.("input, select, textarea, button");
      target?.setAttribute("aria-invalid", message ? "true" : "false");
    },
  };
}

/** Segmented 1–5 rating control (radiogroup). */
export function ratingInput({ value = null, label, onChange }) {
  let current = value;
  const group = h("div", { class: "rating", role: "radiogroup", "aria-label": label });
  const buttons = [1, 2, 3, 4, 5].map((n) => {
    const b = h("button", { type: "button", role: "radio", "aria-checked": String(n === current), "aria-label": `${label}: ${n}` }, String(n));
    b.addEventListener("click", () => set(n));
    b.addEventListener("keydown", (ev) => {
      if (ev.key === "ArrowRight" || ev.key === "ArrowUp") { ev.preventDefault(); set(Math.min(5, (current || 0) + 1)); buttons[current - 1].focus(); }
      if (ev.key === "ArrowLeft" || ev.key === "ArrowDown") { ev.preventDefault(); set(Math.max(1, (current || 2) - 1)); buttons[current - 1].focus(); }
    });
    return b;
  });
  group.append(...buttons);
  function set(n) {
    current = n;
    buttons.forEach((b, i) => b.setAttribute("aria-checked", String(i + 1 === n)));
    onChange?.(n);
  }
  return { el: group, get value() { return current; }, set };
}

/** Map an ApiError's field errors onto field handles; returns messages that had no field. */
export function applyFieldErrors(err, fields) {
  const unmatched = [];
  for (const f of Object.values(fields)) f.setError("");
  const fieldErrors = err?.fieldErrors || {};
  for (const [name, message] of Object.entries(fieldErrors)) {
    if (fields[name]) fields[name].setError(message);
    else unmatched.push(`${name}: ${message}`);
  }
  return unmatched;
}
