// V2 authentication UI: first-run setup, sign-in, change password, sign-out.
// The session lives in an HttpOnly cookie set by the server; nothing is stored in JS.
import { api } from "./core/api.js";
import { applyFieldErrors, field } from "./core/controls.js";
import { clear, h } from "./core/dom.js";
import { openModal, toast, withBusy } from "./core/ui.js";

const root = () => document.getElementById("auth-root");

function brandPanel() {
  return h("div", { class: "auth-brand" },
    h("span", { "aria-hidden": "true", trustedHtml:
      '<svg class="brand-mark" viewBox="0 0 40 40">' +
      '<path d="M20 3l14 5v10c0 9-6 16.5-14 19C12 34.5 6 27 6 18V8z" fill="#122339" stroke="#2cc5cc" stroke-width="2"/>' +
      '<path d="M11 21h5l2.5-6 4 11 2.5-5H30" fill="none" stroke="#2cc5cc" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>' }),
    h("div", {}, h("div", { class: "brand-name" }, "Hospitra"), h("div", { class: "brand-sub" }, "Network Security & Risk Monitoring · v2")));
}

function input(type, attrs = {}) {
  return h("input", { class: "input", type, autocomplete: "off", ...attrs });
}

function screen(title, subtitle, form) {
  clear(root()).append(h("div", { class: "auth-screen" },
    h("div", { class: "auth-card", role: "dialog", "aria-modal": "true", "aria-labelledby": "auth-title" },
      brandPanel(),
      h("h1", { id: "auth-title" }, title),
      subtitle ? h("p", { class: "muted" }, subtitle) : null,
      form)));
  root().hidden = false;
  form.querySelector("input")?.focus();
}

function banner() {
  const el = h("div", { class: "form-error-banner", role: "alert" });
  el.hidden = true;
  return { el, show(msg) { el.textContent = msg || ""; el.hidden = !msg; } };
}

function loginForm(resolve) {
  const username = input("text", { autocomplete: "username", maxlength: "40", autocapitalize: "none" });
  const password = input("password", { autocomplete: "current-password", maxlength: "128" });
  const err = banner();
  const submit = h("button", { class: "btn btn-primary", type: "submit" }, "Sign in");
  const form = h("form", { class: "stack", novalidate: true },
    err.el,
    field({ label: "Username", control: username }).el,
    field({ label: "Password", control: password }).el,
    submit,
    h("p", { class: "dim", style: { fontSize: "12px" } }, "Accounts are created by an Administrator. Sessions expire 8 hours after sign-in (default)."));
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    err.show("");
    if (!username.value.trim() || !password.value) { err.show("Enter your username and password."); return; }
    withBusy(submit, async () => {
      try {
        const me = await api.post("/auth/login", { username: username.value.trim(), password: password.value });
        clear(root());
        root().hidden = true;
        resolve(me);
      } catch (e) {
        password.value = "";
        err.show(e.message);
        password.focus();
      }
    });
  });
  return form;
}

function bootstrapForm(resolve, minLength) {
  const c = {
    username: input("text", { autocomplete: "username", maxlength: "40", placeholder: "e.g. admin" }),
    display_name: input("text", { maxlength: "80", placeholder: "e.g. Security Administrator" }),
    password: input("password", { autocomplete: "new-password", maxlength: "128" }),
    confirm: input("password", { autocomplete: "new-password", maxlength: "128" }),
  };
  const f = {
    username: field({ label: "Username", control: c.username, required: true, hint: "3–40 characters: a–z, 0–9, '.', '_' or '-'." }),
    display_name: field({ label: "Display name", control: c.display_name, required: true }),
    password: field({ label: "Password", control: c.password, required: true, hint: `At least ${minLength} characters.` }),
    confirm: field({ label: "Repeat password", control: c.confirm, required: true }),
  };
  const err = banner();
  const submit = h("button", { class: "btn btn-primary", type: "submit" }, "Create administrator and sign in");
  const form = h("form", { class: "stack", novalidate: true }, err.el, ...Object.values(f).map((x) => x.el), submit);
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    err.show("");
    Object.values(f).forEach((x) => x.setError(""));
    if (c.password.value !== c.confirm.value) { f.confirm.setError("Passwords do not match."); return; }
    withBusy(submit, async () => {
      try {
        const me = await api.post("/auth/bootstrap", {
          username: c.username.value.trim(), display_name: c.display_name.value.trim(), password: c.password.value,
        });
        clear(root());
        root().hidden = true;
        toast({ type: "success", title: "Administrator created", message: `Signed in as ${me.username}.` });
        resolve(me);
      } catch (e) {
        const rest = applyFieldErrors(e, f);
        err.show(rest.length ? `${e.message} ${rest.join(" ")}` : e.message);
      }
    });
  });
  return form;
}

/** Resolves with the signed-in user, showing the setup or sign-in screen if needed. */
export async function ensureSignedIn() {
  // /auth/status is public and also reports whether this browser's session cookie is valid,
  // so a signed-out visitor does not trigger a 401.
  const status = await api.get("/auth/status");
  if (status.authenticated && status.user) return status.user;
  return new Promise((resolve) => {
    if (status.bootstrap_required) {
      screen("First-run setup", "No accounts exist yet. Create the first Administrator account. There are no default passwords.",
        bootstrapForm(resolve, status.password_min_length));
    } else {
      screen("Sign in", "Hospital Network Security & Risk Monitoring Platform", loginForm(resolve));
    }
  });
}

export async function signOut() {
  signingOut = true;
  try { await api.post("/auth/logout"); } catch { /* session may already be gone */ }
  // Reload without changing the route, so no view is mounted against the revoked session.
  location.reload();
}

let signingOut = false;
export const isSigningOut = () => signingOut;

export function openChangePassword() {
  const c = {
    current_password: input("password", { autocomplete: "current-password", maxlength: "128" }),
    new_password: input("password", { autocomplete: "new-password", maxlength: "128" }),
    confirm: input("password", { autocomplete: "new-password", maxlength: "128" }),
  };
  const f = {
    current_password: field({ label: "Current password", control: c.current_password, required: true }),
    new_password: field({ label: "New password", control: c.new_password, required: true, hint: "At least 10 characters." }),
    confirm: field({ label: "Repeat new password", control: c.confirm, required: true }),
  };
  const err = banner();
  openModal({
    title: "Change password",
    size: "small",
    body: h("form", { class: "stack", novalidate: true, onsubmit: (ev) => ev.preventDefault() }, err.el,
      ...Object.values(f).map((x) => x.el),
      h("p", { class: "dim", style: { fontSize: "12px" } }, "Your other signed-in sessions will be signed out.")),
    actions: [
      { label: "Cancel", variant: "btn-ghost", onClick: ({ close }) => close() },
      { label: "Change password", variant: "btn-primary", submit: true, onClick: ({ close, button }) => {
        err.show("");
        Object.values(f).forEach((x) => x.setError(""));
        if (c.new_password.value !== c.confirm.value) { f.confirm.setError("Passwords do not match."); return; }
        withBusy(button, async () => {
          try {
            await api.post("/auth/change-password", { current_password: c.current_password.value, new_password: c.new_password.value });
            close();
            toast({ type: "success", title: "Password changed", message: "Other sessions were signed out." });
          } catch (e) {
            const rest = applyFieldErrors(e, f);
            err.show(rest.length ? `${e.message} ${rest.join(" ")}` : e.message);
          }
        });
      } },
    ],
  });
}
