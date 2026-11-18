// User Management (V2, Admin only). The server enforces the Admin permission on every call.
import { api } from "../core/api.js";
import { h } from "../core/dom.js";
import { fmtDateTime, fmtRelative } from "../core/format.js";
import { icon } from "../core/icons.js";
import { state } from "../core/state.js";
import { createPager, createTable } from "../core/table.js";
import { activeBadge } from "../core/ui.js";
import { openUserForm } from "../forms.js";

const ROLE_TEXT = {
  Viewer: "Read everything and download exports",
  Analyst: "Viewer + simulations, incidents, assets, catalogue, risks and controls",
  Admin: "Analyst + user management and data reset",
};

export default {
  subtitle: "Accounts and roles · passwords are stored only as PBKDF2-SHA256 hashes",
  mount(root) {
    let alive = true;
    let offset = 0;
    const count = h("span", { class: "count" });
    const table = createTable({
      caption: "Users",
      onRowClick: (u) => openUserForm({ user: u, onSaved: load }),
      empty: { title: "No users", icon: "user" },
      columns: [
        { key: "username", label: "Username", render: (u) => h("span", { class: "mono cell-main" }, u.username,
          u.id === state.user.id ? h("span", { class: "badge badge-accent", style: { marginLeft: "6px" } }, "you") : null) },
        { key: "display_name", label: "Display name" },
        { key: "role", label: "Role", render: (u) => h("span", { class: `role-badge-${u.role}`, style: { fontWeight: 700 }, title: ROLE_TEXT[u.role] }, u.role) },
        { key: "active", label: "Status", render: (u) => activeBadge(u.active) },
        { key: "last_login_at", label: "Last sign-in", render: (u) => (u.last_login_at
          ? h("span", { title: fmtDateTime(u.last_login_at) }, fmtRelative(u.last_login_at)) : h("span", { class: "dim" }, "never")) },
        { key: "created_at", label: "Created (UTC)", render: (u) => h("span", { class: "nowrap" }, fmtDateTime(u.created_at, { seconds: false })) },
      ],
    });
    const pager = createPager({ onChange: (o) => { offset = o; load(); } });

    root.append(h("div", { class: "stack" },
      h("div", { class: "callout callout-info" }, icon("info"), h("div", {},
        h("strong", {}, "Roles: "), Object.entries(ROLE_TEXT).map(([r, t], i) => [i ? " · " : "", h("strong", {}, r), ` — ${t}`]),
        ". At least one active Admin must always exist.")),
      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", {}, icon("user"), "User accounts"),
          h("div", { style: { display: "flex", gap: "12px", alignItems: "center" } }, count,
            h("button", { class: "btn btn-primary", type: "button", onclick: () => openUserForm({ onSaved: load }) }, icon("plus"), "New user"))),
        table.el, pager.el)));

    async function load() {
      table.setLoading();
      try {
        const res = await api.get("/users", { limit: 50, offset });
        if (!alive) return;
        table.setRows(res.items);
        pager.update(res.total, res.limit, res.offset);
        count.textContent = `${res.total} account${res.total === 1 ? "" : "s"}`;
      } catch (err) {
        if (alive) table.setError(err, load);
      }
    }

    load();
    return { destroy() { alive = false; } };
  },
};
