// Reusable data table with server-side sorting, keyboard-accessible rows and states.
import { clear, h } from "./dom.js";
import { emptyState, errorState } from "./ui.js";

/**
 * columns: [{ key, label, sortKey?, align?: "num"|"center", width?, render?(row) }]
 */
export function createTable({ columns, rowKey = "id", onRowClick, onSort, sort = null, order = "asc", empty = {}, compact = false, caption }) {
  const thead = h("thead");
  const tbody = h("tbody");
  const table = h("table", { class: `data${compact ? " compact" : ""}` }, caption ? h("caption", { class: "sr-only" }, caption) : null, thead, tbody);
  const wrap = h("div", { class: "table-wrap" }, table);
  const stateHost = h("div");
  const el = h("div", {}, wrap, stateHost);
  let current = { sort, order };
  let selectedId = null;

  function renderHead() {
    clear(thead).append(h("tr", {}, columns.map((col) => {
      const sortable = Boolean(col.sortKey && onSort);
      const active = sortable && current.sort === col.sortKey;
      const th = h("th", {
        class: [col.align || "", sortable ? "sortable" : ""].join(" ").trim(),
        scope: "col",
        style: col.width ? { width: col.width } : null,
        "aria-sort": active ? (current.order === "asc" ? "ascending" : "descending") : null,
        tabindex: sortable ? "0" : null,
      }, col.label, sortable ? h("span", { class: "sort-ind", "aria-hidden": "true" }, active ? (current.order === "asc" ? "▲" : "▼") : "") : null);
      if (sortable) {
        const activate = () => {
          const nextOrder = current.sort === col.sortKey
            ? (current.order === "asc" ? "desc" : "asc")
            : (col.defaultOrder || "asc");
          current = { sort: col.sortKey, order: nextOrder };
          renderHead();
          onSort(current.sort, current.order);
        };
        th.addEventListener("click", activate);
        th.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); activate(); } });
      }
      return th;
    })));
  }

  function setLoading() {
    clear(stateHost);
    clear(tbody).append(...Array.from({ length: 6 }, () =>
      h("tr", {}, columns.map(() => h("td", {}, h("div", { class: "skeleton", style: { width: `${40 + Math.random() * 50}%` } }))))));
  }

  function setError(err, retry) {
    clear(tbody);
    clear(stateHost).append(errorState(err, retry));
  }

  function setRows(rows, { highlight = new Set() } = {}) {
    clear(stateHost);
    clear(tbody);
    if (!rows.length) {
      stateHost.append(emptyState({ title: empty.title || "No records", message: empty.message, iconName: empty.icon || "search" }));
      return;
    }
    for (const row of rows) {
      const id = row[rowKey];
      const tr = h("tr", {
        class: [onRowClick ? "clickable" : "", id === selectedId ? "is-selected" : "", highlight.has(id) ? "is-new" : ""].join(" ").trim(),
        tabindex: onRowClick ? "0" : null,
        dataset: { id },
      }, columns.map((col) => h("td", { class: col.align || "" }, col.render ? col.render(row) : (row[col.key] ?? "—"))));
      if (onRowClick) {
        tr.addEventListener("click", (ev) => {
          if (ev.target.closest("a, button")) return;
          select(id);
          onRowClick(row);
        });
        tr.addEventListener("keydown", (ev) => { if (ev.key === "Enter") { ev.preventDefault(); select(id); onRowClick(row); } });
      }
      tbody.append(tr);
    }
  }

  function select(id) {
    selectedId = id;
    for (const tr of tbody.querySelectorAll("tr")) tr.classList.toggle("is-selected", tr.dataset.id === id);
  }

  renderHead();
  return { el, setLoading, setError, setRows, select };
}

export function createPager({ onChange }) {
  const info = h("span", { class: "num" });
  const prev = h("button", { class: "btn btn-sm", type: "button", "aria-label": "Previous page" }, "‹ Prev");
  const next = h("button", { class: "btn btn-sm", type: "button", "aria-label": "Next page" }, "Next ›");
  const el = h("div", { class: "pager" }, info, h("div", { class: "pager-controls" }, prev, next));
  let state = { total: 0, limit: 25, offset: 0 };
  prev.addEventListener("click", () => onChange(Math.max(0, state.offset - state.limit)));
  next.addEventListener("click", () => onChange(state.offset + state.limit));
  function update(total, limit, offset) {
    state = { total, limit, offset };
    const from = total ? offset + 1 : 0;
    const to = Math.min(offset + limit, total);
    info.textContent = `${from}–${to} of ${total.toLocaleString("en-GB")}`;
    prev.disabled = offset <= 0;
    next.disabled = offset + limit >= total;
    el.hidden = total <= limit && offset === 0;
  }
  return { el, update };
}
