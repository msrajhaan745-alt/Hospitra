// Network Infrastructure — interactive SVG of the seeded logical topology (not live discovery).
import { api } from "../core/api.js";
import { clear, debounce, h, s } from "../core/dom.js";
import { ASSET_TYPE_ICONS, PATHS, icon } from "../core/icons.js";
import { branchByCode, state } from "../core/state.js";
import { assetStatusBadge, criticalityBadge, emptyState, errorState, loadingState } from "../core/ui.js";
import { kv, openAssetDrawer, section } from "../details.js";

const POLICY = {
  management: { tag: "MGMT PATH ONLY", text: "Management interfaces are reachable only through designated management paths." },
  staff: { tag: "DEFAULT-DENY", text: "Default-deny to other zones; approved business services only." },
  clinical: { tag: "APPROVED APPS", text: "Clinical workstations access only approved clinical application services." },
  application: { tag: "RESTRICTED", text: "Hosts clinical applications and data; reachable only from approved zones." },
  medical: { tag: "APPROVED SVCS", text: "Medical devices communicate only with approved clinical services. Vendor access is controlled and time-bound." },
  guest: { tag: "INTERNET-ONLY", text: "Internet-only intent. Guest Wi-Fi must not access private hospital networks." },
  security: { tag: "TELEMETRY SINK", text: "Security telemetry is sent to designated security services." },
  dmz: { tag: "PUBLIC-FACING", text: "Public-facing services and remote-access termination." },
};

const W = 1000;
const ZONE_W = 115;
const ZONE_GAP = (W - 8 * ZONE_W) / 9;
const ZONE_Y = 300;
const ZONE_H = 292;
const zoneX = (i) => ZONE_GAP + i * (ZONE_W + ZONE_GAP);

function splitName(name) {
  if (name.length <= 15) return [name];
  const words = name.split(" ");
  let best = [name, ""];
  let bestDiff = Infinity;
  for (let i = 1; i < words.length; i += 1) {
    const a = words.slice(0, i).join(" ");
    const b = words.slice(i).join(" ");
    const diff = Math.abs(a.length - b.length);
    if (diff < bestDiff) { bestDiff = diff; best = [a, b]; }
  }
  return best;
}

const truncate = (text, n) => (text.length > n ? `${text.slice(0, n - 1)}…` : text);
const shortName = (asset) => asset.name.replace(/\s\([ABC]\)$/, "");

function svgIcon(name, x, y, size) {
  const scale = size / 24;
  return s("path", { class: "node-icon", d: PATHS[name] || PATHS.server, transform: `translate(${x - size / 2} ${y - size / 2}) scale(${scale})` });
}

export default {
  subtitle: "Logical topology of the hospital network · VLAN plan 10.<site>.<vlan>.0/24",
  mount(root, params) {
    let alive = true;
    const fromParam = params.get("branch");
    const ctxBranch = state.branches.find((b) => b.id === state.branchId);
    let branchCode = (fromParam && branchByCode(fromParam) ? fromParam : null) || ctxBranch?.code || state.branches[0].code;
    let selectedZoneId = null;
    let selectedAssetId = params.get("asset");
    let data = null;

    const switcher = h("div", { class: "branch-switch", role: "group", "aria-label": "Select branch" });
    const canvasHost = h("div", { class: "topo-canvas" });
    const side = h("div", { class: "stack" });
    const status = h("span", { class: "muted", style: { fontSize: "12px" } });

    root.append(h("div", { class: "topo-layout" },
      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", {}, icon("network"), "Branch topology"), h("div", { style: { display: "flex", gap: "12px", alignItems: "center" } }, status, switcher)),
        canvasHost),
      side));

    function renderSwitcher() {
      clear(switcher).append(...state.branches.map((b) =>
        h("button", { type: "button", "aria-pressed": String(b.code === branchCode), onclick: () => selectBranch(b.code) }, `Branch ${b.code}`)));
    }

    function selectBranch(code) {
      if (code === branchCode) return;
      branchCode = code;
      selectedZoneId = null;
      selectedAssetId = null;
      renderSwitcher();
      load();
    }

    async function load() {
      const branch = branchByCode(branchCode);
      clear(canvasHost).append(loadingState("Loading topology…"));
      try {
        const [detail, assets, incidents] = await Promise.all([
          api.get(`/branches/${branch.id}`),
          api.get("/assets", { branch_id: branch.id, limit: 200 }),
          api.get("/incidents", { branch_id: branch.id, active_only: true, limit: 200 }),
        ]);
        if (!alive) return;
        const openByTag = {};
        for (const inc of incidents.items) for (const tag of inc.asset_tags) openByTag[tag] = (openByTag[tag] || 0) + 1;
        data = { branch: detail, assets: assets.items, openByTag, openIncidents: incidents.total };
        if (selectedAssetId) {
          const a = data.assets.find((x) => x.id === selectedAssetId);
          if (a) selectedZoneId = a.zone_id;
        }
        status.textContent = `${data.assets.length} assets · ${data.branch.zones.length} zones · ${incidents.total} open incident(s)`;
        draw();
        renderSide();
      } catch (err) {
        if (!alive) return;
        clear(canvasHost).append(errorState(err, load));
      }
    }

    function selectZone(zoneId) {
      selectedZoneId = zoneId;
      selectedAssetId = null;
      draw();
      renderSide();
    }

    function selectAsset(asset) {
      selectedAssetId = asset.id;
      selectedZoneId = asset.zone_id;
      draw();
      renderSide();
      openAssetDrawer(asset.id);
    }

    function activatable(el, fn, label) {
      el.setAttribute("tabindex", "0");
      el.setAttribute("role", "button");
      el.setAttribute("aria-label", label);
      el.addEventListener("click", (ev) => { ev.stopPropagation(); fn(); });
      el.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); ev.stopPropagation(); fn(); } });
      return el;
    }

    function draw() {
      const { branch, assets, openByTag } = data;
      const zones = [...branch.zones].sort((a, b) => a.vlan_id - b.vlan_id);
      const svg = s("svg", { class: "topo-svg", viewBox: `0 0 ${W} ${ZONE_Y + ZONE_H + 16}`, role: "group",
        "aria-label": `Logical topology of ${branch.name}` });

      const links = s("g", {});
      const gwX = W / 2;
      // WAN → gateway → core
      links.append(s("path", { class: "topo-link", d: `M${gwX} 62 V 112` }));
      links.append(s("path", { class: "topo-link", d: `M${gwX} 162 V 202` }));
      zones.forEach((z, i) => {
        const cx = zoneX(i) + ZONE_W / 2;
        links.append(s("path", { class: `topo-link${z.id === selectedZoneId ? " active" : ""}`, d: `M${cx} 246 V ${ZONE_Y}` }));
      });
      // Policy paths drawn beneath the core layer: guest → internet only, DMZ ← public.
      const gIdx = zones.findIndex((z) => z.zone_type === "guest");
      const dIdx = zones.findIndex((z) => z.zone_type === "dmz");
      if (gIdx >= 0) {
        const x = zoneX(gIdx) + ZONE_W * 0.78;
        links.append(s("path", { class: "topo-link policy", d: `M${gwX + 110} 128 H ${x} V ${ZONE_Y}` }));
      }
      if (dIdx >= 0) {
        const x = zoneX(dIdx) + ZONE_W * 0.78;
        links.append(s("path", { class: "topo-link public", d: `M${gwX + 110} 146 H ${x} V ${ZONE_Y}` }));
      }
      svg.append(links);

      const infra = s("g", { class: "topo-infra" });
      infra.append(
        s("rect", { x: gwX - 100, y: 18, width: 200, height: 44, rx: 22 }),
        s("text", { class: "lbl", x: gwX, y: 38, "text-anchor": "middle" }, "Internet / WAN"),
        s("text", { class: "sub", x: gwX, y: 53, "text-anchor": "middle" }, "upstream"),
        s("rect", { x: gwX - 110, y: 112, width: 220, height: 50, rx: 7 }),
        s("text", { class: "lbl", x: gwX, y: 133, "text-anchor": "middle" }, `Branch ${branch.code} gateway`),
        s("text", { class: "sub", x: gwX, y: 149, "text-anchor": "middle" }, "edge firewall · VPN termination via DMZ"),
        s("rect", { x: ZONE_GAP, y: 202, width: W - 2 * ZONE_GAP, height: 44, rx: 7 }),
        s("text", { class: "lbl", x: W / 2, y: 221, "text-anchor": "middle" }, "Core network layer — inter-zone routing"),
        s("text", { class: "sub", x: W / 2, y: 237, "text-anchor": "middle" }, `default-deny between security zones · site ID ${branch.site_id} · 10.${branch.site_id}.<vlan>.0/24`));
      svg.append(infra);

      zones.forEach((z, i) => {
        const x = zoneX(i);
        const g = s("g", { class: `topo-zone${z.id === selectedZoneId ? " is-selected" : ""}` });
        activatable(g, () => selectZone(z.id), `Zone ${z.name}, VLAN ${z.vlan_id}, subnet ${z.subnet_cidr}`);
        g.append(s("rect", { class: "zone-bg", x, y: ZONE_Y, width: ZONE_W, height: ZONE_H, rx: 8 }));
        g.append(s("text", { class: "zone-vlan", x: x + 9, y: ZONE_Y + 17 }, `VLAN ${z.vlan_id}`));
        splitName(z.name).forEach((line, li) => g.append(s("text", { class: "zone-title", x: x + 9, y: ZONE_Y + 33 + li * 14 }, line)));
        g.append(s("text", { class: "zone-meta", x: x + 9, y: ZONE_Y + 64 }, z.subnet_cidr));
        g.append(s("text", { class: "zone-policy", x: x + 9, y: ZONE_Y + 79 }, POLICY[z.zone_type]?.tag || ""));

        const zoneAssets = assets.filter((a) => a.zone_id === z.id).sort((a, b) => a.asset_tag.localeCompare(b.asset_tag));
        zoneAssets.slice(0, 2).forEach((a, ai) => {
          const cx = x + ZONE_W / 2;
          const cy = ZONE_Y + 118 + ai * 100;
          const node = s("g", { class: `topo-asset${a.id === selectedAssetId ? " is-selected" : ""}`, dataset: { status: a.status } });
          activatable(node, () => selectAsset(a), `Asset ${a.asset_tag}, ${a.name}, ${a.asset_type}, status ${a.status}`);
          node.append(
            s("circle", { class: "node-halo", cx, cy, r: 27 }),
            s("circle", { class: "node-bg", cx, cy, r: 21 }),
            svgIcon(ASSET_TYPE_ICONS[a.asset_type] || "server", cx, cy, 20),
            s("text", { class: "node-tag", x: cx, y: cy + 36, "text-anchor": "middle" }, a.asset_tag.replace(/^HSP-/, "")),
            s("text", { class: "node-name", x: cx, y: cy + 49, "text-anchor": "middle" }, truncate(shortName(a), 19)),
            s("text", { class: "node-status", x: cx, y: cy + 62, "text-anchor": "middle", style: { fill: "var(--status-c)" } }, a.status),
            s("title", {}, `${a.asset_tag} — ${a.name}\n${a.asset_type} · ${a.ip_address} · ${a.status}`));
          const open = openByTag[a.asset_tag];
          if (open) {
            node.append(s("g", { class: "inc-badge" },
              s("rect", { x: cx + 12, y: cy - 27, width: 22, height: 15, rx: 7.5 }),
              s("text", { x: cx + 23, y: cy - 16.5, "text-anchor": "middle" }, `!${open}`),
              s("title", {}, `${open} open incident(s)`)));
          }
          g.append(node);
        });
        svg.append(g);
      });
      svg.addEventListener("click", () => { if (selectedZoneId || selectedAssetId) { selectedZoneId = null; selectedAssetId = null; draw(); renderSide(); } });
      clear(canvasHost).append(svg);
    }

    function legend() {
      const types = Object.entries(ASSET_TYPE_ICONS);
      return h("section", { class: "panel" }, h("div", { class: "panel-head" }, h("h3", {}, "Legend")),
        h("div", { class: "panel-body legend" },
          h("div", { class: "legend-group" }, h("h4", {}, "Asset status (ring)"), h("div", { class: "legend-items" },
            [["Active", "var(--ok)"], ["Warning", "var(--warn)"], ["Offline", "var(--danger)", true], ["Maintenance", "var(--info)"]].map(([label, c, dashed]) =>
              h("span", { class: "legend-item" }, h("span", { class: `legend-swatch${dashed ? " dashed" : ""}`, style: { "--c": c } }), label)))),
          h("div", { class: "legend-group" }, h("h4", {}, "Indicators"), h("div", { class: "legend-items" },
            h("span", { class: "legend-item" }, h("span", { class: "badge badge-danger" }, "!n"), "Open incidents on asset"),
            h("span", { class: "legend-item" }, h("span", { class: "legend-line", style: { "--c": "var(--border-strong)" } }), "Zone uplink"),
            h("span", { class: "legend-item" }, h("span", { class: "legend-line dashed", style: { "--c": "var(--warn)" } }), "Guest internet-only path"),
            h("span", { class: "legend-item" }, h("span", { class: "legend-line dashed", style: { "--c": "var(--info)" } }), "Public-facing path"))),
          h("div", { class: "legend-group" }, h("h4", {}, "Asset types"), h("div", { class: "legend-items" },
            types.map(([label, name]) => h("span", { class: "legend-item" }, icon(name), label)))),
          h("p", { class: "dim", style: { fontSize: "11.5px" } }, "Logical representation of seeded records. No traffic, packet counters or live discovery are shown.")));
    }

    function renderSide() {
      const { branch, assets, openByTag } = data;
      const zone = branch.zones.find((z) => z.id === selectedZoneId);
      const info = h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h3", {}, branch.name)),
        h("div", { class: "panel-body" }, kv([
          ["Role", branch.role],
          ["Location", branch.location_label],
          ["Site ID", String(branch.site_id)],
          ["Addressing", h("span", { class: "mono" }, `10.${branch.site_id}.<vlan>.0/24`)],
          ["Zones / assets", `${branch.zone_count} / ${branch.asset_count}`],
        ])));
      let zonePanel;
      if (zone) {
        const zoneAssets = assets.filter((a) => a.zone_id === zone.id);
        zonePanel = h("section", { class: "panel" },
          h("div", { class: "panel-head" }, h("h3", {}, `VLAN ${zone.vlan_id} · ${zone.name}`)),
          h("div", { class: "panel-body stack" },
            kv([["Subnet", h("span", { class: "mono" }, zone.subnet_cidr)], ["Zone type", zone.zone_type], ["Description", zone.description]]),
            h("div", { class: "callout callout-warn" }, icon("shield"), h("div", {}, h("strong", {}, "Policy intent: "), POLICY[zone.zone_type]?.text || "")),
            section(`Assets (${zoneAssets.length})`, h("div", { class: "card-list" }, zoneAssets.map((a) =>
              h("button", { class: "mini-card", type: "button", onclick: () => selectAsset(a), "aria-pressed": String(a.id === selectedAssetId) },
                h("div", { class: "row" }, icon(ASSET_TYPE_ICONS[a.asset_type] || "server"), h("span", { class: "mono" }, a.asset_tag), assetStatusBadge(a.status)),
                h("div", { class: "desc" }, `${a.name} · ${a.ip_address}`),
                h("div", { class: "row", style: { marginTop: "6px" } }, criticalityBadge(a.criticality), h("span", { class: "badge badge-outline" }, a.data_classification),
                  openByTag[a.asset_tag] ? h("span", { class: "badge badge-danger" }, `${openByTag[a.asset_tag]} open incident(s)`) : null)))))));
      } else {
        zonePanel = h("section", { class: "panel" }, emptyState({ title: "Select a zone or asset", message: "Click a security zone to see its subnet, policy intent and assets, or click an asset node to open its details.", iconName: "target", compact: true }));
      }
      clear(side).append(info, zonePanel, legend());
    }

    renderSwitcher();
    load();
    const reload = debounce(load, 300);
    return {
      destroy() { alive = false; },
      onLive: reload,
      onDataChanged: reload,
      onBranch: (id) => { const b = state.branches.find((x) => x.id === id); if (b) selectBranch(b.code); },
    };
  },
};
