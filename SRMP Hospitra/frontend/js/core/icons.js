// Inline stroke icons (24×24). Static developer-authored path data.
import { h } from "./dom.js";

export const PATHS = {
  dashboard: "M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z",
  network: "M12 3a2 2 0 1 0 0 4 2 2 0 0 0 0-4zM5 17a2 2 0 1 0 0 4 2 2 0 0 0 0-4zM19 17a2 2 0 1 0 0 4 2 2 0 0 0 0-4zM12 7v5M12 12l-6.3 5.3M12 12l6.3 5.3",
  server: "M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01",
  shield: "M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z",
  bug: "M12 8a4 4 0 0 0-4 4v3a4 4 0 0 0 8 0v-3a4 4 0 0 0-4-4zM12 8V5M8 13H4M20 13h-4M8 17l-3 2M16 17l3 2M9 6L7 4M15 6l2-2",
  activity: "M3 12h4l3-8 4 16 3-8h4",
  alert: "M12 3L2 20h20L12 3zM12 9v5M12 17h.01",
  list: "M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01",
  siren: "M7 18v-6a5 5 0 0 1 10 0v6M5 21h14M12 3v2M4.2 6.2l1.4 1.4M19.8 6.2l-1.4 1.4M10 13a2 2 0 0 1 2-2",
  file: "M14 3H6v18h12V7zM14 3v4h4M9 13h6M9 17h6",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-4-4",
  x: "M6 6l12 12M18 6L6 18",
  plus: "M12 5v14M5 12h14",
  edit: "M4 20h4L19 9l-4-4L4 16zM14 6l4 4",
  download: "M12 4v12M7 11l5 5 5-5M5 20h14",
  play: "M7 4l13 8-13 8z",
  refresh: "M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7",
  back: "M15 6l-6 6 6 6",
  next: "M9 6l6 6-6 6",
  flask: "M9 3h6M10 3v6L4 19a1 1 0 0 0 .9 1.5h14.2A1 1 0 0 0 20 19l-6-10V3",
  lock: "M6 11h12v10H6zM8 11V7a4 4 0 0 1 8 0v4",
  clock: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l3 2",
  link: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
  heart: "M12 20s-7-4.4-7-10a4 4 0 0 1 7-2.6A4 4 0 0 1 19 10c0 5.6-7 10-7 10zM8.5 11h2l1-2 2 4 1-2h1",
  monitor: "M3 4h18v12H3zM8 20h8M12 16v4",
  database: "M12 3c4.4 0 8 1.3 8 3s-3.6 3-8 3-8-1.3-8-3 3.6-3 8-3zM4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3",
  wifi: "M2 9a15 15 0 0 1 20 0M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M12 19.5h.01",
  globe: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18",
  switch: "M3 8h18v8H3zM7 12h.01M11 12h.01M15 12h.01M18 12h.01",
  key: "M7.5 15.5a4 4 0 1 1 3.4-6H21v3h-2v3h-3v-3h-5.1a4 4 0 0 1-3.4 3z",
  radar: "M12 3a9 9 0 1 0 9 9M12 7a5 5 0 1 0 5 5M12 12l6.5-6.5",
  tablet: "M6 3h12v18H6zM11 18h2",
  check: "M5 12l5 5 9-10",
  info: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 11v6M12 7.5h.01",
  arrow: "M5 12h14M13 6l6 6-6 6",
  open: "M14 4h6v6M20 4l-9 9M18 14v6H4V6h6",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0",
  reset: "M4 11a8 8 0 1 1 2.3 5.7M4 4v7h7",
  firewall: "M3 5h18v14H3zM3 10h18M3 14.5h18M9 5v5M15 10v4.5M9 14.5V19",
  cloud: "M7 18a5 5 0 0 1-.9-9.9A6 6 0 0 1 17.6 9 4.5 4.5 0 0 1 17 18z",
  note: "M5 4h14v12l-4 4H5zM15 20v-4h4M8 9h8M8 13h5",
  target: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 12h.01",
};

export function svgMarkup(name) {
  const d = PATHS[name] || PATHS.info;
  return `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="${d}"/></svg>`;
}

export function icon(name, extraClass = "") {
  return h("span", { class: `icon ${extraClass}`.trim(), "aria-hidden": "true", trustedHtml: svgMarkup(name) });
}

export const ASSET_TYPE_ICONS = {
  "Network Device": "switch",
  Server: "server",
  "Database Server": "database",
  Workstation: "monitor",
  "Medical Device": "heart",
  "Access Point": "wifi",
  Endpoint: "tablet",
  "Security Appliance": "radar",
  "Web Server": "globe",
  "VPN Gateway": "key",
};
