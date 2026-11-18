// Formatting helpers. All timestamps from the API are UTC and are displayed in UTC.

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const pad = (n) => String(n).padStart(2, "0");

export function fmtDateTime(iso, { seconds = true } = {}) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  const time = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}${seconds ? `:${pad(d.getUTCSeconds())}` : ""}`;
  return `${pad(d.getUTCDate())} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}, ${time} UTC`;
}

export function fmtDate(isoDate) {
  if (!isoDate) return "—";
  const d = new Date(isoDate.length === 10 ? `${isoDate}T00:00:00Z` : isoDate);
  return `${pad(d.getUTCDate())} ${MONTHS[d.getUTCMonth()]}`;
}

export function fmtRelative(iso) {
  if (!iso) return "";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  const abs = Math.abs(diff);
  const suffix = diff >= 0 ? "ago" : "from now";
  if (abs < 45) return "just now";
  if (abs < 3600) return `${Math.round(abs / 60)} min ${suffix}`;
  if (abs < 86400) return `${Math.round(abs / 3600)} h ${suffix}`;
  return `${Math.round(abs / 86400)} d ${suffix}`;
}

export const fmtNumber = (n) => (n === null || n === undefined ? "—" : Number(n).toLocaleString("en-GB"));

export function fmtBytes(bytes) {
  if (!bytes && bytes !== 0) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(i ? 1 : 0)} ${units[i]}`;
}

export const shortId = (id) => (id ? id.slice(0, 8).toUpperCase() : "—");

export function humanise(key) {
  return String(key).replaceAll("_", " ").replace(/^\w/, (c) => c.toUpperCase());
}

export const EVENT_TYPE_LABELS = {
  network_access: "Network access",
  auth_failure: "Authentication failure",
  vpn_login: "VPN login",
  device_observed: "Device observed",
  outbound_transfer: "Outbound transfer",
  request_volume: "Request volume",
  file_activity: "File activity",
  vendor_access: "Vendor access",
  telemetry: "Telemetry",
};

export const eventTypeLabel = (t) => EVENT_TYPE_LABELS[t] || humanise(t);

export function toIsoStartOfDay(dateStr) {
  return dateStr ? `${dateStr}T00:00:00Z` : undefined;
}

export function toIsoEndOfDay(dateStr) {
  return dateStr ? `${dateStr}T23:59:59Z` : undefined;
}
