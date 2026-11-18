// Single API client. Every request goes through here; errors are normalised to ApiError.

const BASE = "/api/v1";

export class ApiError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }

  /** Field-level messages from a structured validation error: {field: message}. */
  get fieldErrors() {
    const out = {};
    if (Array.isArray(this.details)) {
      for (const d of this.details) if (d && d.field) out[d.field] = d.message;
    }
    return out;
  }
}

function buildUrl(path, params) {
  const url = new URL(path.startsWith("/api") || path.startsWith("/health") ? path : `${BASE}${path}`, location.origin);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined || v === null || v === "") continue;
      url.searchParams.set(k, String(v));
    }
  }
  return url;
}

async function parseError(response) {
  let body = null;
  try { body = await response.json(); } catch { /* non-JSON error */ }
  const err = body && body.error;
  if (err) return new ApiError(response.status, err.code, err.message, err.details);
  return new ApiError(response.status, "http_error", `Request failed (HTTP ${response.status}).`, null);
}

// Set by app.js: called when a non-auth request returns 401 (session expired or revoked).
let onUnauthenticated = null;
export function setUnauthenticatedHandler(fn) { onUnauthenticated = fn; }

async function request(method, path, { params, body } = {}) {
  let response;
  try {
    response = await fetch(buildUrl(path, params), {
      method,
      headers: body !== undefined ? { "Content-Type": "application/json", Accept: "application/json" } : { Accept: "application/json" },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, "network_error", "Cannot reach the Hospitra server. Is it running on this machine?", null);
  }
  if (!response.ok) {
    const err = await parseError(response);
    if (response.status === 401 && !path.startsWith("/auth/")) onUnauthenticated?.(err);
    throw err;
  }
  if (response.status === 204) return null;
  return response.json();
}

export const api = {
  get: (path, params) => request("GET", path, { params }),
  post: (path, body) => request("POST", path, { body }),
  patch: (path, body) => request("PATCH", path, { body }),
  delete: (path) => request("DELETE", path),

  /** Download a file endpoint, verifying the response before saving it. */
  async download(path) {
    let response;
    try {
      response = await fetch(buildUrl(path));
    } catch {
      throw new ApiError(0, "network_error", "Cannot reach the Hospitra server.", null);
    }
    if (!response.ok) {
      const err = await parseError(response);
      if (response.status === 401) onUnauthenticated?.(err);
      throw err;
    }
    const blob = await response.blob();
    if (!blob.size) throw new ApiError(500, "empty_export", "The export was empty.", null);
    const disposition = response.headers.get("Content-Disposition") || "";
    const match = disposition.match(/filename="([^"]+)"/);
    const filename = match ? match[1] : path.split("/").pop();
    const href = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = href;
    a.download = filename;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(href), 4000);
    return { filename, size: blob.size, type: blob.type };
  },
};
