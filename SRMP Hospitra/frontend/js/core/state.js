// Global application state + a tiny pub/sub bus.
import { api } from "./api.js";

const listeners = new Map();

export const bus = {
  on(topic, fn) {
    if (!listeners.has(topic)) listeners.set(topic, new Set());
    listeners.get(topic).add(fn);
    return () => listeners.get(topic)?.delete(fn);
  },
  emit(topic, payload) {
    for (const fn of listeners.get(topic) || []) {
      try { fn(payload); } catch (err) { console.error(`bus handler for ${topic} failed`, err); }
    }
  },
};

const STORAGE_KEY = "hospitra.branchContext";

function loadBranch() {
  try { return localStorage.getItem(STORAGE_KEY) || ""; } catch { return ""; }
}

export const state = {
  branchId: loadBranch(), // "" = all branches
  branches: [],
  zones: [],
  user: null, // V2: {username, display_name, role, permissions[]}
};

/** UI-level permission check (the server enforces the same rules on every request). */
export const can = (permission) => Boolean(state.user?.permissions?.includes(permission));

export function setBranchContext(branchId) {
  state.branchId = branchId || "";
  try { localStorage.setItem(STORAGE_KEY, state.branchId); } catch { /* storage unavailable */ }
  bus.emit("branch-context", state.branchId);
}

export async function loadReferenceData() {
  const [branches, zones] = await Promise.all([api.get("/branches"), api.get("/zones")]);
  state.branches = branches;
  state.zones = zones;
  if (state.branchId && !branches.some((b) => b.id === state.branchId)) setBranchContext("");
  return { branches, zones };
}

export const branchById = (id) => state.branches.find((b) => b.id === id);
export const branchByCode = (code) => state.branches.find((b) => b.code === code);
export const zonesForBranch = (branchId) => state.zones.filter((z) => z.branch_id === branchId);
