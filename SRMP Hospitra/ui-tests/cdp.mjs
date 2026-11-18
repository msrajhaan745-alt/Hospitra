// Minimal Chrome DevTools Protocol harness (Node >= 22 built-in WebSocket + fetch).
// Used only by the optional UI checks in ui-tests/ — it drives a local headless browser
// against http://127.0.0.1:8000. It is not part of the application.
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const CANDIDATES = [
  process.env.CHROME_PATH,
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
].filter(Boolean);
const CHROME = CANDIDATES.find((p) => existsSync(p));
if (!CHROME) throw new Error("No Chrome/Edge found. Set CHROME_PATH to a Chromium-based browser executable.");
export const OUT = process.env.SHOTS_DIR || join(dirname(fileURLToPath(import.meta.url)), "screenshots");
mkdirSync(OUT, { recursive: true });

// ---- V2: target server and credentials (never hard-coded) ------------------------------------
export const BASE = (process.env.HOSPITRA_UI_BASE || "http://127.0.0.1:8000").replace(/\/$/, "");
export const ADMIN = { username: process.env.HOSPITRA_UI_USER, password: process.env.HOSPITRA_UI_PASSWORD };

/** A cookie-carrying API client for test setup/verification. */
export async function apiSession({ username, password }) {
  const r = await fetch(`${BASE}/api/v1/auth/login`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password }),
  });
  if (!r.ok) throw new Error(`API login for ${username} failed: HTTP ${r.status}`);
  const cookie = r.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  const call = async (method, path, body) => {
    const res = await fetch(`${BASE}/api/v1${path}`, {
      method, headers: { Cookie: cookie, ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  };
  return {
    get: async (p) => (await call("GET", p)).body,
    post: (p, b) => call("POST", p, b),
    patch: (p, b) => call("PATCH", p, b),
  };
}

/** Sign in through the real login screen, then open `hash`. */
export async function signIn(p, creds = ADMIN, hash = "#/command") {
  await p.goto(`${BASE}/${hash}`, 800);
  await p.waitFor(`document.querySelector('.auth-card form') || document.querySelector('.nav-link')`, 10000);
  if (await p.eval(`!!document.querySelector('.auth-card form')`)) {
    await p.eval(`(() => {
      const f = document.querySelector('.auth-card form');
      const [u, pw] = f.querySelectorAll('input');
      u.value = ${JSON.stringify(creds.username)}; pw.value = ${JSON.stringify(creds.password)};
      f.requestSubmit();
    })()`);
  }
  await p.waitFor(`document.querySelector('.nav-link') && document.getElementById('auth-root').hidden`, 10000);
  await p.sleep(900);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function withBrowser(fn, { width = 1600, height = 1000 } = {}) {
  const port = 9300 + Math.floor(Math.random() * 500);
  const profile = mkdtempSync(join(tmpdir(), "cdp-"));
  const proc = spawn(CHROME, [
    "--headless=new", `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`,
    `--window-size=${width},${height}`, "--no-first-run", "--disable-extensions", "about:blank",
  ], { stdio: "ignore" });
  let targets;
  for (let i = 0; i < 50; i++) {
    try { targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json(); if (targets.length) break; } catch {}
    await sleep(200);
  }
  const page = targets.find((t) => t.type === "page");
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener("open", r, { once: true }));
  let id = 0;
  const pending = new Map();
  const problems = [];
  ws.addEventListener("message", (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
      return;
    }
    if (msg.method === "Runtime.exceptionThrown") {
      const d = msg.params.exceptionDetails;
      problems.push(`EXCEPTION: ${d.exception?.description || d.text} @ ${d.url}:${d.lineNumber}`);
    } else if (msg.method === "Runtime.consoleAPICalled" && ["error", "warning", "assert"].includes(msg.params.type)) {
      problems.push(`CONSOLE ${msg.params.type}: ${msg.params.args.map((a) => a.value ?? a.description).join(" ")}`);
    } else if (msg.method === "Log.entryAdded" && msg.params.entry.level === "error") {
      problems.push(`LOG: ${msg.params.entry.text} ${msg.params.entry.url || ""}`);
    } else if (msg.method === "Network.responseReceived" && msg.params.response.status >= 400) {
      problems.push(`HTTP ${msg.params.response.status}: ${msg.params.response.url}`);
    } else if (msg.method === "Network.loadingFailed" && !msg.params.canceled) {
      problems.push(`NETFAIL: ${msg.params.errorText}`);
    }
  });
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const mid = ++id;
    pending.set(mid, { resolve, reject });
    ws.send(JSON.stringify({ id: mid, method, params }));
  });
  await send("Runtime.enable");
  await send("Log.enable");
  await send("Network.enable");
  await send("Page.enable");
  await send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false });

  const api = {
    problems,
    async goto(url, settle = 1500) { await send("Page.navigate", { url }); await sleep(settle); },
    sleep,
    async eval(expression) {
      const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails) throw new Error(`eval failed: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}`);
      return r.result.value;
    },
    async waitFor(expression, timeout = 8000) {
      const start = Date.now();
      while (Date.now() - start < timeout) {
        try { if (await api.eval(expression)) return true; } catch {}
        await sleep(150);
      }
      throw new Error(`timeout waiting for: ${expression}`);
    },
    async click(selector) {
      const ok = await api.eval(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return false; el.scrollIntoView({block:'center'}); el.dispatchEvent(new MouseEvent('click', {bubbles:true, cancelable:true, view:window})); return true; })()`);
      if (!ok) throw new Error(`click: no element ${selector}`);
    },
    async clickText(selector, text) {
      const ok = await api.eval(`(() => { const el = [...document.querySelectorAll(${JSON.stringify(selector)})].find(e => e.textContent.includes(${JSON.stringify(text)})); if (!el) return false; el.scrollIntoView({block:'center'}); el.click(); return true; })()`);
      if (!ok) throw new Error(`clickText: no ${selector} containing "${text}"`);
    },
    async shot(name, fullPage = false) {
      let clip;
      if (fullPage) {
        const m = await send("Page.getLayoutMetrics");
        clip = { x: 0, y: 0, width, height: Math.min(m.cssContentSize.height, 4000), scale: 1 };
        await send("Emulation.setDeviceMetricsOverride", { width, height: clip.height, deviceScaleFactor: 1, mobile: false });
        await sleep(300);
      }
      const r = await send("Page.captureScreenshot", { format: "png", ...(clip ? { clip } : {}) });
      if (fullPage) await send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false });
      const file = join(OUT, `${name}.png`);
      writeFileSync(file, Buffer.from(r.data, "base64"));
      return file;
    },
  };
  try {
    await fn(api);
  } finally {
    ws.close();
    proc.kill();
  }
}
