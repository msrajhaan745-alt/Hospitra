// WebSocket client: notifications only. Views re-read state from the REST API on each message.
import { bus } from "./state.js";

let socket = null;
let retry = 0;
let pingTimer = null;
let status = "connecting";

function setStatus(next) {
  status = next;
  bus.emit("ws-status", status);
}

export const wsStatus = () => status;

export function connectLive() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  setStatus("connecting");
  socket = new WebSocket(`${proto}://${location.host}/ws/events`);

  socket.addEventListener("open", () => {
    retry = 0;
    setStatus("live");
    clearInterval(pingTimer);
    pingTimer = setInterval(() => socket?.readyState === WebSocket.OPEN && socket.send("ping"), 25000);
  });

  socket.addEventListener("message", (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    if (!msg || msg.type === "pong" || msg.type === "connected") return;
    bus.emit("live", msg);
  });

  socket.addEventListener("close", (ev) => {
    clearInterval(pingTimer);
    setStatus("offline");
    if (ev.code === 4401) {
      // Server rejected the session: do not retry; the app will ask the user to sign in again.
      bus.emit("ws-unauthenticated");
      return;
    }
    const delay = Math.min(15000, 1000 * 2 ** retry);
    retry += 1;
    setTimeout(reconnectIfSignedIn, delay);
  });

  socket.addEventListener("error", () => socket?.close());
}

// Before reconnecting, check that the session is still valid; if it is not, ask the user to
// sign in instead of retrying a connection the server will keep refusing.
async function reconnectIfSignedIn() {
  try {
    const res = await fetch("/api/v1/auth/status", { credentials: "same-origin" });
    if (res.ok && !(await res.json()).authenticated) {
      bus.emit("ws-unauthenticated");
      return;
    }
  } catch { /* server unreachable: keep retrying */ }
  connectLive();
}
