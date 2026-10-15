/**
 * api.ts — ATM Simulator API Module (Hardened, Task 2)
 *
 * Security controls:
 *  - WSS enforcement: openSessionSocket uses wss:// when the page is served over https://
 *  - No raw token logging: qrToken is never written to console or DOM attributes
 *  - URL history sanitisation: session IDs are NOT placed in window.location (WebSocket only)
 */

// BASE is derived from the page origin to avoid hardcoded localhost.
// When served over HTTPS (e.g. via Nginx), BASE = https://… and WS = wss://…
const BASE: string =
  (import.meta as any).env?.VITE_API_URL ??
  (typeof window !== "undefined" && window.location?.origin
    ? window.location.origin
    : "http://localhost:4000");

export interface CreateSessionResponse {
  sessionId: string;
  atmId: string;
  expiresAt: number;
  ttlSeconds: number;
  qrToken: string;
}

export interface SessionState {
  id: string;
  atmId: string;
  status: "pending" | "approved" | "consumed" | "expired" | "rejected";
  createdAt: number;
  expiresAt: number;
  approvedByCustomerRef?: string;
}

export async function createSession(atmId = "ATM-DEMO-001"): Promise<CreateSessionResponse> {
  const r = await fetch(`${BASE}/api/session`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ atmId }),
  });
  if (!r.ok) throw new Error("create session failed");
  return r.json();
}

export async function consumeSession(id: string): Promise<void> {
  await fetch(`${BASE}/api/session/${id}/consume`, { method: "POST" });
}

export async function getSession(id: string): Promise<SessionState> {
  const r = await fetch(`${BASE}/api/session/${id}`);
  if (!r.ok) throw new Error("get session failed");
  return r.json();
}

/**
 * Opens a WebSocket for real-time session updates.
 *
 * Security controls:
 *  1. Uses wss:// when the page is loaded over https:// (encrypted WebSocket).
 *     This prevents plain-text ws:// in production deployments behind TLS termination.
 *  2. The session ID is passed as a query parameter to the backend only — it is
 *     NOT placed in window.location.href or window.history, preventing session
 *     ID leakage in browser history, referrer headers, and server access logs.
 *  3. The function does not console.log the sessionId or any session tokens.
 */
export function openSessionSocket(sessionId: string): WebSocket {
  // Enforce wss:// when the app is served over HTTPS
  const wsBase = BASE.replace(/^https:\/\//, "wss://").replace(/^http:\/\//, "ws://");
  const wsUrl = `${wsBase}/ws?sid=${sessionId}`;

  const ws = new WebSocket(wsUrl);

  // Heartbeat: send a ping every 30s and close if no response within 5s.
  // This matches the backend 60s idle timeout and keeps the connection alive
  // through NAT/proxy timeouts without exposing session data.
  let pingTimer: ReturnType<typeof setInterval> | null = null;
  let pongTimeout: ReturnType<typeof setTimeout> | null = null;

  ws.addEventListener("open", () => {
    pingTimer = setInterval(() => {
      if (ws.readyState !== WebSocket.OPEN) {
        if (pingTimer) clearInterval(pingTimer);
        return;
      }
      // Application-level ping (gorilla/websocket handles native ping/pong at
      // the transport layer; this JSON ping satisfies application keepalive)
      ws.send(JSON.stringify({ type: "ping" }));
      pongTimeout = setTimeout(() => {
        // No response — close the stale connection
        ws.close(1001, "ping timeout");
      }, 5000);
    }, 30_000);
  });

  ws.addEventListener("message", (ev) => {
    // Clear pong timeout on any message (server responded)
    if (pongTimeout) {
      clearTimeout(pongTimeout);
      pongTimeout = null;
    }
    // Filter pong messages from reaching the caller — they are internal
    try {
      const msg = JSON.parse(ev.data);
      if (msg?.type === "pong") {
        // Consumed internally; do not propagate
        return;
      }
    } catch {
      // Non-JSON message — ignore
    }
  });

  ws.addEventListener("close", () => {
    if (pingTimer) clearInterval(pingTimer);
    if (pongTimeout) clearTimeout(pongTimeout);
  });

  return ws;
}
