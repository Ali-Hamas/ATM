const BASE =
  (import.meta as any).env?.VITE_API_URL ||
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

export function openSessionSocket(sessionId: string): WebSocket {
  const wsUrl = BASE.replace(/^http/, "ws") + `/ws?sid=${sessionId}`;
  return new WebSocket(wsUrl);
}
