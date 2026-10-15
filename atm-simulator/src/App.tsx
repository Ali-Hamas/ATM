import { useEffect, useRef, useState } from "react";
import { QRCodeCanvas } from "qrcode.react";
import { createSession, consumeSession, getSession, openSessionSocket, CreateSessionResponse, SessionState } from "./api";
import { AtmFrame } from "./components/AtmFrame";
import { ScanFrame } from "./components/ScanFrame";
import { CheckMark } from "./components/CheckMark";

type Screen = "idle" | "menu" | "qr" | "approved" | "withdraw" | "done" | "expired";

export function App() {
  const [screen, setScreen] = useState<Screen>("idle");
  const [session, setSession] = useState<CreateSessionResponse | null>(null);
  const [customer, setCustomer] = useState<string | undefined>();
  const [remaining, setRemaining] = useState(0);
  const wsRef = useRef<WebSocket | null>(null);
  const timerRef = useRef<number | null>(null);
  const pollRef = useRef<number | null>(null);

  useEffect(() => () => {
    wsRef.current?.close();
    if (timerRef.current) window.clearInterval(timerRef.current);
    if (pollRef.current) window.clearInterval(pollRef.current);
  }, []);

  async function startCardless() {
    const s = await createSession();
    setSession(s);
    setScreen("qr");
    setRemaining(s.ttlSeconds);

    if (timerRef.current) window.clearInterval(timerRef.current);
    timerRef.current = window.setInterval(() => {
      const left = Math.max(0, Math.ceil((s.expiresAt - Date.now()) / 1000));
      setRemaining(left);
      if (left <= 0) {
        window.clearInterval(timerRef.current!);
        if (pollRef.current) window.clearInterval(pollRef.current);
        setScreen((cur) => (cur === "qr" ? "expired" : cur));
      }
    }, 250);

    const ws = openSessionSocket(s.sessionId);
    wsRef.current = ws;
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.type === "approved") {
        if (pollRef.current) window.clearInterval(pollRef.current);
        const sess = msg.session as SessionState;
        setCustomer(sess.approvedByCustomerRef);
        setScreen("approved");
      }
    };

    // P1 Security & Resilience: If WebSocket connection drops, fallback to GET /api/session/:id polling
    ws.onclose = () => {
      if (!pollRef.current) {
        pollRef.current = window.setInterval(async () => {
          try {
            const sess = await getSession(s.sessionId);
            if (sess.status === "approved") {
              if (pollRef.current) window.clearInterval(pollRef.current);
              setCustomer(sess.approvedByCustomerRef);
              setScreen("approved");
            } else if (sess.status === "expired") {
              if (pollRef.current) window.clearInterval(pollRef.current);
              setScreen("expired");
            }
          } catch {
            // Ignore intermittent network glitches during polling
          }
        }, 1500);
      }
    };
  }

  function reset() {
    wsRef.current?.close();
    if (timerRef.current) window.clearInterval(timerRef.current);
    if (pollRef.current) window.clearInterval(pollRef.current);
    setSession(null);
    setCustomer(undefined);
    setScreen("idle");
  }

  async function withdraw(amount: number) {
    if (session) await consumeSession(session.sessionId);
    setScreen("done");
    setTimeout(reset, 4000);
    // NOTE: Amount is NOT logged to console — browser developer tools are
    // accessible on shared/kiosk machines. Amounts are recorded by the backend
    // audit log (session.consumed event) instead.
    void amount;
  }


  const atmId = session?.atmId ?? "ATM-DEMO-001";

  return (
    <AtmFrame atmId={atmId}>
      {screen === "idle" && (
        <div className="screen-pane idle-pane">
          <div className="wordmark">
            DEMOBANK<span className="cursor" />
          </div>
          <p className="lede">Insert your card or use cardless access from your bank's mobile app.</p>
          <div className="menu">
            <button className="btn" disabled>Insert Card (disabled in demo)</button>
            <button className="btn primary" onClick={() => setScreen("menu")}>
              Continue
            </button>
          </div>
        </div>
      )}

      {screen === "menu" && (
        <div className="screen-pane">
          <h2>Select a service</h2>
          <div className="menu">
            <button className="btn" disabled>Balance Enquiry</button>
            <button className="btn" disabled>Cash Withdrawal (Card)</button>
            <button className="btn" disabled>Transfer</button>
            <button className="btn primary" onClick={startCardless}>
              Cardless Cash Withdrawal
            </button>
          </div>
          <button className="btn ghost" onClick={reset}>Cancel</button>
        </div>
      )}

      {screen === "qr" && session && (
        <div className="screen-pane qr-pane">
          <h2>Scan with your bank app</h2>
          <p>
            Open your bank's mobile app, choose <strong>Cardless ATM Access</strong>, and scan this code.
          </p>
          <ScanFrame remaining={remaining} ttl={session.ttlSeconds}>
            <QRCodeCanvas value={session.qrToken} size={216} />
          </ScanFrame>
          <div className="qr-meta">
            <span>Session expires in</span>
            <span className="timer">{remaining}s</span>
          </div>
          <button className="btn ghost" onClick={reset}>Cancel</button>
        </div>
      )}

      {screen === "approved" && (
        <div className="screen-pane center-pane">
          <CheckMark />
          <div className="success-title">Authenticated</div>
          <p>Welcome{customer ? `, ${customer}` : ""}. Please select an amount.</p>
          <button className="btn primary" onClick={() => setScreen("withdraw")}>Continue</button>
        </div>
      )}

      {screen === "withdraw" && (
        <div className="screen-pane">
          <h2>Select amount</h2>
          <div className="amounts keypad">
            {[20, 50, 100, 200, 500, 1000].map((a) => (
              <button key={a} className="btn primary key" onClick={() => withdraw(a)}>
                £{a}
              </button>
            ))}
          </div>
          <button className="btn ghost" onClick={reset}>Cancel</button>
        </div>
      )}

      {screen === "done" && (
        <div className="screen-pane center-pane">
          <div className="cash-slot">
            <div className="cash-note" />
            <div className="cash-note delay-1" />
            <div className="cash-note delay-2" />
          </div>
          <div className="success-title">Please take your cash</div>
          <p>Returning to home screen…</p>
        </div>
      )}

      {screen === "expired" && (
        <div className="screen-pane center-pane">
          <h2>Session expired</h2>
          <p>The QR code timed out for your security.</p>
          <button className="btn primary" onClick={reset}>Start over</button>
        </div>
      )}
    </AtmFrame>
  );
}
