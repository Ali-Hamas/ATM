# Running the demo locally

The Go backend serves **the ATM web UI, the REST API, and the WebSocket from the same port**. You only need two terminals: one for the backend, one for the mobile app.

## Prereqs

- Go 1.22+ — https://go.dev/dl/
- Node.js 20+ and npm (only for the mobile app and for rebuilding the ATM UI)
- For testing the mobile app on a real device: Expo Go from the App Store / Play Store
- Phone and laptop on the same Wi-Fi (if using a real phone)

## 1. Backend + ATM UI (one terminal)

```bash
cd backend-go
go run ./cmd/server
```

You should see:
```
auth middleware listening on :4000
ws endpoint  ws://localhost:4000/ws?sid=<sessionId>
```

Open the ATM in your browser:
```
http://localhost:4000
```

That's the ATM simulator screen. **No `npm run dev` needed** — the built UI is embedded inside the Go binary.

## 2. Mobile app (Expo)

```bash
cd mobile-app
npm install              # first time only
npx expo start
```

### Pointing the app at your backend

The mobile app defaults to `http://10.0.2.2:4000` (the Android emulator's loopback). For other targets, edit `API_BASE` in `mobile-app/App.tsx`:

- **Real phone (Expo Go)** — `http://<your-laptop-LAN-IP>:4000` (find it with `ipconfig` on Windows; look at the Wi-Fi IPv4 address)
- **iOS simulator** — `http://localhost:4000`

Allow port 4000 through Windows Firewall when prompted.

Scan the Expo QR with your phone (Android: Expo Go's scanner; iOS: the Camera app).

## 3. The demo

1. In `http://localhost:4000` (the ATM tab): click **Continue** → **Cardless Cash Withdrawal**. A QR appears inside a gold scanning ring with a 60s countdown.
2. On your phone's bank app: tap **Cardless ATM Access** → grant camera permission → point at the QR.
3. Tap **Approve with biometrics (mocked)**.
4. The ATM tab flips to **Authenticated** within a second — that's the WebSocket push.
5. Pick an amount → cash dispense animation → resets to idle.

## Rebuilding the ATM UI

If you edit anything under `atm-simulator/src/`, rebuild and re-embed:

```bash
cd atm-simulator
npm install              # first time only
npm run build            # produces dist/
cp -r dist/* ../backend-go/internal/web/static/
cd ../backend-go
go run ./cmd/server      # picks up the new build
```

## Production-style binary

```bash
cd backend-go
go build -o atm-auth.exe ./cmd/server
./atm-auth.exe
```

The result is a single ~10 MB executable with no external dependencies. Copy it anywhere; it serves the entire ATM stack.

## Troubleshooting

- **App stuck on "Authorising…"** — phone can't reach the backend. Check `API_BASE` is your laptop's LAN IP and that the firewall allows port 4000.
- **`go: command not found`** — install Go, then close and re-open your terminal.
- **Browser shows old UI after editing source** — you forgot to rebuild + re-embed (see *Rebuilding the ATM UI*). The Go binary embeds the UI at compile time.
- **"session_expired"** — QR expires in 60s by default. Set `SESSION_TTL_SECONDS=120` before starting the backend if you need a longer demo window.
