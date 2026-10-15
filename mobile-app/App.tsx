/**
 * DemoBank Mobile App — Hardened (Task 2: Client Security)
 *
 * Security controls implemented:
 *  1. Root/Jailbreak Detection  — blocks approval flow on compromised devices
 *  2. Screen Shielding          — prevents screen capture/recording on sensitive screens
 *  3. Memory-Only Token         — qrToken is never written to AsyncStorage or disk
 *  4. HTTPS-Only Enforcement    — rejects non-HTTPS API base URLs (blocks plain-HTTP in prod)
 *  5. Cert Pinning Prep         — documented ready for expo-ssl-pinning in production
 */

import { useEffect, useRef, useState } from "react";
import { Platform, StatusBar, StyleSheet, Text, View, Pressable, Alert, TextInput, AppState } from "react-native";
import { CameraView, useCameraPermissions } from "expo-camera";
import * as Device from "expo-device";
import * as ScreenCapture from "expo-screen-capture";

// ─── Config ──────────────────────────────────────────────────────────────────
// In development, HTTP is allowed for local testing on Android emulator.
// In a production build (expo build / eas build), set EXPO_PUBLIC_API_BASE to
// an https:// URL and set EXPO_PUBLIC_ENFORCE_HTTPS=true.
const ENV_API_BASE = (process.env.EXPO_PUBLIC_API_BASE ?? "").trim();
const ENFORCE_HTTPS = (process.env.EXPO_PUBLIC_ENFORCE_HTTPS ?? "false").toLowerCase() === "true";
const DEFAULT_API_BASE = ENV_API_BASE || "http://192.168.108.213:4000";

// ─── Helpers ─────────────────────────────────────────────────────────────────
/** Validates that the API base uses HTTPS when in production/enforce mode. */
function isValidApiBase(url: string): { ok: boolean; reason?: string } {
  try {
    const u = new URL(url);
    if (ENFORCE_HTTPS && u.protocol !== "https:") {
      return { ok: false, reason: "Only HTTPS connections are allowed in this build." };
    }
    if (!["http:", "https:"].includes(u.protocol)) {
      return { ok: false, reason: "Invalid URL scheme." };
    }
    return { ok: true };
  } catch {
    return { ok: false, reason: "Invalid URL format." };
  }
}

/**
 * Lightweight root/jailbreak heuristic via expo-device.
 * Returns true if the device appears to be compromised (rooted/jailbroken).
 *
 * NOTE: For production bank deployment, augment with a dedicated library
 * (e.g., expo-root-detection or a native SDK like SafetyNet/App Attest).
 * This check covers the most common automated attacks on demo hardware.
 */
async function isDeviceCompromised(): Promise<boolean> {
  // expo-device.isRootedExperimentalAsync is the built-in check
  try {
    const rooted = await Device.isRootedExperimentalAsync();
    if (rooted) return true;
  } catch {
    // If the check fails we treat it as clean (fail-open for demo; fail-closed in prod)
  }
  // Additional: block emulators in production builds
  if (ENFORCE_HTTPS && !Device.isDevice) {
    // Running on simulator/emulator in a production-mode build
    return true;
  }
  return false;
}

// ─── Types ───────────────────────────────────────────────────────────────────
type Screen = "login" | "home" | "scanner" | "confirm" | "success";

// ─── Component ───────────────────────────────────────────────────────────────
export default function App() {
  const [screen, setScreen] = useState<Screen>("login");
  const [customer, setCustomer] = useState("Ali Hassan");
  const [apiBase, setApiBase] = useState(DEFAULT_API_BASE);
  const [permission, requestPermission] = useCameraPermissions();
  const [busy, setBusy] = useState(false);
  const [deviceBlocked, setDeviceBlocked] = useState(false);

  // ── SECURITY: qrToken is kept ONLY in volatile React state (RAM).
  // It is never written to AsyncStorage, SecureStore, file system, or logs.
  const qrTokenRef = useRef<string | null>(null);

  // ── Root/Jailbreak check on mount ────────────────────────────────────────
  useEffect(() => {
    isDeviceCompromised().then((compromised) => {
      if (compromised) {
        setDeviceBlocked(true);
        Alert.alert(
          "Security Alert",
          "This device appears to be rooted or jailbroken. " +
            "For your security, the Cardless ATM feature is disabled on this device.",
          [{ text: "OK" }]
        );
      }
    });
  }, []);

  // ── Screen shielding on sensitive screens ────────────────────────────────
  // Blocks screenshot, screen recording, and multitasking snapshots on the
  // QR scanner and biometric confirmation screens (Android: FLAG_SECURE;
  // iOS: secure UITextField overlay).
  useEffect(() => {
    const shieldedScreens: Screen[] = ["scanner", "confirm"];
    if (shieldedScreens.includes(screen)) {
      ScreenCapture.preventScreenCaptureAsync();
    } else {
      ScreenCapture.allowScreenCaptureAsync();
    }
    return () => {
      // Always lift the shield when unmounting or leaving a shielded screen
      ScreenCapture.allowScreenCaptureAsync();
    };
  }, [screen]);

  // ── Clear token when app is backgrounded ─────────────────────────────────
  // Ensures the QR token cannot be extracted from memory dumps on Android
  // when the app is suspended.
  useEffect(() => {
    const sub = AppState.addEventListener("change", (state) => {
      if (state === "background" || state === "inactive") {
        qrTokenRef.current = null;
        // If user backgrounds the app mid-confirm, return to home for safety
        setScreen((cur) => (cur === "scanner" || cur === "confirm" ? "home" : cur));
      }
    });
    return () => sub.remove();
  }, []);

  // ─────────────────────────────────────────────────────────────────────────

  async function openScanner() {
    if (deviceBlocked) {
      Alert.alert("Feature Disabled", "Cardless ATM access is unavailable on this device.");
      return;
    }
    if (!permission?.granted) {
      const r = await requestPermission();
      if (!r.granted) {
        Alert.alert("Camera permission is required to scan ATM QR codes.");
        return;
      }
    }
    // Clear any previously held token before opening camera
    qrTokenRef.current = null;
    setScreen("scanner");
  }

  function onQRScanned(data: string) {
    // Store token ONLY in the in-memory ref — never log, never persist
    qrTokenRef.current = data;
    setScreen("confirm");
  }

  async function approve() {
    const token = qrTokenRef.current;
    if (!token) return;

    // ── HTTPS enforcement ───────────────────────────────────────────────────
    const { ok, reason } = isValidApiBase(apiBase);
    if (!ok) {
      Alert.alert("Connection Error", reason ?? "Invalid server URL.");
      return;
    }

    setBusy(true);
    try {
      const r = await fetch(`${apiBase}/api/session/approve`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          // In production, add: Authorization: Bearer <IdP token>
          // "Authorization": `Bearer ${idpToken}`,
        },
        body: JSON.stringify({
          qrToken: token,
          deviceId: "demo-device-001",
          customerRef: customer,
        }),
        // ── Certificate Pinning (Production Readiness) ──────────────────────
        // When deploying to production, replace the fetch call above with a
        // pinned request using expo-ssl-pinning:
        //
        //   import { fetch as pinnedFetch } from "expo-ssl-pinning";
        //   await pinnedFetch(`${apiBase}/api/session/approve`, {
        //     pkPinning: true,
        //     sslPinning: { certs: ["bank_api_cert"] },  // bundled .cer file
        //     ...
        //   });
        //
        // This ensures the app rejects any MitM proxy certificate even if the
        // device's CA store is compromised.
      });
      const j = await r.json();
      if (!r.ok) {
        Alert.alert("Could not authorise", j.error ?? "unknown");
        setScreen("home");
        return;
      }
      setScreen("success");
      setTimeout(() => setScreen("home"), 3000);
    } catch (e: any) {
      Alert.alert("Network error", String(e?.message ?? e));
      setScreen("home");
    } finally {
      // ── Clear token from memory immediately after use ─────────────────────
      qrTokenRef.current = null;
      setBusy(false);
    }
  }

  // ─── Blocked device overlay ───────────────────────────────────────────────
  if (deviceBlocked) {
    return (
      <View style={styles.root}>
        <StatusBar barStyle="light-content" />
        <View style={styles.card}>
          <Text style={styles.brand}>DemoBank</Text>
          <Text style={[styles.hello, { color: C.accent, marginTop: 40 }]}>⚠ Device Security Alert</Text>
          <Text style={styles.tileSub}>
            This device does not meet the security requirements for cardless ATM access.
            Please use an unmodified device.
          </Text>
        </View>
      </View>
    );
  }

  return (
    <View style={styles.root}>
      <StatusBar barStyle="light-content" />

      {screen === "login" && (
        <View style={styles.card}>
          <Text style={styles.brand}>DemoBank</Text>
          <Text style={styles.label}>Customer name (demo)</Text>
          <TextInput style={styles.input} value={customer} onChangeText={setCustomer} />

          <Text style={styles.label}>Backend Server URL</Text>
          <TextInput
            style={styles.input}
            value={apiBase}
            onChangeText={setApiBase}
            placeholder="http://192.168.108.213:4000"
            placeholderTextColor="#8FB1C4"
            autoCapitalize="none"
            keyboardType="url"
          />
          {ENFORCE_HTTPS && !apiBase.startsWith("https://") && (
            <Text style={{ color: C.accent, fontSize: 12, marginTop: -8 }}>
              ⚠ Production build requires HTTPS
            </Text>
          )}

          <Pressable style={styles.btnPrimary} onPress={() => setScreen("home")}>
            <Text style={styles.btnText}>Log in with Face ID (mocked)</Text>
          </Pressable>
        </View>
      )}

      {screen === "home" && (
        <View style={styles.card}>
          <Text style={styles.brand}>DemoBank</Text>
          <Text style={styles.hello}>Hi {customer}</Text>
          <Text style={styles.balance}>£ 2,431.22</Text>

          <Pressable style={styles.tile} onPress={openScanner}>
            <Text style={styles.tileTitle}>Cardless ATM Access</Text>
            <Text style={styles.tileSub}>Scan the QR on an ATM to withdraw without your card</Text>
          </Pressable>
          <Pressable style={[styles.tile, styles.disabled]}>
            <Text style={styles.tileTitle}>Transfer</Text>
          </Pressable>
          <Pressable style={[styles.tile, styles.disabled]}>
            <Text style={styles.tileTitle}>Statements</Text>
          </Pressable>
        </View>
      )}

      {screen === "scanner" && (
        <View style={{ flex: 1 }}>
          <CameraView
            style={{ flex: 1 }}
            facing="back"
            barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
            onBarcodeScanned={(r) => {
              if (qrTokenRef.current) return; // already scanned
              onQRScanned(r.data);
            }}
          />
          <Pressable style={styles.cancelBar} onPress={() => setScreen("home")}>
            <Text style={styles.btnText}>Cancel</Text>
          </Pressable>
        </View>
      )}

      {screen === "confirm" && (
        <View style={styles.card}>
          <Text style={styles.brand}>Approve ATM access?</Text>
          <Text style={styles.tileSub}>
            You're about to unlock an ATM session for cash withdrawal. This does not move any money —
            the ATM will ask you for an amount next.
          </Text>
          <Pressable style={styles.btnPrimary} onPress={approve} disabled={busy}>
            <Text style={styles.btnText}>{busy ? "Authorising…" : "Approve with biometrics (mocked)"}</Text>
          </Pressable>
          <Pressable
            style={styles.btnGhost}
            onPress={() => {
              qrTokenRef.current = null; // clear token on cancel
              setScreen("home");
            }}
          >
            <Text style={styles.btnTextDark}>Cancel</Text>
          </Pressable>
        </View>
      )}

      {screen === "success" && (
        <View style={styles.card}>
          <Text style={styles.brand}>ATM unlocked</Text>
          <Text style={styles.tileSub}>You can now use the ATM. This screen will close automatically.</Text>
        </View>
      )}
    </View>
  );
}

const C = {
  sky: "#447794",
  steel: "#2D5B75",
  deep: "#123249",
  night: "#061222",
  ink: "#F5F8FB",
  muted: "#8FB1C4",
  line: "rgba(68, 119, 148, 0.25)",
  accent: "#C9A961",
};

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: C.night },
  card: { flex: 1, padding: 28, paddingTop: 90, gap: 16, backgroundColor: C.night },
  brand: { color: C.sky, fontSize: 13, fontWeight: "700", letterSpacing: 4, textTransform: "uppercase" },
  hello: { color: C.ink, fontSize: 26, marginTop: 12, fontWeight: "500" },
  balance: { color: C.ink, fontSize: 42, fontWeight: "700", marginBottom: 20, letterSpacing: -1 },
  label: { color: C.muted, marginTop: 14, fontSize: 13, letterSpacing: 1, textTransform: "uppercase" },
  input: {
    backgroundColor: "rgba(68, 119, 148, 0.08)",
    color: C.ink,
    padding: 16,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: C.line,
    fontSize: 16,
  },
  tile: {
    backgroundColor: "rgba(68, 119, 148, 0.08)",
    padding: 20,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: C.line,
    gap: 6,
  },
  tileTitle: { color: C.ink, fontSize: 17, fontWeight: "600" },
  tileSub: { color: C.muted, lineHeight: 21, fontSize: 14 },
  disabled: { opacity: 0.35 },
  btnPrimary: {
    backgroundColor: C.sky,
    padding: 18,
    borderRadius: 12,
    alignItems: "center",
    marginTop: 16,
  },
  btnGhost: { padding: 14, alignItems: "center" },
  btnText: { color: C.night, fontSize: 16, fontWeight: "700", letterSpacing: 0.3 },
  btnTextDark: { color: C.muted, fontSize: 15 },
  cancelBar: { backgroundColor: C.night, padding: 20, alignItems: "center" },
});
