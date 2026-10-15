package realtime_test

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/demobank/atm-auth/internal/realtime"
	"github.com/demobank/atm-auth/internal/session"
	"github.com/gorilla/websocket"
)

// TestHubRejectSecondSubscriber asserts the hardened single-subscriber policy (CODE-010):
// Prevents an attacker from evicting or hijacking an active ATM terminal's WebSocket session.
func TestHubRejectSecondSubscriber(t *testing.T) {
	hub := realtime.NewHub()
	ts := httptest.NewServer(hub)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws?sid=sess-test-001"

	// 1. First legitimate ATM client connects
	ws1, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("first dial failed: %v", err)
	}
	defer ws1.Close()

	// Read greeting on client 1
	var msg1 map[string]interface{}
	if err := ws1.ReadJSON(&msg1); err != nil {
		t.Fatalf("failed to read greeting on client 1: %v", err)
	}
	if msg1["type"] != "subscribed" || msg1["sid"] != "sess-test-001" {
		t.Fatalf("unexpected greeting on client 1: %v", msg1)
	}

	// 2. Second client attempts to hijack/subscribe with the SAME session ID
	ws2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		defer ws2.Close()
		// Expect client 2 to be closed immediately due to active subscriber reject policy
		_ = ws2.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, _, readErr2 := ws2.ReadMessage()
		if readErr2 == nil {
			t.Errorf("expected client 2 to be rejected and closed, but connection succeeded")
		}
	}

	// 3. Client 1 (the legitimate ATM) MUST still be connected and receive notifications
	sess := &session.Session{
		ID:                    "sess-test-001",
		AtmID:                 "ATM-DEMO-001",
		Status:                session.StatusApproved,
		ApprovedByCustomerRef: "Test User",
	}
	hub.Notify(sess, "approved")

	_ = ws1.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msgBytes, err1 := ws1.ReadMessage()
	if err1 != nil {
		t.Fatalf("legitimate client 1 failed to receive notification: %v", err1)
	}

	var notifyMsg map[string]interface{}
	if err := json.Unmarshal(msgBytes, &notifyMsg); err != nil {
		t.Fatalf("failed to parse notify JSON: %v", err)
	}
	if notifyMsg["type"] != "approved" {
		t.Errorf("expected type 'approved', got %v", notifyMsg["type"])
	}
	if notifyMsg["sessionId"] != "sess-test-001" {
		t.Errorf("expected sessionId 'sess-test-001', got %v", notifyMsg["sessionId"])
	}
}

func TestHubMissingSidRejected(t *testing.T) {
	hub := realtime.NewHub()
	ts := httptest.NewServer(hub)
	defer ts.Close()

	// Dial without sid query param
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	// Should receive close code 1008
	_ = ws.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, _, readErr := ws.ReadMessage()
	if readErr == nil {
		t.Errorf("expected connection without sid to be closed with error")
	}
}
