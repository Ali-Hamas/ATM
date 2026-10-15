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

func TestHubSingleSubscriberEviction(t *testing.T) {
	hub := realtime.NewHub()
	ts := httptest.NewServer(hub)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws?sid=sess-test-001"

	// 1. First client connects
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

	// 2. Second client connects with SAME session ID
	ws2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("second dial failed: %v", err)
	}
	defer ws2.Close()

	// Read greeting on client 2
	var msg2 map[string]interface{}
	if err := ws2.ReadJSON(&msg2); err != nil {
		t.Fatalf("failed to read greeting on client 2: %v", err)
	}
	if msg2["type"] != "subscribed" || msg2["sid"] != "sess-test-001" {
		t.Fatalf("unexpected greeting on client 2: %v", msg2)
	}

	// 3. Client 1 should now receive a close message / error due to eviction
	_ = ws1.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err1 := ws1.ReadMessage()
	if err1 == nil {
		t.Errorf("expected client 1 to be evicted and closed, but ReadMessage succeeded")
	}

	// 4. Notify should only reach client 2
	sess := &session.Session{
		ID:                    "sess-test-001",
		AtmID:                 "ATM-DEMO-001",
		Status:                session.StatusApproved,
		ApprovedByCustomerRef: "Test User",
	}
	hub.Notify(sess, "approved")

	_ = ws2.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msgBytes, err2 := ws2.ReadMessage()
	if err2 != nil {
		t.Fatalf("client 2 failed to receive notification: %v", err2)
	}

	var notifyMsg map[string]interface{}
	if err := json.Unmarshal(msgBytes, &notifyMsg); err != nil {
		t.Fatalf("failed to parse notify JSON: %v", err)
	}
	if notifyMsg["type"] != "approved" {
		t.Errorf("expected type 'approved', got %v", notifyMsg["type"])
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
		// Some dialers fail during handshake if server sends close immediately
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
