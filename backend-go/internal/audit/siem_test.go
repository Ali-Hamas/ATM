package audit_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/demobank/atm-auth/internal/audit"
)

func TestSIEMEventFormatting(t *testing.T) {
	logger, err := audit.NewLogger("")
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	ev := audit.SIEMEvent{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		EventAction: "session.approved",
		Outcome:     "success",
		SessionID:   "sess-test-123",
		AtmID:       "ATM-LONDON-01",
		ClientIP:    "192.168.1.50",
		DeviceID:    "device-xyz",
		CustomerRef: "Ali Hassan",
		Detail: map[string]interface{}{
			"auth_method": "biometric_face_id",
		},
	}

	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("failed to marshal SIEM event: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("failed to parse back JSON: %v", err)
	}

	if parsed["event.action"] != "session.approved" {
		t.Errorf("expected event.action 'session.approved', got %v", parsed["event.action"])
	}
	if parsed["session.id"] != "sess-test-123" {
		t.Errorf("expected session.id 'sess-test-123', got %v", parsed["session.id"])
	}
	if parsed["atm.id"] != "ATM-LONDON-01" {
		t.Errorf("expected atm.id 'ATM-LONDON-01', got %v", parsed["atm.id"])
	}
}
