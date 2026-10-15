package session_test

import (
	"strings"
	"testing"
	"time"

	"github.com/demobank/atm-auth/internal/session"
)

func TestStoreStateTransitions(t *testing.T) {
	store := session.NewStore()

	now := time.Now().UnixMilli()
	sess := &session.Session{
		ID:        "test-atomic-session",
		AtmID:     "ATM-TEST-001",
		Status:    session.StatusPending,
		CreatedAt: now,
		ExpiresAt: now + 60000,
	}

	if err := store.Put(sess); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// 1. Transition to Approved
	approved, err := store.TransitionToApproved("test-atomic-session", "dev-phone-1", "Ali Hassan")
	if err != nil {
		t.Fatalf("TransitionToApproved failed: %v", err)
	}
	if approved.Status != session.StatusApproved {
		t.Errorf("expected approved status, got %s", approved.Status)
	}
	if approved.ApprovedByCustomerRef != "Ali Hassan" {
		t.Errorf("expected customer Ali Hassan, got %s", approved.ApprovedByCustomerRef)
	}

	// 2. Cannot approve an already-approved session (race condition / double-approve attack prevention)
	_, err = store.TransitionToApproved("test-atomic-session", "dev-phone-2", "Attacker")
	if err == nil || !strings.Contains(err.Error(), "CONFLICT") {
		t.Fatalf("expected conflict error when re-approving, got %v", err)
	}

	// 3. Transition to Consumed
	consumed, err := store.TransitionToConsumed("test-atomic-session")
	if err != nil {
		t.Fatalf("TransitionToConsumed failed: %v", err)
	}
	if consumed.Status != session.StatusConsumed {
		t.Errorf("expected consumed status, got %s", consumed.Status)
	}

	// 4. Cannot consume an already-consumed session (double-dispense prevention)
	_, err = store.TransitionToConsumed("test-atomic-session")
	if err == nil || !strings.Contains(err.Error(), "CONFLICT") {
		t.Fatalf("expected conflict error when re-consuming, got %v", err)
	}
}

func TestStoreExpiredSessionRejection(t *testing.T) {
	store := session.NewStore()

	past := time.Now().UnixMilli() - 10000
	sess := &session.Session{
		ID:        "expired-session",
		AtmID:     "ATM-TEST-001",
		Status:    session.StatusPending,
		CreatedAt: past - 60000,
		ExpiresAt: past, // Expired
	}
	_ = store.Put(sess)

	_, err := store.TransitionToApproved("expired-session", "dev-1", "Ali")
	if err == nil {
		t.Fatal("expected session expired error, got nil")
	}
}
