package session

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

var (
	ErrSessionNotFound = errors.New("ERR_SESSION_NOT_FOUND")
	ErrSessionExpired  = errors.New("ERR_SESSION_EXPIRED")
)

// SessionStore abstracts session persistence, allowing seamless switching
// between distributed Redis clusters and in-memory storage.
type SessionStore interface {
	Put(sess *Session) error
	Get(id string) (*Session, bool)
	TransitionToApproved(id string, deviceID, customerRef string) (*Session, error)
	TransitionToConsumed(id string) (*Session, error)
	Log(entry AuditEntry)
	Audit() []AuditEntry
	RunSweeper(ctx context.Context)
}

// Store is a thread-safe in-memory implementation of SessionStore.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	audit    []AuditEntry
}

func NewStore() *Store {
	return &Store{sessions: make(map[string]*Session)}
}

func (s *Store) Put(sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
	return nil
}

// Get returns a session, lazily marking it expired if its TTL passed while pending.
// Returns (nil, false) if not found.
func (s *Store) Get(id string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, false
	}
	if sess.Status == StatusPending && nowMillis() > sess.ExpiresAt {
		sess.Status = StatusExpired
		s.logLocked(AuditEntry{Ts: nowMillis(), SessionID: sess.ID, Event: "session.expired"})
	}
	return sess, true
}

// TransitionToApproved atomically transitions a session from 'pending' to 'approved'.
// Mimics the exact behavior of the Redis atomic Lua script.
func (s *Store) TransitionToApproved(id string, deviceID, customerRef string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return nil, ErrSessionNotFound
	}

	if sess.Status != StatusPending {
		return nil, fmt.Errorf("ERR_CONFLICT_%s", sess.Status)
	}

	now := nowMillis()
	if now > sess.ExpiresAt {
		sess.Status = StatusExpired
		s.logLocked(AuditEntry{Ts: now, SessionID: sess.ID, Event: "session.expired"})
		return nil, ErrSessionExpired
	}

	sess.Status = StatusApproved
	sess.ApprovedAt = now
	sess.ApprovedByDeviceID = deviceID
	sess.ApprovedByCustomerRef = customerRef

	// Return a copy to prevent external mutation
	copied := *sess
	return &copied, nil
}

// TransitionToConsumed atomically transitions a session from 'approved' to 'consumed'.
// Mimics the exact behavior of the Redis atomic Lua script.
func (s *Store) TransitionToConsumed(id string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return nil, ErrSessionNotFound
	}

	if sess.Status != StatusApproved {
		return nil, fmt.Errorf("ERR_CONFLICT_%s", sess.Status)
	}

	sess.Status = StatusConsumed
	sess.ConsumedAt = nowMillis()

	copied := *sess
	return &copied, nil
}

// Update applies a function under the write lock and returns the updated session.
func (s *Store) Update(id string, mutate func(*Session)) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, false
	}
	mutate(sess)
	return sess, true
}

func (s *Store) Log(entry AuditEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logLocked(entry)
}

func (s *Store) logLocked(entry AuditEntry) {
	s.audit = append(s.audit, entry)
	log.Printf("[audit] %s %s sid=%s %v",
		time.UnixMilli(entry.Ts).UTC().Format(time.RFC3339),
		entry.Event, entry.SessionID, entry.Detail)
}

func (s *Store) Audit() []AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEntry, len(s.audit))
	copy(out, s.audit)
	return out
}

// RunSweeper expires pending sessions past their TTL every 5s until ctx is done.
func (s *Store) RunSweeper(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepOnce()
		}
	}
}

func (s *Store) sweepOnce() {
	now := nowMillis()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		if sess.Status == StatusPending && now > sess.ExpiresAt {
			sess.Status = StatusExpired
			s.logLocked(AuditEntry{Ts: now, SessionID: sess.ID, Event: "session.expired"})
		}
	}
}

func nowMillis() int64 { return time.Now().UnixMilli() }
