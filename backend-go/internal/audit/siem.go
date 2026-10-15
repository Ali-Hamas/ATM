package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
)

// SIEMEvent represents an audit event formatted according to the Elastic Common Schema (ECS)
// and Splunk Common Information Model (CIM) standards for enterprise bank SIEM ingestion.
type SIEMEvent struct {
	Timestamp   string                 `json:"@timestamp"`
	EventAction string                 `json:"event.action"`
	Category    string                 `json:"event.category"`
	Dataset     string                 `json:"event.dataset"`
	Outcome     string                 `json:"event.outcome"` // "success" | "failure"
	SessionID   string                 `json:"session.id,omitempty"`
	AtmID       string                 `json:"atm.id,omitempty"`
	ClientIP    string                 `json:"client.ip,omitempty"`
	DeviceID    string                 `json:"client.device_id,omitempty"`
	CustomerRef string                 `json:"user.name,omitempty"`
	Reason      string                 `json:"error.message,omitempty"`
	Detail      map[string]interface{} `json:"detail,omitempty"`
}

type Logger struct {
	db        *sql.DB
	logStdout bool
}

// NewLogger initializes the SIEM logger.
// If databaseURL is non-empty, opens a connection pool to PostgreSQL.
func NewLogger(databaseURL string) (*Logger, error) {
	l := &Logger{
		logStdout: true,
	}

	if databaseURL != "" {
		db, err := sql.Open("postgres", databaseURL)
		if err != nil {
			return nil, fmt.Errorf("failed to open postgres connection: %w", err)
		}

		db.SetMaxOpenConns(25)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(5 * time.Minute)

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			log.Printf("[audit] Warning: PostgreSQL at DATABASE_URL is unreachable (%v). Falling back to stdout SIEM streaming.", err)
		} else {
			log.Println("[audit] Connected to immutable PostgreSQL audit database.")
			l.db = db
		}
	}

	return l, nil
}

// Record emits a SIEM event to stdout (for log forwarders like Splunk UF/Filebeat)
// and asynchronously persists it to PostgreSQL if configured.
func (l *Logger) Record(ev SIEMEvent) {
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if ev.Category == "" {
		ev.Category = "authentication"
	}
	if ev.Dataset == "" {
		ev.Dataset = "atm_middleware"
	}
	if ev.Outcome == "" {
		ev.Outcome = "success"
	}

	// 1. Stream structured JSON to stdout for SIEM log shippers
	if l.logStdout {
		b, err := json.Marshal(ev)
		if err == nil {
			// Print directly to stdout without prefix so log forwarders parse clean JSON
			fmt.Fprintln(os.Stdout, string(b))
		}
	}

	// 2. Insert into PostgreSQL if connected
	if l.db != nil {
		go func(e SIEMEvent) {
			detailBytes, _ := json.Marshal(e.Detail)
			nowMilli := time.Now().UnixMilli()
			query := `
				INSERT INTO atm_audit_logs (
					ts_milli, session_id, atm_id, event, outcome, client_ip, device_id, customer_ref, failure_reason, detail
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
			_, err := l.db.Exec(query,
				nowMilli,
				e.SessionID,
				e.AtmID,
				e.EventAction,
				e.Outcome,
				e.ClientIP,
				e.DeviceID,
				e.CustomerRef,
				e.Reason,
				detailBytes,
			)
			if err != nil {
				log.Printf("[audit] Error writing to postgres audit_logs: %v", err)
			}
		}(ev)
	}
}

func (l *Logger) Close() error {
	if l.db != nil {
		return l.db.Close()
	}
	return nil
}
