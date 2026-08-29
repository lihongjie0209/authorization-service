package authorization

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/microservice-platform-go/outbox"
	commonv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/common/v1"
	"google.golang.org/protobuf/proto"
)

type OutboxStore struct {
	db  *sqlx.DB
	now func() time.Time
}

func NewOutboxStore(db *sqlx.DB) *OutboxStore { return &OutboxStore{db: db, now: time.Now} }

func (s *OutboxStore) Claim(ctx context.Context, limit int, lease time.Duration) ([]outbox.Event, error) {
	if s.db == nil {
		return nil, fmt.Errorf("claim authorization outbox: database is disabled")
	}
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin authorization outbox claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	now := s.now()
	type row struct {
		ID       string `db:"id"`
		Subject  string `db:"subject"`
		Envelope []byte `db:"envelope"`
	}
	rows := make([]row, 0)
	query := s.db.Rebind("SELECT id, subject, envelope FROM authorization_outbox_events WHERE published_at IS NULL AND available_at <= ? ORDER BY available_at, created_at LIMIT ? FOR UPDATE SKIP LOCKED")
	if err := tx.SelectContext(ctx, &rows, query, now, limit); err != nil {
		return nil, fmt.Errorf("select authorization outbox events: %w", err)
	}
	events := make([]outbox.Event, 0, len(rows))
	for _, item := range rows {
		envelope := new(commonv1.EventEnvelope)
		if err := proto.Unmarshal(item.Envelope, envelope); err != nil {
			return nil, fmt.Errorf("decode authorization outbox event %q: %w", item.ID, err)
		}
		update := s.db.Rebind("UPDATE authorization_outbox_events SET attempts = attempts + 1, available_at = ?, version = version + 1, updated_at = ?, updated_by = 'outbox-dispatcher' WHERE id = ? AND published_at IS NULL")
		if _, err := tx.ExecContext(ctx, update, now.Add(lease), now, item.ID); err != nil {
			return nil, fmt.Errorf("lease authorization outbox event %q: %w", item.ID, err)
		}
		events = append(events, outbox.Event{ID: item.ID, Subject: item.Subject, Envelope: envelope})
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit authorization outbox claim: %w", err)
	}
	return events, nil
}

func (s *OutboxStore) MarkPublished(ctx context.Context, event outbox.Event, publishedAt time.Time) error {
	result, err := s.db.ExecContext(ctx, s.db.Rebind("UPDATE authorization_outbox_events SET published_at = ?, version = version + 1, updated_at = ?, updated_by = 'outbox-dispatcher', last_error = '' WHERE id = ? AND published_at IS NULL"), publishedAt, publishedAt, event.ID)
	return outboxAffected(result, err, event.ID)
}
func (s *OutboxStore) MarkFailed(ctx context.Context, event outbox.Event, message string, retryAt time.Time) error {
	if len(message) > 4096 {
		message = message[:4096]
	}
	result, err := s.db.ExecContext(ctx, s.db.Rebind("UPDATE authorization_outbox_events SET available_at = ?, last_error = ?, version = version + 1, updated_at = ?, updated_by = 'outbox-dispatcher' WHERE id = ? AND published_at IS NULL"), retryAt, message, s.now(), event.ID)
	return outboxAffected(result, err, event.ID)
}
func outboxAffected(result sql.Result, err error, eventID string) error {
	if err != nil {
		return fmt.Errorf("update authorization outbox event %q: %w", eventID, err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("authorization outbox event %q affected rows: %w", eventID, err)
	}
	if count != 1 {
		return fmt.Errorf("authorization outbox event %q is no longer pending", eventID)
	}
	return nil
}
