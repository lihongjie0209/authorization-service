package authorization

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/authorization-service/internal/database"
	"github.com/lihongjie0209/microservice-platform-go/eventbus"
	commonv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/common/v1"
	tenantv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/tenant/v1"
)

type GroupProjection struct {
	db         *sqlx.DB
	transactor *database.Transactor
	service    *Service
}

func NewGroupProjection(db *sqlx.DB, transactor *database.Transactor, services ...*Service) *GroupProjection {
	projection := &GroupProjection{db: db, transactor: transactor}
	if len(services) > 0 {
		projection.service = services[0]
	}
	return projection
}

func NewRuntimeGroupProjection(db *sqlx.DB, transactor *database.Transactor, service *Service) *GroupProjection {
	return NewGroupProjection(db, transactor, service)
}

func (p *GroupProjection) Apply(ctx context.Context, envelope *commonv1.EventEnvelope) error {
	if envelope == nil || envelope.GetEventId() == "" {
		return fmt.Errorf("group projection requires event envelope")
	}
	event := new(tenantv1.GroupChangedEvent)
	if err := eventbus.DecodePayload(envelope, event); err != nil {
		return fmt.Errorf("decode tenant group event: %w", err)
	}
	if event.GetGroup().GetTenantId() == "" || event.GetGroup().GetId() == "" || event.GetMembershipId() == "" {
		return nil
	}
	status := ""
	switch event.GetChangeType() {
	case "member_added":
		status = "active"
	case "member_removed":
		status = "removed"
	default:
		return nil
	}
	occurredAt := envelope.GetOccurredAt().AsTime()
	if occurredAt.IsZero() {
		occurredAt = time.Now()
	}
	actor := "event-consumer"
	if envelope.GetContext().GetActorId() != "" {
		actor = envelope.GetContext().GetActorId()
	}
	err := p.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		inserted, err := p.markProcessed(ctx, tx, envelope.GetEventId(), envelope.GetEventType(), occurredAt)
		if err != nil || !inserted {
			return err
		}
		if err := p.upsertMembershipGroup(ctx, tx, event.GetGroup().GetTenantId(), event.GetMembershipId(), event.GetGroup().GetId(), status, occurredAt, actor); err != nil {
			return err
		}
		_, err = p.bumpPolicyVersion(ctx, tx, event.GetGroup().GetTenantId(), occurredAt)
		return err
	})
	if err == nil && p.service != nil {
		_ = p.service.InvalidateSubject(event.GetGroup().GetTenantId(), event.GetMembershipId(), "membership")
	}
	return err
}

func (p *GroupProjection) markProcessed(ctx context.Context, tx *sqlx.Tx, eventID, eventType string, now time.Time) (bool, error) {
	query := "INSERT INTO authorization_processed_events (event_id, event_type, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, 1, ?, ?, 'event-consumer', 'event-consumer') ON CONFLICT (event_id) DO NOTHING"
	if p.db.DriverName() == "mysql" {
		query = "INSERT IGNORE INTO authorization_processed_events (event_id, event_type, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, 1, ?, ?, 'event-consumer', 'event-consumer')"
	}
	result, err := tx.ExecContext(ctx, p.db.Rebind(query), eventID, eventType, now, now)
	if err != nil {
		return false, fmt.Errorf("record processed authorization event: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("processed authorization event affected rows: %w", err)
	}
	return count == 1, nil
}

func (p *GroupProjection) upsertMembershipGroup(ctx context.Context, tx *sqlx.Tx, tenantID, membershipID, groupID, status string, occurredAt time.Time, actor string) error {
	query := "INSERT INTO authorization_subject_groups (tenant_id, membership_id, group_id, status, source_occurred_at, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?) ON CONFLICT (tenant_id, membership_id, group_id) DO UPDATE SET status = EXCLUDED.status, source_occurred_at = EXCLUDED.source_occurred_at, version = authorization_subject_groups.version + 1, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by WHERE EXCLUDED.source_occurred_at >= authorization_subject_groups.source_occurred_at"
	if p.db.DriverName() == "mysql" {
		query = "INSERT INTO authorization_subject_groups (tenant_id, membership_id, group_id, status, source_occurred_at, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE status = IF(VALUES(source_occurred_at) >= source_occurred_at, VALUES(status), status), version = IF(VALUES(source_occurred_at) >= source_occurred_at, version + 1, version), updated_at = IF(VALUES(source_occurred_at) >= source_occurred_at, VALUES(updated_at), updated_at), updated_by = IF(VALUES(source_occurred_at) >= source_occurred_at, VALUES(updated_by), updated_by), source_occurred_at = GREATEST(source_occurred_at, VALUES(source_occurred_at))"
	}
	_, err := tx.ExecContext(ctx, p.db.Rebind(query), tenantID, membershipID, groupID, status, occurredAt, occurredAt, occurredAt, actor, actor)
	if err != nil {
		return fmt.Errorf("upsert authorization subject group: %w", err)
	}
	return nil
}

func (p *GroupProjection) bumpPolicyVersion(ctx context.Context, tx *sqlx.Tx, tenantID string, now time.Time) (uint64, error) {
	repository := &SQLRepository{db: p.db}
	return repository.BumpPolicyVersion(ctx, tx, tenantID, now, "event-consumer")
}
