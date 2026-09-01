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

type TenantBootstrapProjection struct {
	db         *sqlx.DB
	transactor *database.Transactor
	repository Repository
	service    *Service
}

func NewRuntimeTenantBootstrapProjection(db *sqlx.DB, transactor *database.Transactor, repository Repository, service *Service) *TenantBootstrapProjection {
	return &TenantBootstrapProjection{db: db, transactor: transactor, repository: repository, service: service}
}

func (p *TenantBootstrapProjection) Apply(ctx context.Context, envelope *commonv1.EventEnvelope) error {
	if envelope == nil || envelope.GetEventId() == "" {
		return fmt.Errorf("tenant bootstrap requires event envelope")
	}
	event := new(tenantv1.TenantCreatedEvent)
	if err := eventbus.DecodePayload(envelope, event); err != nil {
		return fmt.Errorf("decode tenant created event: %w", err)
	}
	tenantID, membershipID := event.GetTenant().GetId(), event.GetOwnerMembershipId()
	if tenantID == "" || membershipID == "" {
		return fmt.Errorf("tenant created event requires tenant and owner membership")
	}
	now := time.Now()
	if envelope.GetOccurredAt() != nil && envelope.GetOccurredAt().IsValid() {
		now = envelope.GetOccurredAt().AsTime()
	}
	actor := event.GetOwnerUserId()
	if actor == "" {
		actor = "tenant-bootstrap"
	}
	err := p.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		inserted, err := markProcessedEvent(ctx, p.db, tx, envelope.GetEventId(), envelope.GetEventType(), now)
		if err != nil || !inserted {
			return err
		}
		if err := p.repository.BootstrapTenantOwner(ctx, tx, tenantID, membershipID, now, actor); err != nil {
			return err
		}
		_, err = p.repository.BumpPolicyVersion(ctx, tx, tenantID, now, actor)
		return err
	})
	if err == nil {
		_ = p.service.InvalidateSubject(tenantID, membershipID, "membership")
	}
	return err
}
