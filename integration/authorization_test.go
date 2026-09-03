//go:build integration

package integration

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	authorizationdomain "github.com/lihongjie0209/authorization-service/internal/authorization"
	"github.com/lihongjie0209/authorization-service/internal/bootstrap"
	"github.com/lihongjie0209/authorization-service/internal/config"
	appdb "github.com/lihongjie0209/authorization-service/internal/database"
	"github.com/lihongjie0209/authorization-service/internal/migration"
	"github.com/lihongjie0209/microservice-platform-go/eventbus"
	platformoutbox "github.com/lihongjie0209/microservice-platform-go/outbox"
	"github.com/lihongjie0209/microservice-platform-go/principal"
	commonv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/common/v1"
	tenantv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/tenant/v1"
)

type authorizationRecordingPublisher struct{ ids []string }

func (p *authorizationRecordingPublisher) Publish(_ context.Context, _ string, envelope *commonv1.EventEnvelope) error {
	p.ids = append(p.ids, envelope.GetEventId())
	return nil
}

func TestAuthorizationDomainCompatibility(t *testing.T) {
	for _, databaseType := range []string{"postgres", "mysql"} {
		t.Run(databaseType, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			dsn, migrationURL := startDatabase(t, ctx, databaseType)
			migrationPath, err := filepath.Abs(filepath.Join("..", "migrations", databaseType))
			if err != nil {
				t.Fatal(err)
			}
			schema := ""
			if databaseType == "postgres" {
				schema = "authorization_domain"
			}
			migrationCfg := config.Migration{Path: migrationPath, DatabaseURL: migrationURL, Table: "authorization_domain_schema_migrations", Schema: schema, CreateSchema: schema != ""}
			if err := migration.Run(migrationCfg, "up", 0); err != nil {
				t.Fatal(err)
			}
			db, err := appdb.Open(ctx, config.Database{Type: databaseType, DSN: dsn, Schema: schema, MaxOpenConns: 5, MaxIdleConns: 2, ConnMaxLifetime: time.Minute, ConnMaxIdleTime: time.Minute, PingTimeout: 10 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			repository := authorizationdomain.NewRepository(db)
			service := authorizationdomain.NewService(repository, appdb.NewTransactor(db))
			if _, err := bootstrap.GrantPlatformSuperAdmin(ctx, db, "platform-user-1", "user"); err != nil {
				t.Fatalf("GrantPlatformSuperAdmin() error = %v", err)
			}
			if _, err := bootstrap.GrantPlatformSuperAdmin(ctx, db, "platform-user-1", "user"); err != nil {
				t.Fatalf("idempotent GrantPlatformSuperAdmin() error = %v", err)
			}
			platformDecision, err := service.Check(ctx, bootstrap.PlatformTenantID, "platform-user-1", "user", "identity.user", "list")
			if err != nil || !platformDecision.Allowed || platformDecision.DataScope != "all" {
				t.Fatalf("platform Check() = (%+v, %v)", platformDecision, err)
			}
			tenantCreated, err := eventbus.NewEnvelope(eventbus.Metadata{EventID: uuid.NewString(), EventType: "platform.tenant.v1.TenantCreated", AggregateID: "tenant-owner", AggregateType: "tenant", TenantID: "tenant-owner", SchemaVersion: 1, ActorID: "owner-user", OccurredAt: time.Now().Truncate(time.Microsecond)}, &tenantv1.TenantCreatedEvent{Tenant: &tenantv1.Tenant{Id: "tenant-owner"}, OwnerMembershipId: "owner-membership", OwnerUserId: "owner-user"})
			if err != nil {
				t.Fatal(err)
			}
			tenantBootstrap := authorizationdomain.NewRuntimeTenantBootstrapProjection(db, appdb.NewTransactor(db), repository, service)
			if err := tenantBootstrap.Apply(ctx, tenantCreated); err != nil {
				t.Fatal(err)
			}
			if err := tenantBootstrap.Apply(ctx, tenantCreated); err != nil {
				t.Fatalf("duplicate tenant bootstrap: %v", err)
			}
			ownerDecision, err := service.Check(ctx, "tenant-owner", "owner-membership", "membership", "any.resource", "any-action")
			if err != nil || !ownerDecision.Allowed || ownerDecision.DataScope != "all" {
				t.Fatalf("tenant owner Check() = (%+v, %v)", ownerDecision, err)
			}
			otherDecision, err := service.Check(ctx, "tenant-owner", "other-membership", "membership", "any.resource", "any-action")
			if err != nil || otherDecision.Allowed {
				t.Fatalf("unbound membership Check() = (%+v, %v)", otherDecision, err)
			}
			actorCtx := principal.WithContext(ctx, principal.Principal{ID: "admin-1", Type: principal.TypeServiceAccount})

			permission, err := service.CreatePermission(actorCtx, "tenant-1", "invoice.read", "Read invoices", "invoice", "read")
			if err != nil {
				t.Fatal(err)
			}
			role, err := service.CreateRole(actorCtx, "tenant-1", "auditor", "Auditor", "Read-only invoice access", "organization")
			if err != nil {
				t.Fatal(err)
			}
			rolePage, err := service.SearchRoles(actorCtx, "tenant-1", "audit", "active", 1, 20)
			if err != nil || rolePage.Total != 1 || len(rolePage.Items) != 1 || rolePage.Items[0].ID != role.ID {
				t.Fatalf("SearchRoles() = (%+v, %v)", rolePage, err)
			}
			roleBatch, err := service.BatchGetRoles(actorCtx, "tenant-1", []string{role.ID, uuid.NewString()})
			if err != nil || len(roleBatch) != 1 || roleBatch[0].ID != role.ID {
				t.Fatalf("BatchGetRoles() = (%+v, %v)", roleBatch, err)
			}
			rolePermission, err := service.GrantRolePermission(actorCtx, "tenant-1", role.ID, permission.ID)
			if err != nil {
				t.Fatal(err)
			}
			rolePermissionBatch, err := service.BatchGetRolePermissions(actorCtx, role.ID, []string{permission.ID, uuid.NewString()})
			if err != nil || len(rolePermissionBatch) != 1 || rolePermissionBatch[0].ID != rolePermission.ID {
				t.Fatalf("BatchGetRolePermissions() = (%+v, %v)", rolePermissionBatch, err)
			}
			binding, err := service.CreateBinding(actorCtx, "tenant-1", "group-1", "group", role.ID, "org-1")
			if err != nil {
				t.Fatal(err)
			}

			decision, err := service.Check(ctx, "tenant-1", "membership-1", "membership", "invoice", "read")
			if err != nil || decision.Allowed || decision.PolicyVersion != 4 {
				t.Fatalf("pre-projection Check() = (%+v, %v)", decision, err)
			}
			occurredAt := time.Now().Truncate(time.Microsecond)
			groupEnvelope, err := eventbus.NewEnvelope(eventbus.Metadata{EventID: uuid.NewString(), EventType: "platform.tenant.v1.GroupChanged", AggregateID: "group-1", AggregateType: "group", TenantID: "tenant-1", SchemaVersion: 1, ActorID: "tenant-service", OccurredAt: occurredAt}, &tenantv1.GroupChangedEvent{Group: &tenantv1.Group{Id: "group-1", TenantId: "tenant-1"}, MembershipId: "membership-1", ChangeType: "member_added"})
			if err != nil {
				t.Fatal(err)
			}
			projection := authorizationdomain.NewGroupProjection(db, appdb.NewTransactor(db), service)
			if err := projection.Apply(ctx, groupEnvelope); err != nil {
				t.Fatal(err)
			}
			if err := projection.Apply(ctx, groupEnvelope); err != nil {
				t.Fatalf("duplicate projection: %v", err)
			}
			decision, err = service.Check(ctx, "tenant-1", "membership-1", "membership", "invoice", "read")
			if err != nil || !decision.Allowed || decision.DataScope != "organization" || len(decision.OrganizationUnitIDs) != 1 || decision.PolicyVersion != 5 {
				t.Fatalf("Check() = (%+v, %v)", decision, err)
			}
			updated, err := service.UpdateRole(actorCtx, role.ID, "Senior Auditor", role.Description, "tenant", "active", role.Version)
			if err != nil || updated.Version != 2 {
				t.Fatalf("UpdateRole() = (%+v, %v)", updated, err)
			}
			if _, err := service.UpdateRole(actorCtx, role.ID, "Stale", role.Description, "tenant", "active", role.Version); !isStaleVersion(err) {
				t.Fatalf("stale UpdateRole() error = %v", err)
			}
			if _, err := service.RevokeRolePermission(actorCtx, rolePermission.ID, rolePermission.Version); err != nil {
				t.Fatal(err)
			}
			decision, err = service.Check(ctx, "tenant-1", "membership-1", "membership", "invoice", "read")
			if err != nil || decision.Allowed {
				t.Fatalf("revoked permission decision = (%+v, %v)", decision, err)
			}
			if _, err := service.RevokeBinding(actorCtx, binding.ID, binding.Version); err != nil {
				t.Fatal(err)
			}

			var outboxCount int
			if err := db.GetContext(ctx, &outboxCount, "SELECT COUNT(*) FROM authorization_outbox_events"); err != nil || outboxCount != 7 {
				t.Fatalf("outbox count = %d, err=%v", outboxCount, err)
			}
			publisher := &authorizationRecordingPublisher{}
			outboxStore, err := platformoutbox.NewSQLStore(db, "authorization_outbox_events")
			if err != nil {
				t.Fatal(err)
			}
			dispatcher, err := platformoutbox.New(outboxStore, publisher, platformoutbox.Config{BatchSize: 100, Lease: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			published, err := dispatcher.RunOnce(ctx)
			if err != nil || published != 7 || len(publisher.ids) != 7 {
				t.Fatalf("RunOnce() = (%d, %v), ids=%v", published, err, publisher.ids)
			}
			var pendingCount int
			if err := db.GetContext(ctx, &pendingCount, "SELECT COUNT(*) FROM authorization_outbox_events WHERE published_at IS NULL"); err != nil || pendingCount != 0 {
				t.Fatalf("pending outbox count = %d, err=%v", pendingCount, err)
			}
		})
	}
}

func isStaleVersion(err error) bool {
	return errors.Is(err, authorizationdomain.ErrStaleVersion)
}
