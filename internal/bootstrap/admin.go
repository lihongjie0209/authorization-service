package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	appdb "github.com/lihongjie0209/authorization-service/internal/database"
	"github.com/lihongjie0209/microservice-platform-go/principal"
)

const (
	PlatformTenantID   = "__platform__"
	SuperAdminRoleCode = "platform-super-admin"
)

type Result struct {
	BindingID   string `json:"binding_id"`
	SubjectID   string `json:"subject_id"`
	SubjectType string `json:"subject_type"`
	RoleID      string `json:"role_id"`
}

func GrantPlatformSuperAdmin(ctx context.Context, db *sqlx.DB, subjectID, subjectType string) (Result, error) {
	if db == nil {
		return Result{}, errors.New("database is required")
	}
	subjectID = strings.TrimSpace(subjectID)
	subjectType = strings.ToLower(strings.TrimSpace(subjectType))
	if subjectID == "" || (subjectType != "user" && subjectType != "service_account") {
		return Result{}, errors.New("a non-empty user or service-account subject is required")
	}
	now := time.Now()
	actor := "platform-bootstrap:" + subjectID
	actorCtx := principal.SystemContext(ctx, actor)
	var roleID, bindingID string
	if err := appdb.NewTransactor(db).Within(actorCtx, nil, func(tx *sqlx.Tx) error {
		query := db.Rebind("SELECT id FROM roles WHERE tenant_id = ? AND code = ? AND status = 'active'")
		if err := tx.GetContext(actorCtx, &roleID, query, PlatformTenantID, SuperAdminRoleCode); err != nil {
			return fmt.Errorf("find platform super-admin role (run migrations first): %w", err)
		}
		bindingID = uuid.NewSHA1(uuid.NameSpaceOID, []byte(PlatformTenantID+"\x00"+subjectType+"\x00"+subjectID+"\x00"+roleID)).String()
		if err := upsertBinding(actorCtx, db, tx, bindingID, roleID, subjectID, subjectType, now, actor); err != nil {
			return err
		}
		return bumpPolicyVersion(actorCtx, db, tx, now, actor)
	}); err != nil {
		return Result{}, err
	}
	return Result{BindingID: bindingID, SubjectID: subjectID, SubjectType: subjectType, RoleID: roleID}, nil
}

func upsertBinding(ctx context.Context, db *sqlx.DB, tx *sqlx.Tx, bindingID, roleID, subjectID, subjectType string, now time.Time, actor string) error {
	var query string
	if db.DriverName() == "mysql" {
		query = "INSERT INTO role_bindings (id, tenant_id, subject_id, subject_type, role_id, organization_unit_id, status, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, ?, ?, NULL, 'active', 1, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE status = 'active', version = version + 1, updated_at = VALUES(updated_at), updated_by = VALUES(updated_by)"
	} else {
		query = "INSERT INTO role_bindings (id, tenant_id, subject_id, subject_type, role_id, organization_unit_id, status, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, ?, ?, NULL, 'active', 1, ?, ?, ?, ?) ON CONFLICT (tenant_id, subject_type, subject_id, role_id) DO UPDATE SET status = 'active', version = role_bindings.version + 1, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by"
	}
	if _, err := tx.ExecContext(ctx, db.Rebind(query), bindingID, PlatformTenantID, subjectID, subjectType, roleID, now, now, actor, actor); err != nil {
		return fmt.Errorf("upsert platform super-admin binding: %w", err)
	}
	return nil
}

func bumpPolicyVersion(ctx context.Context, db *sqlx.DB, tx *sqlx.Tx, now time.Time, actor string) error {
	var query string
	if db.DriverName() == "mysql" {
		query = "INSERT INTO authorization_policy_versions (tenant_id, policy_version, version, created_at, updated_at, created_by, updated_by) VALUES (?, 1, 1, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE policy_version = policy_version + 1, version = version + 1, updated_at = VALUES(updated_at), updated_by = VALUES(updated_by)"
	} else {
		query = "INSERT INTO authorization_policy_versions (tenant_id, policy_version, version, created_at, updated_at, created_by, updated_by) VALUES (?, 1, 1, ?, ?, ?, ?) ON CONFLICT (tenant_id) DO UPDATE SET policy_version = authorization_policy_versions.policy_version + 1, version = authorization_policy_versions.version + 1, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by"
	}
	if _, err := tx.ExecContext(ctx, db.Rebind(query), PlatformTenantID, now, now, actor, actor); err != nil {
		return fmt.Errorf("bump platform policy version: %w", err)
	}
	return nil
}
