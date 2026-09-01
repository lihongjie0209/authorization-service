package authorization

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

var (
	ErrNotFound     = errors.New("authorization resource not found")
	ErrStaleVersion = errors.New("authorization resource version is stale")
)

type Repository interface {
	CreatePermission(context.Context, sqlx.ExtContext, Permission) error
	UpdatePermission(context.Context, sqlx.ExtContext, Permission) error
	ListPermissions(context.Context, string, int, int) ([]Permission, int64, error)
	ListPermissionCatalog(context.Context, string, string, int, int) ([]Permission, int64, error)
	CreateRole(context.Context, sqlx.ExtContext, Role) error
	GetRole(context.Context, string) (Role, error)
	UpdateRole(context.Context, sqlx.ExtContext, Role) error
	ListRoles(context.Context, string, int, int) ([]Role, int64, error)
	GetPermission(context.Context, string) (Permission, error)
	CreateRolePermission(context.Context, sqlx.ExtContext, RolePermission) error
	GetRolePermission(context.Context, string) (RolePermission, error)
	GetRolePermissionByPair(context.Context, string, string) (RolePermission, error)
	UpdateRolePermission(context.Context, sqlx.ExtContext, RolePermission) error
	ListRolePermissions(context.Context, string) ([]RolePermission, error)
	CreateBinding(context.Context, sqlx.ExtContext, Binding) error
	GetBinding(context.Context, string) (Binding, error)
	UpdateBinding(context.Context, sqlx.ExtContext, Binding) error
	ListBindings(context.Context, string, string, string, int, int) ([]Binding, int64, error)
	Resolve(context.Context, string, string, string, string, string) ([]resolvedGrant, uint64, error)
	ResolvePermissionCodes(context.Context, string, string, string, []string) ([]resolvedPermissionCodeGrant, uint64, error)
	BootstrapTenantOwner(context.Context, sqlx.ExtContext, string, string, time.Time, string) error
	BumpPolicyVersion(context.Context, sqlx.ExtContext, string, time.Time, string) (uint64, error)
	AddOutbox(context.Context, sqlx.ExtContext, OutboxEvent) error
}

type resolvedGrant struct {
	DataScope           string `db:"data_scope"`
	OrganizationUnitID  string `db:"organization_unit_id"`
	ConditionExpression string `db:"condition_expression"`
}

type resolvedPermissionCodeGrant struct {
	Code                string `db:"code"`
	ResourceType        string `db:"resource_type"`
	Action              string `db:"action"`
	ConditionExpression string `db:"condition_expression"`
}

type SQLRepository struct{ db *sqlx.DB }

func NewRepository(db *sqlx.DB) Repository { return &SQLRepository{db: db} }

const permissionColumns = "id, tenant_id, code, name, resource_type, action, status, version, created_at, updated_at, created_by, updated_by, condition_expression"
const roleColumns = "id, tenant_id, code, name, description, data_scope, status, version, created_at, updated_at, created_by, updated_by"
const rolePermissionColumns = "id, tenant_id, role_id, permission_id, status, version, created_at, updated_at, created_by, updated_by"
const bindingColumns = "id, tenant_id, subject_id, subject_type, role_id, COALESCE(organization_unit_id, '') AS organization_unit_id, status, version, created_at, updated_at, created_by, updated_by"

func (r *SQLRepository) CreatePermission(ctx context.Context, exec sqlx.ExtContext, value Permission) error {
	query := r.db.Rebind("INSERT INTO permissions (" + permissionColumns + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	_, err := exec.ExecContext(ctx, query, value.ID, value.TenantID, value.Code, value.Name, value.ResourceType, value.Action, value.Status, value.Version, value.CreatedAt, value.UpdatedAt, value.CreatedBy, value.UpdatedBy, value.ConditionExpression)
	return wrap(err, "insert permission")
}

func (r *SQLRepository) ListPermissions(ctx context.Context, tenantID string, limit, offset int) ([]Permission, int64, error) {
	items := make([]Permission, 0)
	var total int64
	if err := r.db.GetContext(ctx, &total, r.db.Rebind("SELECT COUNT(*) FROM permissions WHERE tenant_id = ?"), tenantID); err != nil {
		return nil, 0, fmt.Errorf("count permissions: %w", err)
	}
	if err := r.db.SelectContext(ctx, &items, r.db.Rebind("SELECT "+permissionColumns+" FROM permissions WHERE tenant_id = ? ORDER BY code, id LIMIT ? OFFSET ?"), tenantID, limit, offset); err != nil {
		return nil, 0, fmt.Errorf("list permissions: %w", err)
	}
	return items, total, nil
}

func (r *SQLRepository) ListPermissionCatalog(ctx context.Context, tenantID, search string, limit, offset int) ([]Permission, int64, error) {
	items := make([]Permission, 0)
	pattern := "%" + strings.ToLower(strings.TrimSpace(search)) + "%"
	where := "tenant_id = ? AND status = 'active' AND (? = '%%' OR LOWER(code) LIKE ? OR LOWER(name) LIKE ? OR LOWER(resource_type) LIKE ? OR LOWER(action) LIKE ?)"
	args := []any{tenantID, pattern, pattern, pattern, pattern, pattern}
	var total int64
	if err := r.db.GetContext(ctx, &total, r.db.Rebind("SELECT COUNT(*) FROM permissions WHERE "+where), args...); err != nil {
		return nil, 0, fmt.Errorf("count permission catalog: %w", err)
	}
	listArgs := append(args, limit, offset)
	if err := r.db.SelectContext(ctx, &items, r.db.Rebind("SELECT "+permissionColumns+" FROM permissions WHERE "+where+" ORDER BY code, id LIMIT ? OFFSET ?"), listArgs...); err != nil {
		return nil, 0, fmt.Errorf("list permission catalog: %w", err)
	}
	return items, total, nil
}

func (r *SQLRepository) GetPermission(ctx context.Context, id string) (Permission, error) {
	var value Permission
	err := r.db.GetContext(ctx, &value, r.db.Rebind("SELECT "+permissionColumns+" FROM permissions WHERE id = ?"), id)
	return value, mapNotFound(err, "select permission")
}

func (r *SQLRepository) UpdatePermission(ctx context.Context, exec sqlx.ExtContext, value Permission) error {
	result, err := exec.ExecContext(ctx, r.db.Rebind("UPDATE permissions SET name = ?, condition_expression = ?, status = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE id = ? AND version = ?"), value.Name, value.ConditionExpression, value.Status, value.UpdatedAt, value.UpdatedBy, value.ID, value.Version)
	return affected(result, err, "update permission")
}

func (r *SQLRepository) CreateRole(ctx context.Context, exec sqlx.ExtContext, value Role) error {
	query := r.db.Rebind("INSERT INTO roles (" + roleColumns + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	_, err := exec.ExecContext(ctx, query, value.ID, value.TenantID, value.Code, value.Name, value.Description, value.DataScope, value.Status, value.Version, value.CreatedAt, value.UpdatedAt, value.CreatedBy, value.UpdatedBy)
	return wrap(err, "insert role")
}
func (r *SQLRepository) GetRole(ctx context.Context, id string) (Role, error) {
	var value Role
	err := r.db.GetContext(ctx, &value, r.db.Rebind("SELECT "+roleColumns+" FROM roles WHERE id = ?"), id)
	return value, mapNotFound(err, "select role")
}
func (r *SQLRepository) UpdateRole(ctx context.Context, exec sqlx.ExtContext, value Role) error {
	result, err := exec.ExecContext(ctx, r.db.Rebind("UPDATE roles SET name = ?, description = ?, data_scope = ?, status = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE id = ? AND version = ?"), value.Name, value.Description, value.DataScope, value.Status, value.UpdatedAt, value.UpdatedBy, value.ID, value.Version)
	return affected(result, err, "update role")
}
func (r *SQLRepository) ListRoles(ctx context.Context, tenantID string, limit, offset int) ([]Role, int64, error) {
	items := make([]Role, 0)
	var total int64
	if err := r.db.GetContext(ctx, &total, r.db.Rebind("SELECT COUNT(*) FROM roles WHERE tenant_id = ?"), tenantID); err != nil {
		return nil, 0, fmt.Errorf("count roles: %w", err)
	}
	if err := r.db.SelectContext(ctx, &items, r.db.Rebind("SELECT "+roleColumns+" FROM roles WHERE tenant_id = ? ORDER BY code, id LIMIT ? OFFSET ?"), tenantID, limit, offset); err != nil {
		return nil, 0, fmt.Errorf("list roles: %w", err)
	}
	return items, total, nil
}

func (r *SQLRepository) CreateRolePermission(ctx context.Context, exec sqlx.ExtContext, value RolePermission) error {
	query := r.db.Rebind("INSERT INTO role_permissions (" + rolePermissionColumns + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	_, err := exec.ExecContext(ctx, query, value.ID, value.TenantID, value.RoleID, value.PermissionID, value.Status, value.Version, value.CreatedAt, value.UpdatedAt, value.CreatedBy, value.UpdatedBy)
	return wrap(err, "insert role permission")
}
func (r *SQLRepository) GetRolePermission(ctx context.Context, id string) (RolePermission, error) {
	var value RolePermission
	err := r.db.GetContext(ctx, &value, r.db.Rebind("SELECT "+rolePermissionColumns+" FROM role_permissions WHERE id = ?"), id)
	return value, mapNotFound(err, "select role permission")
}
func (r *SQLRepository) GetRolePermissionByPair(ctx context.Context, roleID, permissionID string) (RolePermission, error) {
	var value RolePermission
	err := r.db.GetContext(ctx, &value, r.db.Rebind("SELECT "+rolePermissionColumns+" FROM role_permissions WHERE role_id = ? AND permission_id = ?"), roleID, permissionID)
	return value, mapNotFound(err, "select role permission by pair")
}
func (r *SQLRepository) UpdateRolePermission(ctx context.Context, exec sqlx.ExtContext, value RolePermission) error {
	result, err := exec.ExecContext(ctx, r.db.Rebind("UPDATE role_permissions SET status = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE id = ? AND version = ?"), value.Status, value.UpdatedAt, value.UpdatedBy, value.ID, value.Version)
	return affected(result, err, "update role permission")
}
func (r *SQLRepository) ListRolePermissions(ctx context.Context, roleID string) ([]RolePermission, error) {
	items := make([]RolePermission, 0)
	err := r.db.SelectContext(ctx, &items, r.db.Rebind("SELECT "+rolePermissionColumns+" FROM role_permissions WHERE role_id = ? ORDER BY created_at, id"), roleID)
	return items, wrap(err, "list role permissions")
}

func (r *SQLRepository) CreateBinding(ctx context.Context, exec sqlx.ExtContext, value Binding) error {
	query := r.db.Rebind("INSERT INTO role_bindings (id, tenant_id, subject_id, subject_type, role_id, organization_unit_id, status, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	_, err := exec.ExecContext(ctx, query, value.ID, value.TenantID, value.SubjectID, value.SubjectType, value.RoleID, nullableID(value.OrganizationUnitID), value.Status, value.Version, value.CreatedAt, value.UpdatedAt, value.CreatedBy, value.UpdatedBy)
	return wrap(err, "insert role binding")
}
func (r *SQLRepository) GetBinding(ctx context.Context, id string) (Binding, error) {
	var value Binding
	err := r.db.GetContext(ctx, &value, r.db.Rebind("SELECT "+bindingColumns+" FROM role_bindings WHERE id = ?"), id)
	return value, mapNotFound(err, "select role binding")
}
func (r *SQLRepository) UpdateBinding(ctx context.Context, exec sqlx.ExtContext, value Binding) error {
	result, err := exec.ExecContext(ctx, r.db.Rebind("UPDATE role_bindings SET status = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE id = ? AND version = ?"), value.Status, value.UpdatedAt, value.UpdatedBy, value.ID, value.Version)
	return affected(result, err, "update role binding")
}
func (r *SQLRepository) ListBindings(ctx context.Context, tenantID, subjectID, subjectType string, limit, offset int) ([]Binding, int64, error) {
	where := "tenant_id = ?"
	args := []any{tenantID}
	if subjectID != "" {
		where += " AND subject_id = ? AND subject_type = ?"
		args = append(args, subjectID, subjectType)
	}
	var total int64
	if err := r.db.GetContext(ctx, &total, r.db.Rebind("SELECT COUNT(*) FROM role_bindings WHERE "+where), args...); err != nil {
		return nil, 0, fmt.Errorf("count role bindings: %w", err)
	}
	items := make([]Binding, 0)
	args = append(args, limit, offset)
	if err := r.db.SelectContext(ctx, &items, r.db.Rebind("SELECT "+bindingColumns+" FROM role_bindings WHERE "+where+" ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"), args...); err != nil {
		return nil, 0, fmt.Errorf("list role bindings: %w", err)
	}
	return items, total, nil
}

func (r *SQLRepository) Resolve(ctx context.Context, tenantID, subjectID, subjectType, resourceType, action string) ([]resolvedGrant, uint64, error) {
	grants := make([]resolvedGrant, 0)
	query := r.db.Rebind("SELECT r.data_scope, COALESCE(rb.organization_unit_id, '') AS organization_unit_id, p.condition_expression FROM role_bindings rb JOIN roles r ON r.id = rb.role_id JOIN role_permissions rp ON rp.role_id = r.id JOIN permissions p ON p.id = rp.permission_id WHERE rb.tenant_id = ? AND ((rb.subject_id = ? AND rb.subject_type = ?) OR (? = 'membership' AND rb.subject_type = 'group' AND EXISTS (SELECT 1 FROM authorization_subject_groups sg WHERE sg.tenant_id = rb.tenant_id AND sg.membership_id = ? AND sg.group_id = rb.subject_id AND sg.status = 'active'))) AND (p.resource_type = ? OR p.resource_type = '*') AND (p.action = ? OR p.action = '*') AND rb.status = 'active' AND r.status = 'active' AND rp.status = 'active' AND p.status = 'active'")
	if err := r.db.SelectContext(ctx, &grants, query, tenantID, subjectID, subjectType, subjectType, subjectID, resourceType, action); err != nil {
		return nil, 0, fmt.Errorf("resolve authorization grants: %w", err)
	}
	var version uint64
	err := r.db.GetContext(ctx, &version, r.db.Rebind("SELECT policy_version FROM authorization_policy_versions WHERE tenant_id = ?"), tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		version = 0
		err = nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("select policy version: %w", err)
	}
	return grants, version, nil
}

func (r *SQLRepository) ResolvePermissionCodes(ctx context.Context, tenantID, subjectID, subjectType string, codes []string) ([]resolvedPermissionCodeGrant, uint64, error) {
	query, args, err := sqlx.In("SELECT DISTINCT p.code, p.resource_type, p.action, p.condition_expression FROM role_bindings rb JOIN roles r ON r.id = rb.role_id JOIN role_permissions rp ON rp.role_id = r.id JOIN permissions p ON p.id = rp.permission_id WHERE rb.tenant_id = ? AND ((rb.subject_id = ? AND rb.subject_type = ?) OR (? = 'membership' AND rb.subject_type = 'group' AND EXISTS (SELECT 1 FROM authorization_subject_groups sg WHERE sg.tenant_id = rb.tenant_id AND sg.membership_id = ? AND sg.group_id = rb.subject_id AND sg.status = 'active'))) AND (p.code IN (?) OR (p.resource_type = '*' AND p.action = '*')) AND rb.status = 'active' AND r.status = 'active' AND rp.status = 'active' AND p.status = 'active'", tenantID, subjectID, subjectType, subjectType, subjectID, codes)
	if err != nil {
		return nil, 0, fmt.Errorf("build permission code query: %w", err)
	}
	grants := make([]resolvedPermissionCodeGrant, 0)
	if err := r.db.SelectContext(ctx, &grants, r.db.Rebind(query), args...); err != nil {
		return nil, 0, fmt.Errorf("resolve permission code grants: %w", err)
	}
	var version uint64
	err = r.db.GetContext(ctx, &version, r.db.Rebind("SELECT policy_version FROM authorization_policy_versions WHERE tenant_id = ?"), tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return grants, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("select policy version: %w", err)
	}
	return grants, version, nil
}

func (r *SQLRepository) BootstrapTenantOwner(ctx context.Context, exec sqlx.ExtContext, tenantID, membershipID string, now time.Time, actor string) error {
	permissionID := tenantBootstrapID("permission", tenantID)
	roleID := tenantBootstrapID("role", tenantID)
	rolePermissionID := tenantBootstrapID("role-permission", tenantID)
	bindingID := tenantBootstrapID("binding:"+membershipID, tenantID)

	permissionQuery := "INSERT INTO permissions (id, tenant_id, code, name, resource_type, action, status, version, created_at, updated_at, created_by, updated_by, condition_expression) VALUES (?, ?, 'tenant.owner-admin', 'Tenant owner administrator', '*', '*', 'active', 1, ?, ?, ?, ?, '') ON CONFLICT DO NOTHING"
	roleQuery := "INSERT INTO roles (id, tenant_id, code, name, description, data_scope, status, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, 'tenant-owner-admin', 'Tenant owner administrator', 'Full access for the tenant owner', 'all', 'active', 1, ?, ?, ?, ?) ON CONFLICT DO NOTHING"
	rolePermissionQuery := "INSERT INTO role_permissions (id, tenant_id, role_id, permission_id, status, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, ?, 'active', 1, ?, ?, ?, ?) ON CONFLICT DO NOTHING"
	bindingQuery := "INSERT INTO role_bindings (id, tenant_id, subject_id, subject_type, role_id, organization_unit_id, status, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, 'membership', ?, NULL, 'active', 1, ?, ?, ?, ?) ON CONFLICT DO NOTHING"
	if r.db.DriverName() == "mysql" {
		permissionQuery = strings.Replace(permissionQuery, "INSERT INTO", "INSERT IGNORE INTO", 1)
		permissionQuery = strings.TrimSuffix(permissionQuery, " ON CONFLICT DO NOTHING")
		roleQuery = strings.Replace(roleQuery, "INSERT INTO", "INSERT IGNORE INTO", 1)
		roleQuery = strings.TrimSuffix(roleQuery, " ON CONFLICT DO NOTHING")
		rolePermissionQuery = strings.Replace(rolePermissionQuery, "INSERT INTO", "INSERT IGNORE INTO", 1)
		rolePermissionQuery = strings.TrimSuffix(rolePermissionQuery, " ON CONFLICT DO NOTHING")
		bindingQuery = strings.Replace(bindingQuery, "INSERT INTO", "INSERT IGNORE INTO", 1)
		bindingQuery = strings.TrimSuffix(bindingQuery, " ON CONFLICT DO NOTHING")
	}
	for _, statement := range []struct {
		name  string
		query string
		args  []any
	}{
		{name: "permission", query: permissionQuery, args: []any{permissionID, tenantID, now, now, actor, actor}},
		{name: "role", query: roleQuery, args: []any{roleID, tenantID, now, now, actor, actor}},
		{name: "role permission", query: rolePermissionQuery, args: []any{rolePermissionID, tenantID, roleID, permissionID, now, now, actor, actor}},
		{name: "owner binding", query: bindingQuery, args: []any{bindingID, tenantID, membershipID, roleID, now, now, actor, actor}},
	} {
		if _, err := exec.ExecContext(ctx, r.db.Rebind(statement.query), statement.args...); err != nil {
			return fmt.Errorf("bootstrap tenant owner %s: %w", statement.name, err)
		}
	}
	return nil
}

func (r *SQLRepository) BumpPolicyVersion(ctx context.Context, exec sqlx.ExtContext, tenantID string, now time.Time, actor string) (uint64, error) {
	if r.db.DriverName() == "mysql" {
		_, err := exec.ExecContext(ctx, r.db.Rebind("INSERT INTO authorization_policy_versions (tenant_id, policy_version, version, created_at, updated_at, created_by, updated_by) VALUES (?, 1, 1, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE policy_version = policy_version + 1, version = version + 1, updated_at = VALUES(updated_at), updated_by = VALUES(updated_by)"), tenantID, now, now, actor, actor)
		if err != nil {
			return 0, fmt.Errorf("bump policy version: %w", err)
		}
	} else {
		_, err := exec.ExecContext(ctx, r.db.Rebind("INSERT INTO authorization_policy_versions (tenant_id, policy_version, version, created_at, updated_at, created_by, updated_by) VALUES (?, 1, 1, ?, ?, ?, ?) ON CONFLICT (tenant_id) DO UPDATE SET policy_version = authorization_policy_versions.policy_version + 1, version = authorization_policy_versions.version + 1, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by"), tenantID, now, now, actor, actor)
		if err != nil {
			return 0, fmt.Errorf("bump policy version: %w", err)
		}
	}
	var version uint64
	if err := sqlx.GetContext(ctx, exec, &version, r.db.Rebind("SELECT policy_version FROM authorization_policy_versions WHERE tenant_id = ?"), tenantID); err != nil {
		return 0, fmt.Errorf("select bumped policy version: %w", err)
	}
	return version, nil
}
func (r *SQLRepository) AddOutbox(ctx context.Context, exec sqlx.ExtContext, event OutboxEvent) error {
	_, err := exec.ExecContext(ctx, r.db.Rebind("INSERT INTO authorization_outbox_events (id, subject, envelope, attempts, available_at, published_at, last_error, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, 0, ?, NULL, '', ?, ?, ?, ?, ?)"), event.ID, event.Subject, event.Envelope, event.AvailableAt, event.Version, event.CreatedAt, event.UpdatedAt, event.CreatedBy, event.UpdatedBy)
	return wrap(err, "insert authorization outbox")
}

func wrap(err error, operation string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
func mapNotFound(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return wrap(err, operation)
}
func affected(result sql.Result, err error, operation string) error {
	if err != nil {
		return wrap(err, operation)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return wrap(err, operation+" affected rows")
	}
	if count == 0 {
		return ErrStaleVersion
	}
	return nil
}
func nullableID(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func tenantBootstrapID(kind, tenantID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("authorization:tenant-bootstrap:"+kind+":"+tenantID)).String()
}
