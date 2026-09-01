package authorization

import (
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
)

func TestSQLRepositoryResolveIncludesWildcardPermissions(t *testing.T) {
	t.Parallel()
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	db := sqlx.NewDb(database, "postgres")
	repository := &SQLRepository{db: db}

	grantQuery := db.Rebind("SELECT r.data_scope, COALESCE(rb.organization_unit_id, '') AS organization_unit_id, p.condition_expression FROM role_bindings rb JOIN roles r ON r.id = rb.role_id JOIN role_permissions rp ON rp.role_id = r.id JOIN permissions p ON p.id = rp.permission_id WHERE rb.tenant_id = ? AND ((rb.subject_id = ? AND rb.subject_type = ?) OR (? = 'membership' AND rb.subject_type = 'group' AND EXISTS (SELECT 1 FROM authorization_subject_groups sg WHERE sg.tenant_id = rb.tenant_id AND sg.membership_id = ? AND sg.group_id = rb.subject_id AND sg.status = 'active'))) AND (p.resource_type = ? OR p.resource_type = '*') AND (p.action = ? OR p.action = '*') AND rb.status = 'active' AND r.status = 'active' AND rp.status = 'active' AND p.status = 'active'")
	mock.ExpectQuery(regexp.QuoteMeta(grantQuery)).
		WithArgs("__platform__", "user-1", "user", "user", "user-1", "identity.user", "list").
		WillReturnRows(sqlmock.NewRows([]string{"data_scope", "organization_unit_id", "condition_expression"}).AddRow("all", "", ""))
	mock.ExpectQuery(regexp.QuoteMeta(db.Rebind("SELECT policy_version FROM authorization_policy_versions WHERE tenant_id = ?"))).
		WithArgs("__platform__").WillReturnRows(sqlmock.NewRows([]string{"policy_version"}).AddRow(1))

	grants, version, err := repository.Resolve(t.Context(), "__platform__", "user-1", "user", "identity.user", "list")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].DataScope != "all" || version != 1 {
		t.Fatalf("Resolve() = %+v, %d", grants, version)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLRepositoryBootstrapTenantOwnerCreatesReservedGrantGraph(t *testing.T) {
	t.Parallel()
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	db := sqlx.NewDb(database, "postgres")
	repository := &SQLRepository{db: db}
	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
	tenantID, membershipID, actor := "tenant-1", "membership-1", "user-1"
	permissionID := tenantBootstrapID("permission", tenantID)
	roleID := tenantBootstrapID("role", tenantID)

	mock.ExpectExec("INSERT INTO permissions").
		WithArgs(permissionID, tenantID, now, now, actor, actor).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO roles").
		WithArgs(roleID, tenantID, now, now, actor, actor).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO role_permissions").
		WithArgs(tenantBootstrapID("role-permission", tenantID), tenantID, roleID, permissionID, now, now, actor, actor).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO role_bindings").
		WithArgs(tenantBootstrapID("binding:"+membershipID, tenantID), tenantID, membershipID, roleID, now, now, actor, actor).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repository.BootstrapTenantOwner(t.Context(), db, tenantID, membershipID, now, actor); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLRepositoryResolvePermissionCodesUsesSingleGrantQuery(t *testing.T) {
	t.Parallel()
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	db := sqlx.NewDb(database, "postgres")
	repository := &SQLRepository{db: db}

	mock.ExpectQuery("SELECT DISTINCT p\\.code").
		WithArgs("tenant-1", "membership-1", "membership", "membership", "membership-1", "application.read", "application.update").
		WillReturnRows(sqlmock.NewRows([]string{"code", "resource_type", "action", "condition_expression"}).AddRow("application.read", "application", "read", ""))
	mock.ExpectQuery(regexp.QuoteMeta(db.Rebind("SELECT policy_version FROM authorization_policy_versions WHERE tenant_id = ?"))).
		WithArgs("tenant-1").WillReturnRows(sqlmock.NewRows([]string{"policy_version"}).AddRow(3))

	grants, version, err := repository.ResolvePermissionCodes(t.Context(), "tenant-1", "membership-1", "membership", []string{"application.read", "application.update"})
	if err != nil || len(grants) != 1 || grants[0].Code != "application.read" || version != 3 {
		t.Fatalf("grants=%+v version=%d err=%v", grants, version, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
