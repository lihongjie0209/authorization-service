package bootstrap

import (
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
)

func TestGrantPlatformSuperAdminIsTransactionalAndIdempotent(t *testing.T) {
	t.Parallel()
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	db := sqlx.NewDb(database, "postgres")
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(db.Rebind("SELECT id FROM roles WHERE tenant_id = ? AND code = ? AND status = 'active'"))).
		WithArgs(PlatformTenantID, SuperAdminRoleCode).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("platform-super-admin-role"))
	mock.ExpectExec("INSERT INTO role_bindings .* ON CONFLICT .* DO UPDATE").
		WithArgs(sqlmock.AnyArg(), PlatformTenantID, "user-1", "user", "platform-super-admin-role", sqlmock.AnyArg(), sqlmock.AnyArg(), "platform-bootstrap:user-1", "platform-bootstrap:user-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO authorization_policy_versions .* ON CONFLICT .* DO UPDATE").
		WithArgs(PlatformTenantID, sqlmock.AnyArg(), sqlmock.AnyArg(), "platform-bootstrap:user-1", "platform-bootstrap:user-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	result, err := GrantPlatformSuperAdmin(t.Context(), db, " user-1 ", "USER")
	if err != nil {
		t.Fatal(err)
	}
	if result.BindingID == "" || result.SubjectID != "user-1" || result.SubjectType != "user" || result.RoleID != "platform-super-admin-role" {
		t.Fatalf("result = %+v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestGrantPlatformSuperAdminRejectsInvalidSubjectBeforeDatabaseUse(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ id, subjectType string }{{"", "user"}, {"user-1", "membership"}} {
		if _, err := GrantPlatformSuperAdmin(t.Context(), &sqlx.DB{}, test.id, test.subjectType); err == nil {
			t.Fatalf("GrantPlatformSuperAdmin(%q, %q) error = nil", test.id, test.subjectType)
		}
	}
}
