package authorization

import (
	"context"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/authorization-service/internal/apperror"
	"github.com/lihongjie0209/authorization-service/internal/database"
)

type fakeRepository struct {
	grants        []resolvedGrant
	policyVersion uint64
	resolveCalls  int
}

func (*fakeRepository) CreatePermission(context.Context, sqlx.ExtContext, Permission) error {
	return nil
}
func (*fakeRepository) UpdatePermission(context.Context, sqlx.ExtContext, Permission) error {
	return nil
}
func (*fakeRepository) ListPermissions(context.Context, string, int, int) ([]Permission, int64, error) {
	return nil, 0, nil
}
func (*fakeRepository) CreateRole(context.Context, sqlx.ExtContext, Role) error { return nil }
func (*fakeRepository) GetRole(context.Context, string) (Role, error)           { return Role{}, ErrNotFound }
func (*fakeRepository) UpdateRole(context.Context, sqlx.ExtContext, Role) error { return nil }
func (*fakeRepository) ListRoles(context.Context, string, int, int) ([]Role, int64, error) {
	return nil, 0, nil
}
func (*fakeRepository) GetPermission(context.Context, string) (Permission, error) {
	return Permission{}, ErrNotFound
}
func (*fakeRepository) CreateRolePermission(context.Context, sqlx.ExtContext, RolePermission) error {
	return nil
}
func (*fakeRepository) GetRolePermission(context.Context, string) (RolePermission, error) {
	return RolePermission{}, ErrNotFound
}
func (*fakeRepository) GetRolePermissionByPair(context.Context, string, string) (RolePermission, error) {
	return RolePermission{}, ErrNotFound
}
func (*fakeRepository) UpdateRolePermission(context.Context, sqlx.ExtContext, RolePermission) error {
	return nil
}
func (*fakeRepository) ListRolePermissions(context.Context, string) ([]RolePermission, error) {
	return nil, nil
}
func (*fakeRepository) CreateBinding(context.Context, sqlx.ExtContext, Binding) error { return nil }
func (*fakeRepository) GetBinding(context.Context, string) (Binding, error) {
	return Binding{}, ErrNotFound
}
func (*fakeRepository) UpdateBinding(context.Context, sqlx.ExtContext, Binding) error { return nil }
func (*fakeRepository) ListBindings(context.Context, string, string, string, int, int) ([]Binding, int64, error) {
	return nil, 0, nil
}

func (f *fakeRepository) Resolve(context.Context, string, string, string, string, string) ([]resolvedGrant, uint64, error) {
	f.resolveCalls++
	return f.grants, f.policyVersion, nil
}
func (*fakeRepository) BumpPolicyVersion(context.Context, sqlx.ExtContext, string, time.Time, string) (uint64, error) {
	return 1, nil
}
func (*fakeRepository) AddOutbox(context.Context, sqlx.ExtContext, OutboxEvent) error { return nil }

func TestService_CheckDeniesWithoutGrant(t *testing.T) {
	t.Parallel()
	service := NewService(&fakeRepository{policyVersion: 7}, &database.Transactor{})
	decision, err := service.Check(t.Context(), "tenant-1", "membership-1", "membership", "invoice", "read")
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || decision.DataScope != "none" || decision.PolicyVersion != 7 || decision.DecisionID == "" {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestService_CheckChoosesBroadestScopeAndDeduplicatesOrganizations(t *testing.T) {
	t.Parallel()
	repository := &fakeRepository{policyVersion: 8, grants: []resolvedGrant{{DataScope: "organization", OrganizationUnitID: "org-1"}, {DataScope: "self"}, {DataScope: "organization", OrganizationUnitID: "org-1"}, {DataScope: "tenant"}}}
	service := NewService(repository, &database.Transactor{})
	decision, err := service.Check(t.Context(), "tenant-1", "membership-1", "membership", "invoice", "read")
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || decision.DataScope != "tenant" || len(decision.OrganizationUnitIDs) != 1 || decision.OrganizationUnitIDs[0] != "org-1" {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestService_CheckEvaluatesABACCondition(t *testing.T) {
	repository := &fakeRepository{policyVersion: 9, grants: []resolvedGrant{{DataScope: "tenant", ConditionExpression: `attributes["department"] == "finance" && resource_id.startsWith("invoice-")`}}}
	service := NewService(repository, &database.Transactor{})
	allowed, err := service.CheckWithAttributes(t.Context(), "tenant-1", "membership-1", "membership", "invoice", "invoice-1", "read", map[string]string{"department": "finance"})
	if err != nil || !allowed.Allowed {
		t.Fatalf("allowed=%+v err=%v", allowed, err)
	}
	denied, err := service.CheckWithAttributes(t.Context(), "tenant-1", "membership-1", "membership", "invoice", "invoice-1", "read", map[string]string{"department": "sales"})
	if err != nil || denied.Allowed || denied.Reason != "ABAC condition did not match" {
		t.Fatalf("denied=%+v err=%v", denied, err)
	}
}

func TestService_CheckCachesAndInvalidatesSubject(t *testing.T) {
	repository := &fakeRepository{policyVersion: 9, grants: []resolvedGrant{{DataScope: "tenant"}}}
	service := NewService(repository, &database.Transactor{})
	for range 2 {
		if _, err := service.Check(t.Context(), "tenant-1", "membership-1", "membership", "invoice", "read"); err != nil {
			t.Fatal(err)
		}
	}
	if repository.resolveCalls != 1 {
		t.Fatalf("Resolve calls = %d, want 1", repository.resolveCalls)
	}
	if err := service.InvalidateSubject("tenant-1", "membership-1", "membership"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Check(t.Context(), "tenant-1", "membership-1", "membership", "invoice", "read"); err != nil {
		t.Fatal(err)
	}
	if repository.resolveCalls != 2 {
		t.Fatalf("Resolve calls after invalidation = %d, want 2", repository.resolveCalls)
	}
}

func TestService_CreatePermissionRequiresActor(t *testing.T) {
	t.Parallel()
	service := NewService(&fakeRepository{}, &database.Transactor{})
	_, err := service.CreatePermission(t.Context(), "tenant-1", "invoice.read", "Read invoices", "invoice", "read")
	appErr, ok := err.(*apperror.Error)
	if !ok || appErr.Code != apperror.CodeUnauthorized {
		t.Fatalf("CreatePermission() error = %v, want unauthorized", err)
	}
}

func TestService_UpdatePermissionRejectsInvalidCondition(t *testing.T) {
	t.Parallel()
	service := NewService(&fakeRepository{}, &database.Transactor{})
	_, err := service.UpdatePermission(t.Context(), "permission-1", "Read invoices", "attributes[", "active", 1)
	appErr, ok := err.(*apperror.Error)
	if !ok || appErr.Code != apperror.CodeInvalidArgument {
		t.Fatalf("UpdatePermission() error = %v, want invalid argument", err)
	}
}

func TestNormalizePageRejectsOversize(t *testing.T) {
	t.Parallel()
	_, _, err := normalizePage(1, 101)
	appErr, ok := err.(*apperror.Error)
	if !ok || appErr.Code != apperror.CodeInvalidArgument {
		t.Fatalf("normalizePage() error = %v", err)
	}
}
