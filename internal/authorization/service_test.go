package authorization

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/authorization-service/internal/apperror"
	"github.com/lihongjie0209/authorization-service/internal/database"
	platformauthz "github.com/lihongjie0209/microservice-platform-go/authz"
	"github.com/lihongjie0209/microservice-platform-go/principal"
	authorizationv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/authorization/v1"
)

type fakeRepository struct {
	grants              []resolvedGrant
	policyVersion       uint64
	resolveCalls        int
	resolvedTenant      string
	resolvedSubject     string
	resolvedSubjectType string
	codeGrants          []resolvedPermissionCodeGrant
	catalogItems        []Permission
	catalogTenant       string
	catalogSearch       string
	role                *Role
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
func (f *fakeRepository) ListPermissionCatalog(_ context.Context, tenantID, search string, _, _ int) ([]Permission, int64, error) {
	f.catalogTenant, f.catalogSearch = tenantID, search
	return f.catalogItems, int64(len(f.catalogItems)), nil
}
func (*fakeRepository) CreateRole(context.Context, sqlx.ExtContext, Role) error { return nil }
func (f *fakeRepository) GetRole(context.Context, string) (Role, error) {
	if f.role == nil {
		return Role{}, ErrNotFound
	}
	return *f.role, nil
}
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

func (f *fakeRepository) Resolve(_ context.Context, tenantID, subjectID, subjectType, _, _ string) ([]resolvedGrant, uint64, error) {
	f.resolveCalls++
	f.resolvedTenant, f.resolvedSubject, f.resolvedSubjectType = tenantID, subjectID, subjectType
	return f.grants, f.policyVersion, nil
}
func (f *fakeRepository) ResolvePermissionCodes(_ context.Context, tenantID, subjectID, subjectType string, _ []string) ([]resolvedPermissionCodeGrant, uint64, error) {
	f.resolvedTenant, f.resolvedSubject, f.resolvedSubjectType = tenantID, subjectID, subjectType
	return f.codeGrants, f.policyVersion, nil
}
func (*fakeRepository) BootstrapTenantOwner(context.Context, sqlx.ExtContext, string, string, time.Time, string) error {
	return nil
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

func TestEnforceInteractiveTenantBindsUsersAndAllowsTrustedServices(t *testing.T) {
	t.Parallel()
	tenantUser := principal.WithContext(t.Context(), principal.Principal{ID: "user-1", Type: principal.TypeUser, TenantID: "tenant-1", MembershipID: "membership-1"})
	if err := enforceInteractiveTenant(tenantUser, "tenant-1"); err != nil {
		t.Fatalf("matching tenant: %v", err)
	}
	if err := enforceInteractiveTenant(tenantUser, "tenant-2"); err == nil {
		t.Fatal("cross-tenant user access must fail")
	}
	platformUser := principal.WithContext(t.Context(), principal.Principal{ID: "user-1", Type: principal.TypeUser})
	if err := enforceInteractiveTenant(platformUser, platformauthz.PlatformTenantID); err != nil {
		t.Fatalf("platform namespace: %v", err)
	}
	if err := enforceInteractiveTenant(platformUser, "tenant-1"); err == nil {
		t.Fatal("unscoped platform user must not select a tenant namespace")
	}
	serviceCaller := principal.WithContext(t.Context(), principal.Principal{ID: "provisioner", Type: principal.TypeServiceAccount})
	if err := enforceInteractiveTenant(serviceCaller, "tenant-2"); err != nil {
		t.Fatalf("trusted service scope is governed by its service authorization: %v", err)
	}
}

func TestService_AuthorizeUserManagementScopeDerivesPlatformTarget(t *testing.T) {
	t.Parallel()
	repository := &fakeRepository{grants: []resolvedGrant{{DataScope: "all"}}, policyVersion: 3}
	service := NewService(repository, &database.Transactor{})
	ctx := principal.WithContext(t.Context(), principal.Principal{ID: "user-1", Type: principal.TypeUser, TenantID: "tenant-1", MembershipID: "membership-1"})
	authorizedCtx, targetTenantID, err := service.AuthorizeUserManagementScope(ctx, "tenant-1", "platform", "authorization.permission", "create")
	if err != nil {
		t.Fatal(err)
	}
	if targetTenantID != platformauthz.PlatformTenantID || repository.resolvedTenant != platformauthz.PlatformTenantID || repository.resolvedSubject != "user-1" || repository.resolvedSubjectType != "user" {
		t.Fatalf("target=%q resolved=(%q,%q,%q)", targetTenantID, repository.resolvedTenant, repository.resolvedSubject, repository.resolvedSubjectType)
	}
	if err := enforceInteractiveTenant(authorizedCtx, platformauthz.PlatformTenantID); err != nil {
		t.Fatalf("authorized target marker: %v", err)
	}
	if err := enforceInteractiveTenant(authorizedCtx, "tenant-1"); err == nil {
		t.Fatal("authorized target marker must not permit another scope")
	}
	if _, _, err := service.AuthorizeUserManagementScope(ctx, "tenant-2", "platform", "authorization.permission", "create"); err == nil {
		t.Fatal("selected tenant mismatch must fail")
	}
}

func TestService_AuthorizeUserManagementScopeDeniesWithoutGrant(t *testing.T) {
	t.Parallel()
	service := NewService(&fakeRepository{}, &database.Transactor{})
	ctx := principal.WithContext(t.Context(), principal.Principal{ID: "user-1", Type: principal.TypeUser, TenantID: "tenant-1", MembershipID: "membership-1"})
	if _, _, err := service.AuthorizeUserManagementScope(ctx, "tenant-1", "tenant", "authorization.permission", "list"); err == nil {
		t.Fatal("management scope without a grant must fail")
	}
}

func TestService_UpdateRoleRejectsCrossTenantResourceID(t *testing.T) {
	t.Parallel()
	repository := &fakeRepository{role: &Role{ID: "role-2", TenantID: "tenant-2", Name: "Other role", DataScope: "tenant", Status: "active", AuditFields: AuditFields{Version: 1}}}
	service := NewService(repository, &database.Transactor{})
	ctx := principal.WithContext(t.Context(), principal.Principal{ID: "user-1", Type: principal.TypeUser, TenantID: "tenant-1", MembershipID: "membership-1"})
	if _, err := service.UpdateRole(ctx, "role-2", "Changed", "", "tenant", "active", 1); err == nil {
		t.Fatal("cross-tenant role ID must be rejected before update")
	}
}

func TestService_ListPermissionCatalogUsesBoundedSearch(t *testing.T) {
	t.Parallel()
	repository := &fakeRepository{catalogItems: []Permission{{Code: "application.read"}}}
	service := NewService(repository, &database.Transactor{})
	page, err := service.ListPermissionCatalog(t.Context(), " tenant-1 ", " application ", 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	if repository.catalogTenant != "tenant-1" || repository.catalogSearch != "application" || len(page.Items) != 1 {
		t.Fatalf("catalog tenant=%q search=%q page=%+v", repository.catalogTenant, repository.catalogSearch, page)
	}
	if _, err := service.ListPermissionCatalog(t.Context(), "tenant-1", strings.Repeat("x", 101), 1, 20); err == nil {
		t.Fatal("oversized search must fail")
	}
}

func TestService_CheckPermissionCodesNormalizesAndPreservesRequestOrder(t *testing.T) {
	t.Parallel()
	repository := &fakeRepository{policyVersion: 12, codeGrants: []resolvedPermissionCodeGrant{{Code: "application.read"}, {Code: "ignored", ConditionExpression: "false"}}}
	service := NewService(repository, &database.Transactor{})
	decision, err := service.CheckPermissionCodes(t.Context(), "tenant-1", "membership-1", "membership", []string{" APPLICATION.READ ", "denied", "application.read"})
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.AllowedCodes) != 1 || decision.AllowedCodes[0] != "application.read" || decision.PolicyVersion != 12 {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestService_CheckPermissionCodesHonorsWildcardRole(t *testing.T) {
	t.Parallel()
	repository := &fakeRepository{codeGrants: []resolvedPermissionCodeGrant{{Code: "platform.super-admin", ResourceType: "*", Action: "*"}}}
	service := NewService(repository, &database.Transactor{})
	decision, err := service.CheckPermissionCodes(t.Context(), "tenant-1", "membership-1", "membership", []string{"a", "b"})
	if err != nil || len(decision.AllowedCodes) != 2 {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
}

func TestService_CheckPermissionCodesHidesConditionalGrantWithoutResourceFacts(t *testing.T) {
	t.Parallel()
	repository := &fakeRepository{codeGrants: []resolvedPermissionCodeGrant{{
		Code:                "invoice.approve",
		ConditionExpression: `attributes["department"] == "finance" && resource_id.startsWith("invoice-")`,
	}}}
	service := NewService(repository, &database.Transactor{})
	decision, err := service.CheckPermissionCodes(t.Context(), "tenant-1", "membership-1", "membership", []string{"invoice.approve"})
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.AllowedCodes) != 0 {
		t.Fatalf("decision = %+v, conditional grant must fail closed", decision)
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

func TestValidSubjectTypeIncludesPlatformUser(t *testing.T) {
	t.Parallel()
	if !validSubjectType("user") || subjectTypeProto("user") != authorizationv1.SubjectType_SUBJECT_TYPE_USER {
		t.Fatal("platform user subject must be accepted and mapped to protobuf")
	}
}
