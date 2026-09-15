package authorization

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/authorization-service/internal/apperror"
	"github.com/lihongjie0209/authorization-service/internal/database"
	platformauthz "github.com/lihongjie0209/microservice-platform-go/authz"
	"github.com/lihongjie0209/microservice-platform-go/operationlog"
	"github.com/lihongjie0209/microservice-platform-go/principal"
	"github.com/lihongjie0209/microservice-platform-go/securitylog"
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
	roleSearchTenant    string
	roleSearchKeyword   string
	roleSearchStatus    string
	roleSearchLimit     int
	roleSearchOffset    int
	roleBatchTenant     string
	roleBatchIDs        []string
	binding             *Binding
	permissionFilter    PermissionFilter
	roleFilter          RoleFilter
	bindingFilter       BindingFilter
}

type recordingOperationLog struct{ entry operationlog.Entry }
type recordingSecurityLog struct{ entry securitylog.Entry }

func (*recordingOperationLog) Enabled() bool { return true }
func (r *recordingOperationLog) Record(_ context.Context, entry operationlog.Entry) error {
	r.entry = entry
	return nil
}
func (*recordingSecurityLog) Enabled() bool    { return true }
func (*recordingSecurityLog) FailClosed() bool { return true }
func (r *recordingSecurityLog) Record(_ context.Context, entry securitylog.Entry) error {
	r.entry = entry
	return nil
}

func TestMutationRecordsOperationAfterCommit(t *testing.T) {
	databaseHandle, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = databaseHandle.Close() })
	db := sqlx.NewDb(databaseHandle, "postgres")
	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config").WithArgs("user-1").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	recorder := &recordingOperationLog{}
	service := NewService(&fakeRepository{}, database.NewTransactor(db))
	service.operations = recorder
	ctx := principal.WithContext(t.Context(), principal.Principal{ID: "user-1", Type: principal.TypeUser, TenantID: "tenant-1", MembershipID: "membership-1"})
	if _, err := service.CreatePermission(ctx, "tenant-1", "invoice.read", "Read invoices", "invoice", "read"); err != nil {
		t.Fatal(err)
	}
	if recorder.entry.Operation != "authorization.permission_created" || !recorder.entry.Succeeded || recorder.entry.ResourceID != "tenant-1" {
		t.Fatalf("operation entry = %+v", recorder.entry)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMutationRecordsSecurityEventAfterCommit(t *testing.T) {
	databaseHandle, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = databaseHandle.Close() })
	db := sqlx.NewDb(databaseHandle, "postgres")
	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config").WithArgs("user-1").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	recorder := &recordingSecurityLog{}
	service := NewService(&fakeRepository{}, database.NewTransactor(db))
	service.security = recorder
	ctx := principal.WithContext(t.Context(), principal.Principal{ID: "user-1", Type: principal.TypeUser, TenantID: "tenant-1", MembershipID: "membership-1"})
	if _, err := service.CreateRole(ctx, "tenant-1", "manager", "Manager", "Tenant manager", "tenant"); err != nil {
		t.Fatal(err)
	}
	if recorder.entry.EventType != securitylog.EventTenantAuthorization || recorder.entry.Reason != "role_created" || !recorder.entry.Succeeded || recorder.entry.TenantID != "tenant-1" {
		t.Fatalf("security entry = %+v", recorder.entry)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
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
func (f *fakeRepository) SearchPermissions(_ context.Context, tenantID string, filter PermissionFilter, _, _ int) ([]Permission, int64, error) {
	f.permissionFilter = filter
	return f.catalogItems, int64(len(f.catalogItems)), nil
}
func (f *fakeRepository) ListPermissionCatalog(_ context.Context, tenantID, search string, _, _ int) ([]Permission, int64, error) {
	f.catalogTenant, f.catalogSearch = tenantID, search
	return f.catalogItems, int64(len(f.catalogItems)), nil
}
func (*fakeRepository) CreateRole(context.Context, sqlx.ExtContext, Role) error { return nil }
func (f *fakeRepository) GetRole(context.Context, string, string) (Role, error) {
	if f.role == nil {
		return Role{}, ErrNotFound
	}
	return *f.role, nil
}
func (*fakeRepository) UpdateRole(context.Context, sqlx.ExtContext, Role) error { return nil }
func (*fakeRepository) ListRoles(context.Context, string, int, int) ([]Role, int64, error) {
	return nil, 0, nil
}
func (f *fakeRepository) SearchRoles(_ context.Context, tenantID, keyword, status string, limit, offset int) ([]Role, int64, error) {
	f.roleSearchTenant, f.roleSearchKeyword, f.roleSearchStatus, f.roleSearchLimit, f.roleSearchOffset = tenantID, keyword, status, limit, offset
	if f.role == nil {
		return nil, 0, nil
	}
	return []Role{*f.role}, 1, nil
}
func (f *fakeRepository) SearchRolesFiltered(_ context.Context, tenantID string, filter RoleFilter, limit, offset int) ([]Role, int64, error) {
	f.roleFilter = filter
	status := ""
	if len(filter.Statuses) > 0 {
		status = filter.Statuses[0]
	}
	return f.SearchRoles(context.Background(), tenantID, filter.Keyword, status, limit, offset)
}
func (f *fakeRepository) BatchGetRoles(_ context.Context, tenantID string, ids []string) ([]Role, error) {
	f.roleBatchTenant, f.roleBatchIDs = tenantID, append([]string(nil), ids...)
	if f.role == nil {
		return nil, nil
	}
	return []Role{*f.role}, nil
}
func (*fakeRepository) GetPermission(context.Context, string, string) (Permission, error) {
	return Permission{}, ErrNotFound
}
func (*fakeRepository) CreateRolePermission(context.Context, sqlx.ExtContext, RolePermission) error {
	return nil
}
func (*fakeRepository) GetRolePermission(context.Context, string, string) (RolePermission, error) {
	return RolePermission{}, ErrNotFound
}
func (*fakeRepository) GetRolePermissionByPair(context.Context, string, string, string) (RolePermission, error) {
	return RolePermission{}, ErrNotFound
}
func (*fakeRepository) UpdateRolePermission(context.Context, sqlx.ExtContext, RolePermission) error {
	return nil
}
func (*fakeRepository) ListRolePermissions(context.Context, string, string) ([]RolePermission, error) {
	return nil, nil
}
func (*fakeRepository) BatchGetRolePermissions(context.Context, string, string, []string) ([]RolePermission, error) {
	return nil, nil
}
func (*fakeRepository) CreateBinding(context.Context, sqlx.ExtContext, Binding) error { return nil }
func (f *fakeRepository) GetBinding(_ context.Context, tenantID, _ string) (Binding, error) {
	if f.binding == nil {
		return Binding{}, ErrNotFound
	}
	if f.binding.TenantID != tenantID {
		return Binding{}, ErrNotFound
	}
	return *f.binding, nil
}
func (*fakeRepository) UpdateBinding(context.Context, sqlx.ExtContext, Binding) error { return nil }
func (*fakeRepository) ListBindings(context.Context, string, string, string, int, int) ([]Binding, int64, error) {
	return nil, 0, nil
}
func (f *fakeRepository) SearchBindings(_ context.Context, _ string, filter BindingFilter, _, _ int) ([]Binding, int64, error) {
	f.bindingFilter = filter
	return nil, 0, nil
}

func (f *fakeRepository) Resolve(_ context.Context, tenantID, subjectID, subjectType, _, _ string) ([]resolvedGrant, uint64, error) {
	f.resolveCalls++
	f.resolvedTenant, f.resolvedSubject, f.resolvedSubjectType = tenantID, subjectID, subjectType
	return f.grants, f.policyVersion, nil
}

func TestGetBindingEnforcesTenantScope(t *testing.T) {
	t.Parallel()
	service := NewService(&fakeRepository{binding: &Binding{ID: "binding-1", TenantID: "tenant-1", AuditFields: AuditFields{Version: 4}}}, &database.Transactor{})
	ctx := principal.WithContext(t.Context(), principal.Principal{ID: "user-1", Type: principal.TypeUser, TenantID: "tenant-1", MembershipID: "membership-1"})
	value, err := service.GetBinding(ctx, "tenant-1", " binding-1 ")
	if err != nil || value.Version != 4 {
		t.Fatalf("GetBinding() = (%+v, %v)", value, err)
	}
	other := principal.WithContext(t.Context(), principal.Principal{ID: "user-2", Type: principal.TypeUser, TenantID: "tenant-2", MembershipID: "membership-2"})
	if _, err := service.GetBinding(other, "tenant-2", "binding-1"); err == nil {
		t.Fatal("cross-tenant binding lookup must fail")
	}
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
func (f *fakeRepository) PolicyVersion(context.Context, string) (uint64, error) {
	return f.policyVersion, nil
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

func TestListFiltersNormalizeAndRejectInvalidRanges(t *testing.T) {
	repository := &fakeRepository{}
	service := NewService(repository, &database.Transactor{})
	ctx := principal.WithContext(t.Context(), principal.Principal{ID: "service-1", Type: principal.TypeServiceAccount})
	from, to := time.Now().Add(-time.Hour), time.Now()
	if _, err := service.SearchPermissions(ctx, "tenant-1", PermissionFilter{Keyword: " invoice ", IDs: []string{"p1", "p1"}, Statuses: []string{"active"}, CreatedFrom: &from, CreatedTo: &to}, 1, 20); err != nil {
		t.Fatal(err)
	}
	if repository.permissionFilter.Keyword != "invoice" || len(repository.permissionFilter.IDs) != 1 {
		t.Fatalf("permission filter = %+v", repository.permissionFilter)
	}
	if _, err := service.SearchRolesFiltered(ctx, "tenant-1", RoleFilter{Statuses: []string{"unknown"}}, 1, 20); err == nil {
		t.Fatal("invalid role status must be rejected")
	}
	if _, err := service.SearchBindings(ctx, "tenant-1", BindingFilter{SubjectID: "membership-1"}, 1, 20); err == nil {
		t.Fatal("subject id without subject type must be rejected")
	}
	if _, err := service.SearchPermissions(ctx, "tenant-1", PermissionFilter{CreatedFrom: &to, CreatedTo: &from}, 1, 20); err == nil {
		t.Fatal("reversed creation range must be rejected")
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
	if _, err := service.UpdateRole(ctx, "tenant-1", "role-2", "Changed", "", "tenant", "active", 1); err == nil {
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

func TestService_SearchAndBatchGetRolesAreTenantScopedAndBounded(t *testing.T) {
	t.Parallel()
	repository := &fakeRepository{role: &Role{ID: "role-1", TenantID: "tenant-1", Code: "operator"}}
	service := NewService(repository, &database.Transactor{})
	ctx := principal.WithContext(t.Context(), principal.Principal{ID: "user-1", Type: principal.TypeUser, TenantID: "tenant-1", MembershipID: "membership-1"})
	page, err := service.SearchRoles(ctx, " tenant-1 ", " operator ", "active", 2, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || repository.roleSearchTenant != "tenant-1" || repository.roleSearchKeyword != "operator" || repository.roleSearchLimit != 25 || repository.roleSearchOffset != 25 {
		t.Fatalf("SearchRoles() page=%+v repository=%+v", page, repository)
	}
	if _, err := service.SearchRoles(ctx, "tenant-1", strings.Repeat("x", 101), "", 1, 20); err == nil {
		t.Fatal("oversized role keyword must fail")
	}
	items, err := service.BatchGetRoles(ctx, "tenant-1", []string{" role-1 ", "role-1"})
	if err != nil || len(items) != 1 || len(repository.roleBatchIDs) != 1 || repository.roleBatchIDs[0] != "role-1" {
		t.Fatalf("BatchGetRoles() items=%+v ids=%v err=%v", items, repository.roleBatchIDs, err)
	}
	tooMany := make([]string, 101)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("role-%d", index)
	}
	if _, err := service.BatchGetRoles(ctx, "tenant-1", tooMany); err == nil {
		t.Fatal("oversized role batch must fail")
	}
}

func TestService_BatchGetRolePermissionsValidatesBoundedIDs(t *testing.T) {
	t.Parallel()
	repository := &fakeRepository{role: &Role{ID: "role-1", TenantID: "tenant-1"}}
	service := NewService(repository, &database.Transactor{})
	ctx := principal.WithContext(t.Context(), principal.Principal{ID: "user-1", Type: principal.TypeUser, TenantID: "tenant-1", MembershipID: "membership-1"})
	items, err := service.BatchGetRolePermissions(ctx, "tenant-1", "role-1", nil)
	if err != nil || len(items) != 0 {
		t.Fatalf("empty BatchGetRolePermissions() = (%+v, %v)", items, err)
	}
	tooMany := make([]string, 101)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("permission-%d", index)
	}
	if _, err := service.BatchGetRolePermissions(ctx, "tenant-1", "role-1", tooMany); err == nil {
		t.Fatal("oversized permission batch must fail")
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
	_, err := service.UpdatePermission(t.Context(), "tenant-1", "permission-1", "Read invoices", "attributes[", "active", 1)
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

func TestValidSubjectForTenantSeparatesGlobalUsersFromMemberships(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		tenantID    string
		subjectType string
		want        bool
	}{
		{name: "platform user", tenantID: platformauthz.PlatformTenantID, subjectType: "user", want: true},
		{name: "platform service account", tenantID: platformauthz.PlatformTenantID, subjectType: "service_account", want: true},
		{name: "platform membership rejected", tenantID: platformauthz.PlatformTenantID, subjectType: "membership"},
		{name: "tenant membership", tenantID: "tenant-1", subjectType: "membership", want: true},
		{name: "tenant group", tenantID: "tenant-1", subjectType: "group", want: true},
		{name: "tenant global user rejected", tenantID: "tenant-1", subjectType: "user"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validSubjectForTenant(test.tenantID, test.subjectType); got != test.want {
				t.Fatalf("validSubjectForTenant(%q, %q) = %v, want %v", test.tenantID, test.subjectType, got, test.want)
			}
		})
	}
}
