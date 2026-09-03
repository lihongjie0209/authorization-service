package grpctransport

import (
	"context"
	"strings"

	authorizationdomain "github.com/lihongjie0209/authorization-service/internal/authorization"
	authorizationv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/authorization/v1"
	commonv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/common/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type authorizationServer struct {
	authorizationv1.UnimplementedAuthorizationServiceServer
	service *authorizationdomain.Service
}

func (s *authorizationServer) Check(ctx context.Context, request *authorizationv1.CheckRequest) (*authorizationv1.CheckResponse, error) {
	decision, err := s.service.CheckWithAttributes(ctx, request.GetTenantId(), request.GetSubject().GetId(), subjectTypeString(request.GetSubject().GetType()), request.GetResourceType(), request.GetResourceId(), request.GetAction(), request.GetAttributes())
	if err != nil {
		return nil, grpcError(err)
	}
	return toProtoDecision(decision), nil
}

func (s *authorizationServer) BatchCheck(ctx context.Context, request *authorizationv1.BatchCheckRequest) (*authorizationv1.BatchCheckResponse, error) {
	decisions := make([]*authorizationv1.CheckResponse, 0, len(request.GetChecks()))
	for _, check := range request.GetChecks() {
		decision, err := s.Check(ctx, check)
		if err != nil {
			return nil, err
		}
		decisions = append(decisions, decision)
	}
	return &authorizationv1.BatchCheckResponse{Decisions: decisions}, nil
}

func (s *authorizationServer) ResolveDataScope(ctx context.Context, request *authorizationv1.ResolveDataScopeRequest) (*authorizationv1.ResolveDataScopeResponse, error) {
	decision, err := s.Check(ctx, request.GetCheck())
	if err != nil {
		return nil, err
	}
	return &authorizationv1.ResolveDataScopeResponse{Decision: decision}, nil
}

func (s *authorizationServer) InvalidateSubject(_ context.Context, request *authorizationv1.InvalidateSubjectRequest) (*authorizationv1.InvalidateSubjectResponse, error) {
	if err := s.service.InvalidateSubject(request.GetTenantId(), request.GetSubject().GetId(), subjectTypeString(request.GetSubject().GetType())); err != nil {
		return nil, grpcError(err)
	}
	return &authorizationv1.InvalidateSubjectResponse{}, nil
}

func (s *authorizationServer) CreatePermission(ctx context.Context, request *authorizationv1.CreatePermissionRequest) (*authorizationv1.CreatePermissionResponse, error) {
	value, err := s.service.CreatePermission(ctx, request.GetTenantId(), request.GetCode(), request.GetName(), request.GetResourceType(), request.GetAction(), request.GetConditionExpression())
	if err != nil {
		return nil, grpcError(err)
	}
	return &authorizationv1.CreatePermissionResponse{Permission: toProtoPermission(value)}, nil
}
func (s *authorizationServer) GetPermission(ctx context.Context, request *authorizationv1.GetPermissionRequest) (*authorizationv1.GetPermissionResponse, error) {
	value, err := s.service.GetPermission(ctx, request.GetPermissionId())
	if err != nil {
		return nil, grpcError(err)
	}
	return &authorizationv1.GetPermissionResponse{Permission: toProtoPermission(value)}, nil
}
func (s *authorizationServer) UpdatePermission(ctx context.Context, request *authorizationv1.UpdatePermissionRequest) (*authorizationv1.UpdatePermissionResponse, error) {
	value, err := s.service.UpdatePermission(ctx, request.GetPermissionId(), request.GetName(), request.GetConditionExpression(), request.GetStatus(), request.GetExpectedVersion())
	if err != nil {
		return nil, grpcError(err)
	}
	return &authorizationv1.UpdatePermissionResponse{Permission: toProtoPermission(value)}, nil
}
func (s *authorizationServer) ListPermissions(ctx context.Context, request *authorizationv1.ListPermissionsRequest) (*authorizationv1.ListPermissionsResponse, error) {
	page, size := protoPage(request.GetPage())
	values, err := s.service.ListPermissions(ctx, request.GetTenantId(), page, size)
	if err != nil {
		return nil, grpcError(err)
	}
	items := make([]*authorizationv1.Permission, 0, len(values.Items))
	for _, value := range values.Items {
		items = append(items, toProtoPermission(value))
	}
	return &authorizationv1.ListPermissionsResponse{Permissions: items, Page: pageResult(values.Total, values.Page, values.PageSize)}, nil
}
func (s *authorizationServer) CreateRole(ctx context.Context, request *authorizationv1.CreateRoleRequest) (*authorizationv1.CreateRoleResponse, error) {
	value, err := s.service.CreateRole(ctx, request.GetTenantId(), request.GetCode(), request.GetName(), request.GetDescription(), request.GetDataScope())
	if err != nil {
		return nil, grpcError(err)
	}
	return &authorizationv1.CreateRoleResponse{Role: toProtoRole(value)}, nil
}
func (s *authorizationServer) GetRole(ctx context.Context, request *authorizationv1.GetRoleRequest) (*authorizationv1.GetRoleResponse, error) {
	value, err := s.service.GetRole(ctx, request.GetRoleId())
	if err != nil {
		return nil, grpcError(err)
	}
	return &authorizationv1.GetRoleResponse{Role: toProtoRole(value)}, nil
}
func (s *authorizationServer) UpdateRole(ctx context.Context, request *authorizationv1.UpdateRoleRequest) (*authorizationv1.UpdateRoleResponse, error) {
	value, err := s.service.UpdateRole(ctx, request.GetRoleId(), request.GetName(), request.GetDescription(), request.GetDataScope(), request.GetStatus(), request.GetExpectedVersion())
	if err != nil {
		return nil, grpcError(err)
	}
	return &authorizationv1.UpdateRoleResponse{Role: toProtoRole(value)}, nil
}
func (s *authorizationServer) ListRoles(ctx context.Context, request *authorizationv1.ListRolesRequest) (*authorizationv1.ListRolesResponse, error) {
	page, size := protoPage(request.GetPage())
	values, err := s.service.ListRoles(ctx, request.GetTenantId(), page, size)
	if err != nil {
		return nil, grpcError(err)
	}
	items := make([]*authorizationv1.Role, 0, len(values.Items))
	for _, value := range values.Items {
		items = append(items, toProtoRole(value))
	}
	return &authorizationv1.ListRolesResponse{Roles: items, Page: pageResult(values.Total, values.Page, values.PageSize)}, nil
}
func (s *authorizationServer) GrantRolePermission(ctx context.Context, request *authorizationv1.GrantRolePermissionRequest) (*authorizationv1.GrantRolePermissionResponse, error) {
	value, err := s.service.GrantRolePermission(ctx, request.GetTenantId(), request.GetRoleId(), request.GetPermissionId())
	if err != nil {
		return nil, grpcError(err)
	}
	return &authorizationv1.GrantRolePermissionResponse{RolePermission: toProtoRolePermission(value)}, nil
}
func (s *authorizationServer) RevokeRolePermission(ctx context.Context, request *authorizationv1.RevokeRolePermissionRequest) (*authorizationv1.RevokeRolePermissionResponse, error) {
	value, err := s.service.RevokeRolePermission(ctx, request.GetRolePermissionId(), request.GetExpectedVersion())
	if err != nil {
		return nil, grpcError(err)
	}
	return &authorizationv1.RevokeRolePermissionResponse{RolePermission: toProtoRolePermission(value)}, nil
}
func (s *authorizationServer) ListRolePermissions(ctx context.Context, request *authorizationv1.ListRolePermissionsRequest) (*authorizationv1.ListRolePermissionsResponse, error) {
	values, err := s.service.ListRolePermissions(ctx, request.GetRoleId())
	if err != nil {
		return nil, grpcError(err)
	}
	items := make([]*authorizationv1.RolePermission, 0, len(values))
	for _, value := range values {
		items = append(items, toProtoRolePermission(value))
	}
	return &authorizationv1.ListRolePermissionsResponse{RolePermissions: items}, nil
}
func (s *authorizationServer) CreateBinding(ctx context.Context, request *authorizationv1.CreateBindingRequest) (*authorizationv1.CreateBindingResponse, error) {
	value, err := s.service.CreateBinding(ctx, request.GetTenantId(), request.GetSubject().GetId(), subjectTypeString(request.GetSubject().GetType()), request.GetRoleId(), request.GetOrganizationUnitId())
	if err != nil {
		return nil, grpcError(err)
	}
	return &authorizationv1.CreateBindingResponse{Binding: toProtoBinding(value)}, nil
}
func (s *authorizationServer) GetBinding(ctx context.Context, request *authorizationv1.GetBindingRequest) (*authorizationv1.GetBindingResponse, error) {
	value, err := s.service.GetBinding(ctx, request.GetBindingId())
	if err != nil {
		return nil, grpcError(err)
	}
	return &authorizationv1.GetBindingResponse{Binding: toProtoBinding(value)}, nil
}
func (s *authorizationServer) RevokeBinding(ctx context.Context, request *authorizationv1.RevokeBindingRequest) (*authorizationv1.RevokeBindingResponse, error) {
	value, err := s.service.RevokeBinding(ctx, request.GetBindingId(), request.GetExpectedVersion())
	if err != nil {
		return nil, grpcError(err)
	}
	return &authorizationv1.RevokeBindingResponse{Binding: toProtoBinding(value)}, nil
}
func (s *authorizationServer) ListBindings(ctx context.Context, request *authorizationv1.ListBindingsRequest) (*authorizationv1.ListBindingsResponse, error) {
	page, size := protoPage(request.GetPage())
	subjectID, subjectType := "", ""
	if request.GetSubject() != nil {
		subjectID, subjectType = request.GetSubject().GetId(), subjectTypeString(request.GetSubject().GetType())
	}
	values, err := s.service.ListBindings(ctx, request.GetTenantId(), subjectID, subjectType, page, size)
	if err != nil {
		return nil, grpcError(err)
	}
	items := make([]*authorizationv1.Binding, 0, len(values.Items))
	for _, value := range values.Items {
		items = append(items, toProtoBinding(value))
	}
	return &authorizationv1.ListBindingsResponse{Bindings: items, Page: pageResult(values.Total, values.Page, values.PageSize)}, nil
}

func toProtoDecision(value authorizationdomain.Decision) *authorizationv1.CheckResponse {
	return &authorizationv1.CheckResponse{Allowed: value.Allowed, DecisionId: value.DecisionID, Reason: value.Reason, PolicyVersion: value.PolicyVersion, DataScope: dataScopeProto(value.DataScope), OrganizationUnitIds: value.OrganizationUnitIDs}
}
func toProtoPermission(value authorizationdomain.Permission) *authorizationv1.Permission {
	return &authorizationv1.Permission{Id: value.ID, TenantId: value.TenantID, Code: value.Code, Name: value.Name, ResourceType: value.ResourceType, Action: value.Action, Status: value.Status, Version: value.Version, CreatedAt: timestamppb.New(value.CreatedAt), UpdatedAt: timestamppb.New(value.UpdatedAt), CreatedBy: value.CreatedBy, UpdatedBy: value.UpdatedBy, ConditionExpression: value.ConditionExpression}
}
func toProtoRole(value authorizationdomain.Role) *authorizationv1.Role {
	return &authorizationv1.Role{Id: value.ID, TenantId: value.TenantID, Code: value.Code, Name: value.Name, Description: value.Description, DataScope: value.DataScope, Status: value.Status, Version: value.Version, CreatedAt: timestamppb.New(value.CreatedAt), UpdatedAt: timestamppb.New(value.UpdatedAt), CreatedBy: value.CreatedBy, UpdatedBy: value.UpdatedBy}
}
func toProtoRolePermission(value authorizationdomain.RolePermission) *authorizationv1.RolePermission {
	return &authorizationv1.RolePermission{Id: value.ID, TenantId: value.TenantID, RoleId: value.RoleID, PermissionId: value.PermissionID, Status: value.Status, Version: value.Version, CreatedAt: timestamppb.New(value.CreatedAt), UpdatedAt: timestamppb.New(value.UpdatedAt), CreatedBy: value.CreatedBy, UpdatedBy: value.UpdatedBy}
}
func toProtoBinding(value authorizationdomain.Binding) *authorizationv1.Binding {
	return &authorizationv1.Binding{Id: value.ID, TenantId: value.TenantID, Subject: &authorizationv1.Subject{Id: value.SubjectID, Type: subjectTypeProto(value.SubjectType)}, RoleId: value.RoleID, OrganizationUnitId: value.OrganizationUnitID, Status: value.Status, Version: value.Version, CreatedAt: timestamppb.New(value.CreatedAt), UpdatedAt: timestamppb.New(value.UpdatedAt), CreatedBy: value.CreatedBy, UpdatedBy: value.UpdatedBy}
}
func protoPage(value *commonv1.PageRequest) (int, int) {
	if value == nil {
		return 0, 0
	}
	return int(value.GetPage()), int(value.GetPageSize())
}
func pageResult(total int64, page, size int) *commonv1.PageResult {
	return &commonv1.PageResult{Total: uint64(total), Page: uint32(page), PageSize: uint32(size)}
}
func subjectTypeString(value authorizationv1.SubjectType) string {
	return strings.ToLower(strings.TrimPrefix(value.String(), "SUBJECT_TYPE_"))
}
func subjectTypeProto(value string) authorizationv1.SubjectType {
	return authorizationv1.SubjectType(authorizationv1.SubjectType_value["SUBJECT_TYPE_"+strings.ToUpper(value)])
}
func dataScopeProto(value string) authorizationv1.DataScopeType {
	return authorizationv1.DataScopeType(authorizationv1.DataScopeType_value["DATA_SCOPE_TYPE_"+strings.ToUpper(value)])
}
