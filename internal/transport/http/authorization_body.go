package httptransport

import (
	"time"

	"github.com/lihongjie0209/authorization-service/internal/authorization"
)

type PermissionBody struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenant_id"`
	Code                string    `json:"code"`
	Name                string    `json:"name"`
	ResourceType        string    `json:"resource_type"`
	Action              string    `json:"action"`
	ConditionExpression string    `json:"condition_expression"`
	Status              string    `json:"status"`
	Version             int64     `json:"version"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	CreatedBy           string    `json:"created_by"`
	UpdatedBy           string    `json:"updated_by"`
}

type RoleBody struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	DataScope   string    `json:"data_scope"`
	Status      string    `json:"status"`
	Version     int64     `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	CreatedBy   string    `json:"created_by"`
	UpdatedBy   string    `json:"updated_by"`
}

type RolePermissionBody struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	RoleID       string    `json:"role_id"`
	PermissionID string    `json:"permission_id"`
	Status       string    `json:"status"`
	Version      int64     `json:"version"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	CreatedBy    string    `json:"created_by"`
	UpdatedBy    string    `json:"updated_by"`
}

type BindingBody struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	SubjectID          string    `json:"subject_id"`
	SubjectType        string    `json:"subject_type"`
	RoleID             string    `json:"role_id"`
	OrganizationUnitID string    `json:"organization_unit_id"`
	Status             string    `json:"status"`
	Version            int64     `json:"version"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	CreatedBy          string    `json:"created_by"`
	UpdatedBy          string    `json:"updated_by"`
}

type DecisionBody struct {
	Allowed             bool     `json:"allowed"`
	DecisionID          string   `json:"decision_id"`
	Reason              string   `json:"reason"`
	PolicyVersion       uint64   `json:"policy_version"`
	DataScope           string   `json:"data_scope"`
	OrganizationUnitIDs []string `json:"organization_unit_ids"`
}

type PermissionCodeDecisionBody struct {
	AllowedCodes  []string `json:"allowed_codes"`
	PolicyVersion uint64   `json:"policy_version"`
}

type PermissionPageBody struct {
	Items    []PermissionBody `json:"items"`
	Total    int64            `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
}

type RolePageBody struct {
	Items    []RoleBody `json:"items"`
	Total    int64      `json:"total"`
	Page     int        `json:"page"`
	PageSize int        `json:"page_size"`
}

type BindingPageResponseBody struct {
	Items    []BindingBody `json:"items"`
	Total    int64         `json:"total"`
	Page     int           `json:"page"`
	PageSize int           `json:"page_size"`
}

type RolePermissionsBody struct {
	RolePermissions []RolePermissionBody `json:"role_permissions"`
}

type DecisionsBody struct {
	Decisions []DecisionBody `json:"decisions"`
}

func permissionBody(value authorization.Permission) PermissionBody {
	return PermissionBody{
		ID: value.ID, TenantID: value.TenantID, Code: value.Code, Name: value.Name,
		ResourceType: value.ResourceType, Action: value.Action, ConditionExpression: value.ConditionExpression,
		Status: value.Status, Version: value.Version, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
		CreatedBy: value.CreatedBy, UpdatedBy: value.UpdatedBy,
	}
}

func roleBody(value authorization.Role) RoleBody {
	return RoleBody{
		ID: value.ID, TenantID: value.TenantID, Code: value.Code, Name: value.Name,
		Description: value.Description, DataScope: value.DataScope, Status: value.Status, Version: value.Version,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, CreatedBy: value.CreatedBy, UpdatedBy: value.UpdatedBy,
	}
}

func rolePermissionBody(value authorization.RolePermission) RolePermissionBody {
	return RolePermissionBody{
		ID: value.ID, TenantID: value.TenantID, RoleID: value.RoleID, PermissionID: value.PermissionID,
		Status: value.Status, Version: value.Version, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
		CreatedBy: value.CreatedBy, UpdatedBy: value.UpdatedBy,
	}
}

func bindingBody(value authorization.Binding) BindingBody {
	return BindingBody{
		ID: value.ID, TenantID: value.TenantID, SubjectID: value.SubjectID, SubjectType: value.SubjectType,
		RoleID: value.RoleID, OrganizationUnitID: value.OrganizationUnitID, Status: value.Status,
		Version: value.Version, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
		CreatedBy: value.CreatedBy, UpdatedBy: value.UpdatedBy,
	}
}

func decisionBody(value authorization.Decision) DecisionBody {
	return DecisionBody{
		Allowed: value.Allowed, DecisionID: value.DecisionID, Reason: value.Reason,
		PolicyVersion: value.PolicyVersion, DataScope: value.DataScope,
		OrganizationUnitIDs: append([]string(nil), value.OrganizationUnitIDs...),
	}
}

func permissionBodies(values []authorization.Permission) []PermissionBody {
	result := make([]PermissionBody, len(values))
	for index := range values {
		result[index] = permissionBody(values[index])
	}
	return result
}

func roleBodies(values []authorization.Role) []RoleBody {
	result := make([]RoleBody, len(values))
	for index := range values {
		result[index] = roleBody(values[index])
	}
	return result
}

func rolePermissionBodies(values []authorization.RolePermission) []RolePermissionBody {
	result := make([]RolePermissionBody, len(values))
	for index := range values {
		result[index] = rolePermissionBody(values[index])
	}
	return result
}

func bindingBodies(values []authorization.Binding) []BindingBody {
	result := make([]BindingBody, len(values))
	for index := range values {
		result[index] = bindingBody(values[index])
	}
	return result
}

func permissionPageBody(value authorization.Page[authorization.Permission]) PermissionPageBody {
	return PermissionPageBody{Items: permissionBodies(value.Items), Total: value.Total, Page: value.Page, PageSize: value.PageSize}
}

func rolePageBody(value authorization.Page[authorization.Role]) RolePageBody {
	return RolePageBody{Items: roleBodies(value.Items), Total: value.Total, Page: value.Page, PageSize: value.PageSize}
}

func bindingPageBody(value authorization.Page[authorization.Binding]) BindingPageResponseBody {
	return BindingPageResponseBody{Items: bindingBodies(value.Items), Total: value.Total, Page: value.Page, PageSize: value.PageSize}
}
