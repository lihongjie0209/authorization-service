package authorization

import "time"

type AuditFields struct {
	Version   int64     `db:"version" json:"version"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
	CreatedBy string    `db:"created_by" json:"created_by"`
	UpdatedBy string    `db:"updated_by" json:"updated_by"`
}

type Permission struct {
	ID                  string `db:"id" json:"id"`
	TenantID            string `db:"tenant_id" json:"tenant_id"`
	Code                string `db:"code" json:"code"`
	Name                string `db:"name" json:"name"`
	ResourceType        string `db:"resource_type" json:"resource_type"`
	Action              string `db:"action" json:"action"`
	ConditionExpression string `db:"condition_expression" json:"condition_expression"`
	Status              string `db:"status" json:"status"`
	AuditFields
}

type Role struct {
	ID          string `db:"id" json:"id"`
	TenantID    string `db:"tenant_id" json:"tenant_id"`
	Code        string `db:"code" json:"code"`
	Name        string `db:"name" json:"name"`
	Description string `db:"description" json:"description"`
	DataScope   string `db:"data_scope" json:"data_scope"`
	Status      string `db:"status" json:"status"`
	AuditFields
}

type RolePermission struct {
	ID           string `db:"id" json:"id"`
	TenantID     string `db:"tenant_id" json:"tenant_id"`
	RoleID       string `db:"role_id" json:"role_id"`
	PermissionID string `db:"permission_id" json:"permission_id"`
	Status       string `db:"status" json:"status"`
	AuditFields
}

type Binding struct {
	ID                 string `db:"id" json:"id"`
	TenantID           string `db:"tenant_id" json:"tenant_id"`
	SubjectID          string `db:"subject_id" json:"subject_id"`
	SubjectType        string `db:"subject_type" json:"subject_type"`
	RoleID             string `db:"role_id" json:"role_id"`
	OrganizationUnitID string `db:"organization_unit_id" json:"organization_unit_id"`
	Status             string `db:"status" json:"status"`
	AuditFields
}

type Decision struct {
	Allowed             bool     `json:"allowed"`
	DecisionID          string   `json:"decision_id"`
	Reason              string   `json:"reason"`
	PolicyVersion       uint64   `json:"policy_version"`
	DataScope           string   `json:"data_scope"`
	OrganizationUnitIDs []string `json:"organization_unit_ids"`
}

type Page[T any] struct {
	Items    []T   `json:"items"`
	Total    int64 `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
}

type OutboxEvent struct {
	ID          string
	Subject     string
	Envelope    []byte
	AvailableAt time.Time
	AuditFields
}
