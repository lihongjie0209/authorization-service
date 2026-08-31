package httptransport

import (
	"github.com/gin-gonic/gin"
	"github.com/lihongjie0209/authorization-service/internal/apperror"
)

type CreatePermissionRequest struct {
	TenantID            string `json:"tenant_id" binding:"required"`
	Code                string `json:"code" binding:"required"`
	Name                string `json:"name" binding:"required"`
	ResourceType        string `json:"resource_type" binding:"required"`
	Action              string `json:"action" binding:"required"`
	ConditionExpression string `json:"condition_expression"`
}
type ListPermissionsRequest struct {
	TenantID string `json:"tenant_id" binding:"required"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}
type UpdatePermissionRequest struct {
	PermissionID        string `json:"permission_id" binding:"required"`
	Name                string `json:"name" binding:"required"`
	ConditionExpression string `json:"condition_expression"`
	Status              string `json:"status" binding:"required"`
	Version             int64  `json:"version" binding:"required,gt=0"`
}
type CreateRoleRequest struct {
	TenantID    string `json:"tenant_id" binding:"required"`
	Code        string `json:"code" binding:"required"`
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	DataScope   string `json:"data_scope" binding:"required"`
}
type UpdateRoleRequest struct {
	RoleID      string `json:"role_id" binding:"required"`
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	DataScope   string `json:"data_scope" binding:"required"`
	Status      string `json:"status" binding:"required"`
	Version     int64  `json:"version" binding:"required,gt=0"`
}
type ListRolesRequest struct {
	TenantID string `json:"tenant_id" binding:"required"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}
type GrantRolePermissionRequest struct {
	TenantID     string `json:"tenant_id" binding:"required"`
	RoleID       string `json:"role_id" binding:"required"`
	PermissionID string `json:"permission_id" binding:"required"`
}
type RevokeRolePermissionRequest struct {
	RolePermissionID string `json:"role_permission_id" binding:"required"`
	Version          int64  `json:"version" binding:"required,gt=0"`
}
type ListRolePermissionsRequest struct {
	RoleID string `json:"role_id" binding:"required"`
}
type CreateBindingRequest struct {
	TenantID           string `json:"tenant_id" binding:"required"`
	SubjectID          string `json:"subject_id" binding:"required"`
	SubjectType        string `json:"subject_type" binding:"required"`
	RoleID             string `json:"role_id" binding:"required"`
	OrganizationUnitID string `json:"organization_unit_id"`
}
type RevokeBindingRequest struct {
	BindingID string `json:"binding_id" binding:"required"`
	Version   int64  `json:"version" binding:"required,gt=0"`
}
type ListBindingsRequest struct {
	TenantID    string `json:"tenant_id" binding:"required"`
	SubjectID   string `json:"subject_id"`
	SubjectType string `json:"subject_type"`
	Page        int    `json:"page"`
	PageSize    int    `json:"page_size"`
}
type CheckAuthorizationRequest struct {
	TenantID     string            `json:"tenant_id" binding:"required"`
	SubjectID    string            `json:"subject_id" binding:"required"`
	SubjectType  string            `json:"subject_type" binding:"required"`
	ResourceType string            `json:"resource_type" binding:"required"`
	ResourceID   string            `json:"resource_id"`
	Action       string            `json:"action" binding:"required"`
	Attributes   map[string]string `json:"attributes"`
}
type BatchCheckAuthorizationRequest struct {
	Checks []CheckAuthorizationRequest `json:"checks" binding:"required,min=1,max=100"`
}

// CreatePermission godoc
// @Summary Create a tenant permission
// @Tags authorization-permissions
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body CreatePermissionRequest true "Permission"
// @Success 200 {object} Response
// @Router /api/v1/authorization/permissions/create [post]
func (h *Handler) CreatePermission(c *gin.Context) {
	var request CreatePermissionRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	value, err := h.authorization.CreatePermission(c.Request.Context(), request.TenantID, request.Code, request.Name, request.ResourceType, request.Action, request.ConditionExpression)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, value)
}

// UpdatePermission godoc
// @Summary Update a tenant permission
// @Tags authorization-permissions
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body UpdatePermissionRequest true "Permission update"
// @Success 200 {object} Response
// @Router /api/v1/authorization/permissions/update [post]
func (h *Handler) UpdatePermission(c *gin.Context) {
	var request UpdatePermissionRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	value, err := h.authorization.UpdatePermission(c.Request.Context(), request.PermissionID, request.Name, request.ConditionExpression, request.Status, request.Version)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, value)
}

// ListPermissions godoc
// @Summary List tenant permissions
// @Tags authorization-permissions
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body ListPermissionsRequest true "Tenant and pagination"
// @Success 200 {object} Response
// @Router /api/v1/authorization/permissions/list [post]
func (h *Handler) ListPermissions(c *gin.Context) {
	var request ListPermissionsRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	value, err := h.authorization.ListPermissions(c.Request.Context(), request.TenantID, request.Page, request.PageSize)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, value)
}

// CreateRole godoc
// @Summary Create a tenant role
// @Tags authorization-roles
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body CreateRoleRequest true "Role"
// @Success 200 {object} Response
// @Router /api/v1/authorization/roles/create [post]
func (h *Handler) CreateRole(c *gin.Context) {
	var request CreateRoleRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	value, err := h.authorization.CreateRole(c.Request.Context(), request.TenantID, request.Code, request.Name, request.Description, request.DataScope)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, value)
}

// UpdateRole godoc
// @Summary Update a role with optimistic locking
// @Tags authorization-roles
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body UpdateRoleRequest true "Role and current version"
// @Success 200 {object} Response
// @Router /api/v1/authorization/roles/update [post]
func (h *Handler) UpdateRole(c *gin.Context) {
	var request UpdateRoleRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	value, err := h.authorization.UpdateRole(c.Request.Context(), request.RoleID, request.Name, request.Description, request.DataScope, request.Status, request.Version)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, value)
}

// ListRoles godoc
// @Summary List tenant roles
// @Tags authorization-roles
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body ListRolesRequest true "Tenant and pagination"
// @Success 200 {object} Response
// @Router /api/v1/authorization/roles/list [post]
func (h *Handler) ListRoles(c *gin.Context) {
	var request ListRolesRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	value, err := h.authorization.ListRoles(c.Request.Context(), request.TenantID, request.Page, request.PageSize)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, value)
}

// GrantRolePermission godoc
// @Summary Grant a permission to a role
// @Tags authorization-roles
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body GrantRolePermissionRequest true "Role permission"
// @Success 200 {object} Response
// @Router /api/v1/authorization/role-permissions/grant [post]
func (h *Handler) GrantRolePermission(c *gin.Context) {
	var request GrantRolePermissionRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	value, err := h.authorization.GrantRolePermission(c.Request.Context(), request.TenantID, request.RoleID, request.PermissionID)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, value)
}

// RevokeRolePermission godoc
// @Summary Revoke a role permission with optimistic locking
// @Tags authorization-roles
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body RevokeRolePermissionRequest true "Role permission and current version"
// @Success 200 {object} Response
// @Router /api/v1/authorization/role-permissions/revoke [post]
func (h *Handler) RevokeRolePermission(c *gin.Context) {
	var request RevokeRolePermissionRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	value, err := h.authorization.RevokeRolePermission(c.Request.Context(), request.RolePermissionID, request.Version)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, value)
}

// ListRolePermissions godoc
// @Summary List permissions assigned to a role
// @Tags authorization-roles
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body ListRolePermissionsRequest true "Role"
// @Success 200 {object} Response
// @Router /api/v1/authorization/role-permissions/list [post]
func (h *Handler) ListRolePermissions(c *gin.Context) {
	var request ListRolePermissionsRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	value, err := h.authorization.ListRolePermissions(c.Request.Context(), request.RoleID)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, gin.H{"role_permissions": value})
}

// CreateBinding godoc
// @Summary Bind a role to a membership, group, or service account
// @Tags authorization-bindings
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body CreateBindingRequest true "Role binding"
// @Success 200 {object} Response
// @Router /api/v1/authorization/bindings/create [post]
func (h *Handler) CreateBinding(c *gin.Context) {
	var request CreateBindingRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	value, err := h.authorization.CreateBinding(c.Request.Context(), request.TenantID, request.SubjectID, request.SubjectType, request.RoleID, request.OrganizationUnitID)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, value)
}

// RevokeBinding godoc
// @Summary Revoke a binding with optimistic locking
// @Tags authorization-bindings
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body RevokeBindingRequest true "Binding and current version"
// @Success 200 {object} Response
// @Router /api/v1/authorization/bindings/revoke [post]
func (h *Handler) RevokeBinding(c *gin.Context) {
	var request RevokeBindingRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	value, err := h.authorization.RevokeBinding(c.Request.Context(), request.BindingID, request.Version)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, value)
}

// ListBindings godoc
// @Summary List tenant or subject role bindings
// @Tags authorization-bindings
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body ListBindingsRequest true "Tenant, optional subject, and pagination"
// @Success 200 {object} Response
// @Router /api/v1/authorization/bindings/list [post]
func (h *Handler) ListBindings(c *gin.Context) {
	var request ListBindingsRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	value, err := h.authorization.ListBindings(c.Request.Context(), request.TenantID, request.SubjectID, request.SubjectType, request.Page, request.PageSize)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, value)
}

// CheckAuthorization godoc
// @Summary Preview an authorization decision
// @Tags authorization-decisions
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body CheckAuthorizationRequest true "Authorization check"
// @Success 200 {object} Response
// @Router /api/v1/authorization/check [post]
func (h *Handler) CheckAuthorization(c *gin.Context) {
	var request CheckAuthorizationRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	value, err := h.authorization.CheckWithAttributes(c.Request.Context(), request.TenantID, request.SubjectID, request.SubjectType, request.ResourceType, request.ResourceID, request.Action, request.Attributes)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, value)
}

// BatchCheckAuthorization godoc
// @Summary Preview up to 100 authorization decisions
// @Tags authorization-decisions
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body BatchCheckAuthorizationRequest true "Authorization checks"
// @Success 200 {object} Response
// @Router /api/v1/authorization/batch-check [post]
func (h *Handler) BatchCheckAuthorization(c *gin.Context) {
	var request BatchCheckAuthorizationRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	decisions := make([]any, 0, len(request.Checks))
	for _, check := range request.Checks {
		decision, err := h.authorization.CheckWithAttributes(c.Request.Context(), check.TenantID, check.SubjectID, check.SubjectType, check.ResourceType, check.ResourceID, check.Action, check.Attributes)
		if err != nil {
			Fail(c, h.logger, err)
			return
		}
		decisions = append(decisions, decision)
	}
	OK(c, gin.H{"decisions": decisions})
}
