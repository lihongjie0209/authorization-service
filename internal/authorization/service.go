package authorization

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"cel.dev/cel-go/cel"
	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/authorization-service/internal/apperror"
	"github.com/lihongjie0209/authorization-service/internal/database"
	"github.com/lihongjie0209/microservice-platform-go/audit"
	"github.com/lihongjie0209/microservice-platform-go/eventbus"
	authorizationv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/authorization/v1"
	"go.uber.org/fx"
	"google.golang.org/protobuf/proto"
)

type Service struct {
	repository Repository
	transactor *database.Transactor
	now        func() time.Time
	cel        *cel.Env
	cacheTTL   time.Duration
	cacheMu    sync.RWMutex
	cache      map[string]decisionCacheEntry
}

type decisionCacheEntry struct {
	decision  Decision
	expiresAt time.Time
}

type PermissionCodeDecision struct {
	AllowedCodes  []string `json:"allowed_codes"`
	PolicyVersion uint64   `json:"policy_version"`
}

func NewService(repository Repository, transactor *database.Transactor) *Service {
	environment, _ := cel.NewEnv(cel.Variable("tenant_id", cel.StringType), cel.Variable("subject_id", cel.StringType), cel.Variable("resource_id", cel.StringType), cel.Variable("attributes", cel.MapType(cel.StringType, cel.StringType)))
	return &Service{repository: repository, transactor: transactor, now: time.Now, cel: environment, cacheTTL: 30 * time.Second, cache: make(map[string]decisionCacheEntry)}
}

func (s *Service) CreatePermission(ctx context.Context, tenantID, code, name, resourceType, action string, conditionExpression ...string) (Permission, error) {
	tenantID, code, name = strings.TrimSpace(tenantID), strings.ToLower(strings.TrimSpace(code)), strings.TrimSpace(name)
	resourceType, action = strings.ToLower(strings.TrimSpace(resourceType)), strings.ToLower(strings.TrimSpace(action))
	if tenantID == "" || code == "" || name == "" || resourceType == "" || action == "" {
		return Permission{}, apperror.Invalid("tenant_id, code, name, resource_type and action are required", nil)
	}
	condition := ""
	if len(conditionExpression) > 0 {
		condition = strings.TrimSpace(conditionExpression[0])
	}
	if condition != "" {
		if _, issues := s.cel.Compile(condition); issues != nil && issues.Err() != nil {
			return Permission{}, apperror.Invalid("invalid ABAC condition expression", issues.Err())
		}
	}
	fields, err := audit.New(ctx, s.now())
	if err != nil {
		return Permission{}, apperror.Unauthorized("authenticated actor is required")
	}
	value := Permission{ID: uuid.NewString(), TenantID: tenantID, Code: code, Name: name, ResourceType: resourceType, Action: action, ConditionExpression: condition, Status: "active", AuditFields: auditFields(fields)}
	if err := s.mutate(ctx, tenantID, "", "unspecified", "permission_created", fields, func(tx *sqlx.Tx) error { return s.repository.CreatePermission(ctx, tx, value) }); err != nil {
		return Permission{}, err
	}
	return value, nil
}

func (s *Service) ListPermissions(ctx context.Context, tenantID string, page, pageSize int) (Page[Permission], error) {
	page, pageSize, err := normalizePage(page, pageSize)
	if err != nil {
		return Page[Permission]{}, err
	}
	items, total, err := s.repository.ListPermissions(ctx, strings.TrimSpace(tenantID), pageSize, (page-1)*pageSize)
	return Page[Permission]{Items: items, Total: total, Page: page, PageSize: pageSize}, translate(err)
}

func (s *Service) UpdatePermission(ctx context.Context, id, name, conditionExpression, status string, version int64) (Permission, error) {
	id, name = strings.TrimSpace(id), strings.TrimSpace(name)
	conditionExpression, status = strings.TrimSpace(conditionExpression), strings.ToLower(strings.TrimSpace(status))
	if id == "" || name == "" || version < 1 || (status != "active" && status != "disabled") {
		return Permission{}, apperror.Invalid("invalid permission update", nil)
	}
	if conditionExpression != "" {
		if _, issues := s.cel.Compile(conditionExpression); issues != nil && issues.Err() != nil {
			return Permission{}, apperror.Invalid("invalid ABAC condition expression", issues.Err())
		}
	}
	current, err := s.repository.GetPermission(ctx, id)
	if err != nil {
		return Permission{}, translate(err)
	}
	actor, now, err := audit.UpdatedBy(ctx, s.now())
	if err != nil {
		return Permission{}, apperror.Unauthorized("authenticated actor is required")
	}
	value := current
	value.Name, value.ConditionExpression, value.Status = name, conditionExpression, status
	value.Version, value.UpdatedAt, value.UpdatedBy = version, now, actor
	fields := audit.Fields{Version: version, CreatedAt: current.CreatedAt, UpdatedAt: now, CreatedBy: current.CreatedBy, UpdatedBy: actor}
	if err := s.mutate(ctx, current.TenantID, "", "unspecified", "permission_updated", fields, func(tx *sqlx.Tx) error {
		return s.repository.UpdatePermission(ctx, tx, value)
	}); err != nil {
		return Permission{}, err
	}
	return s.repository.GetPermission(ctx, id)
}

func (s *Service) CreateRole(ctx context.Context, tenantID, code, name, description, dataScope string) (Role, error) {
	tenantID, code, name = strings.TrimSpace(tenantID), strings.ToLower(strings.TrimSpace(code)), strings.TrimSpace(name)
	dataScope = strings.ToLower(strings.TrimSpace(dataScope))
	if tenantID == "" || code == "" || name == "" || !validDataScope(dataScope) {
		return Role{}, apperror.Invalid("invalid role", nil)
	}
	fields, err := audit.New(ctx, s.now())
	if err != nil {
		return Role{}, apperror.Unauthorized("authenticated actor is required")
	}
	value := Role{ID: uuid.NewString(), TenantID: tenantID, Code: code, Name: name, Description: strings.TrimSpace(description), DataScope: dataScope, Status: "active", AuditFields: auditFields(fields)}
	if err := s.mutate(ctx, tenantID, "", "unspecified", "role_created", fields, func(tx *sqlx.Tx) error { return s.repository.CreateRole(ctx, tx, value) }); err != nil {
		return Role{}, err
	}
	return value, nil
}

func (s *Service) UpdateRole(ctx context.Context, id, name, description, dataScope, status string, version int64) (Role, error) {
	if id == "" || strings.TrimSpace(name) == "" || version < 1 || !validDataScope(dataScope) || (status != "active" && status != "disabled") {
		return Role{}, apperror.Invalid("invalid role update", nil)
	}
	current, err := s.repository.GetRole(ctx, id)
	if err != nil {
		return Role{}, translate(err)
	}
	actor, now, err := audit.UpdatedBy(ctx, s.now())
	if err != nil {
		return Role{}, apperror.Unauthorized("authenticated actor is required")
	}
	value := current
	value.Name, value.Description, value.DataScope, value.Status, value.Version, value.UpdatedAt, value.UpdatedBy = strings.TrimSpace(name), strings.TrimSpace(description), dataScope, status, version, now, actor
	fields := audit.Fields{Version: version, CreatedAt: current.CreatedAt, UpdatedAt: now, CreatedBy: current.CreatedBy, UpdatedBy: actor}
	if err := s.mutate(ctx, current.TenantID, "", "unspecified", "role_updated", fields, func(tx *sqlx.Tx) error { return s.repository.UpdateRole(ctx, tx, value) }); err != nil {
		return Role{}, err
	}
	return s.repository.GetRole(ctx, id)
}

func (s *Service) ListRoles(ctx context.Context, tenantID string, page, pageSize int) (Page[Role], error) {
	page, pageSize, err := normalizePage(page, pageSize)
	if err != nil {
		return Page[Role]{}, err
	}
	items, total, err := s.repository.ListRoles(ctx, strings.TrimSpace(tenantID), pageSize, (page-1)*pageSize)
	return Page[Role]{Items: items, Total: total, Page: page, PageSize: pageSize}, translate(err)
}

func (s *Service) GrantRolePermission(ctx context.Context, tenantID, roleID, permissionID string) (RolePermission, error) {
	role, err := s.repository.GetRole(ctx, roleID)
	if err != nil {
		return RolePermission{}, translate(err)
	}
	permission, err := s.repository.GetPermission(ctx, permissionID)
	if err != nil {
		return RolePermission{}, translate(err)
	}
	if tenantID == "" || tenantID != role.TenantID || tenantID != permission.TenantID {
		return RolePermission{}, apperror.Invalid("role and permission must belong to tenant", nil)
	}
	existing, existingErr := s.repository.GetRolePermissionByPair(ctx, roleID, permissionID)
	if existingErr == nil && existing.Status == "active" {
		return existing, nil
	}
	if existingErr != nil && !errors.Is(existingErr, ErrNotFound) {
		return RolePermission{}, translate(existingErr)
	}
	fields, err := audit.New(ctx, s.now())
	if err != nil {
		return RolePermission{}, apperror.Unauthorized("authenticated actor is required")
	}
	value := RolePermission{ID: uuid.NewString(), TenantID: tenantID, RoleID: roleID, PermissionID: permissionID, Status: "active", AuditFields: auditFields(fields)}
	operation := func(tx *sqlx.Tx) error { return s.repository.CreateRolePermission(ctx, tx, value) }
	if existingErr == nil {
		value = existing
		value.Status, value.UpdatedAt, value.UpdatedBy = "active", fields.UpdatedAt, fields.UpdatedBy
		operation = func(tx *sqlx.Tx) error { return s.repository.UpdateRolePermission(ctx, tx, value) }
	}
	if err := s.mutate(ctx, tenantID, "", "unspecified", "role_permission_granted", fields, operation); err != nil {
		return RolePermission{}, err
	}
	return s.repository.GetRolePermissionByPair(ctx, roleID, permissionID)
}

func (s *Service) RevokeRolePermission(ctx context.Context, id string, version int64) (RolePermission, error) {
	value, err := s.repository.GetRolePermission(ctx, id)
	if err != nil {
		return RolePermission{}, translate(err)
	}
	actor, now, err := audit.UpdatedBy(ctx, s.now())
	if err != nil {
		return RolePermission{}, apperror.Unauthorized("authenticated actor is required")
	}
	value.Status, value.Version, value.UpdatedAt, value.UpdatedBy = "revoked", version, now, actor
	fields := audit.Fields{Version: version, CreatedAt: value.CreatedAt, UpdatedAt: now, CreatedBy: value.CreatedBy, UpdatedBy: actor}
	if err := s.mutate(ctx, value.TenantID, "", "unspecified", "role_permission_revoked", fields, func(tx *sqlx.Tx) error { return s.repository.UpdateRolePermission(ctx, tx, value) }); err != nil {
		return RolePermission{}, err
	}
	return s.repository.GetRolePermission(ctx, id)
}
func (s *Service) ListRolePermissions(ctx context.Context, roleID string) ([]RolePermission, error) {
	values, err := s.repository.ListRolePermissions(ctx, roleID)
	return values, translate(err)
}

func (s *Service) CreateBinding(ctx context.Context, tenantID, subjectID, subjectType, roleID, organizationUnitID string) (Binding, error) {
	role, err := s.repository.GetRole(ctx, roleID)
	if err != nil {
		return Binding{}, translate(err)
	}
	subjectType = strings.ToLower(strings.TrimSpace(subjectType))
	if tenantID == "" || subjectID == "" || role.TenantID != tenantID || !validSubjectType(subjectType) {
		return Binding{}, apperror.Invalid("invalid role binding", nil)
	}
	fields, err := audit.New(ctx, s.now())
	if err != nil {
		return Binding{}, apperror.Unauthorized("authenticated actor is required")
	}
	value := Binding{ID: uuid.NewString(), TenantID: tenantID, SubjectID: subjectID, SubjectType: subjectType, RoleID: roleID, OrganizationUnitID: organizationUnitID, Status: "active", AuditFields: auditFields(fields)}
	if err := s.mutate(ctx, tenantID, subjectID, subjectType, "binding_created", fields, func(tx *sqlx.Tx) error { return s.repository.CreateBinding(ctx, tx, value) }); err != nil {
		return Binding{}, err
	}
	return value, nil
}

func (s *Service) RevokeBinding(ctx context.Context, id string, version int64) (Binding, error) {
	value, err := s.repository.GetBinding(ctx, id)
	if err != nil {
		return Binding{}, translate(err)
	}
	actor, now, err := audit.UpdatedBy(ctx, s.now())
	if err != nil {
		return Binding{}, apperror.Unauthorized("authenticated actor is required")
	}
	value.Status, value.Version, value.UpdatedAt, value.UpdatedBy = "revoked", version, now, actor
	fields := audit.Fields{Version: version, CreatedAt: value.CreatedAt, UpdatedAt: now, CreatedBy: value.CreatedBy, UpdatedBy: actor}
	if err := s.mutate(ctx, value.TenantID, value.SubjectID, value.SubjectType, "binding_revoked", fields, func(tx *sqlx.Tx) error { return s.repository.UpdateBinding(ctx, tx, value) }); err != nil {
		return Binding{}, err
	}
	return s.repository.GetBinding(ctx, id)
}

func (s *Service) ListBindings(ctx context.Context, tenantID, subjectID, subjectType string, page, pageSize int) (Page[Binding], error) {
	page, pageSize, err := normalizePage(page, pageSize)
	if err != nil {
		return Page[Binding]{}, err
	}
	items, total, err := s.repository.ListBindings(ctx, tenantID, subjectID, subjectType, pageSize, (page-1)*pageSize)
	return Page[Binding]{Items: items, Total: total, Page: page, PageSize: pageSize}, translate(err)
}

func (s *Service) Check(ctx context.Context, tenantID, subjectID, subjectType, resourceType, action string) (Decision, error) {
	return s.CheckWithAttributes(ctx, tenantID, subjectID, subjectType, resourceType, "", action, nil)
}

func (s *Service) CheckPermissionCodes(ctx context.Context, tenantID, subjectID, subjectType string, requested []string) (PermissionCodeDecision, error) {
	tenantID, subjectID, subjectType = strings.TrimSpace(tenantID), strings.TrimSpace(subjectID), strings.ToLower(strings.TrimSpace(subjectType))
	if len(requested) == 0 || len(requested) > 100 {
		return PermissionCodeDecision{}, apperror.Invalid("tenant_id, a valid subject, and 1 to 100 permission_codes are required", nil)
	}
	seen := make(map[string]struct{}, len(requested))
	codes := make([]string, 0, len(requested))
	for _, requestedCode := range requested {
		code := strings.ToLower(strings.TrimSpace(requestedCode))
		if code == "" {
			continue
		}
		if _, exists := seen[code]; !exists {
			seen[code] = struct{}{}
			codes = append(codes, code)
		}
	}
	if tenantID == "" || subjectID == "" || !validSubjectType(subjectType) || len(codes) == 0 {
		return PermissionCodeDecision{}, apperror.Invalid("tenant_id, a valid subject, and 1 to 100 permission_codes are required", nil)
	}
	grants, policyVersion, err := s.repository.ResolvePermissionCodes(ctx, tenantID, subjectID, subjectType, codes)
	if err != nil {
		return PermissionCodeDecision{}, translate(err)
	}
	allowed := make(map[string]struct{}, len(grants))
	allowAll := false
	for _, grant := range grants {
		// Navigation has no concrete resource or request attributes. Conditional
		// grants cannot be proven here and therefore remain hidden; the domain API
		// evaluates them later with its authoritative facts.
		if strings.TrimSpace(grant.ConditionExpression) != "" {
			continue
		}
		if grant.ResourceType == "*" && grant.Action == "*" {
			allowAll = true
		}
		allowed[grant.Code] = struct{}{}
	}
	result := PermissionCodeDecision{AllowedCodes: make([]string, 0, len(codes)), PolicyVersion: policyVersion}
	for _, code := range codes {
		if _, ok := allowed[code]; ok || allowAll {
			result.AllowedCodes = append(result.AllowedCodes, code)
		}
	}
	return result, nil
}
func (s *Service) CheckWithAttributes(ctx context.Context, tenantID, subjectID, subjectType, resourceType, resourceID, action string, attributes map[string]string) (Decision, error) {
	if tenantID == "" || subjectID == "" || !validSubjectType(subjectType) || resourceType == "" || action == "" {
		return Decision{}, apperror.Invalid("invalid authorization check", nil)
	}
	cacheKey := decisionCacheKey(tenantID, subjectID, subjectType, resourceType, resourceID, action, attributes)
	if decision, ok := s.cachedDecision(cacheKey); ok {
		return decision, nil
	}
	grants, policyVersion, err := s.repository.Resolve(ctx, tenantID, subjectID, subjectType, resourceType, action)
	if err != nil {
		return Decision{}, translate(err)
	}
	decision := Decision{DecisionID: uuid.NewString(), PolicyVersion: policyVersion, DataScope: "none", OrganizationUnitIDs: []string{}}
	if len(grants) == 0 {
		decision.Reason = "no matching active grant"
		s.storeDecision(cacheKey, decision)
		return decision, nil
	}
	for _, grant := range grants {
		matched, err := s.matchesCondition(grant.ConditionExpression, tenantID, subjectID, resourceID, attributes)
		if err != nil {
			return Decision{}, apperror.Internal(err)
		}
		if !matched {
			continue
		}
		decision.Allowed, decision.Reason = true, "matching active role grant"
		if scopeRank(grant.DataScope) > scopeRank(decision.DataScope) {
			decision.DataScope = grant.DataScope
		}
		if grant.DataScope == "organization" && grant.OrganizationUnitID != "" {
			decision.OrganizationUnitIDs = appendUnique(decision.OrganizationUnitIDs, grant.OrganizationUnitID)
		}
	}
	if !decision.Allowed {
		decision.Reason = "ABAC condition did not match"
	}
	s.storeDecision(cacheKey, decision)
	return decision, nil
}

func (s *Service) InvalidateSubject(tenantID, subjectID, subjectType string) error {
	tenantID, subjectID, subjectType = strings.TrimSpace(tenantID), strings.TrimSpace(subjectID), strings.ToLower(strings.TrimSpace(subjectType))
	if tenantID == "" || subjectID == "" || !validSubjectType(subjectType) {
		return apperror.Invalid("tenant_id and a valid subject are required", nil)
	}
	prefix := tenantID + "\x00" + subjectID + "\x00" + subjectType + "\x00"
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	for key := range s.cache {
		if strings.HasPrefix(key, prefix) {
			delete(s.cache, key)
		}
	}
	return nil
}

func (s *Service) cachedDecision(key string) (Decision, bool) {
	s.cacheMu.RLock()
	entry, ok := s.cache[key]
	s.cacheMu.RUnlock()
	if !ok || !s.now().Before(entry.expiresAt) {
		if ok {
			s.cacheMu.Lock()
			delete(s.cache, key)
			s.cacheMu.Unlock()
		}
		return Decision{}, false
	}
	entry.decision.OrganizationUnitIDs = append([]string(nil), entry.decision.OrganizationUnitIDs...)
	return entry.decision, true
}

func (s *Service) storeDecision(key string, decision Decision) {
	decision.OrganizationUnitIDs = append([]string(nil), decision.OrganizationUnitIDs...)
	s.cacheMu.Lock()
	s.cache[key] = decisionCacheEntry{decision: decision, expiresAt: s.now().Add(s.cacheTTL)}
	s.cacheMu.Unlock()
}

func (s *Service) invalidateTenant(tenantID string) {
	prefix := strings.TrimSpace(tenantID) + "\x00"
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	for key := range s.cache {
		if strings.HasPrefix(key, prefix) {
			delete(s.cache, key)
		}
	}
}

func decisionCacheKey(tenantID, subjectID, subjectType, resourceType, resourceID, action string, attributes map[string]string) string {
	parts := []string{tenantID, subjectID, strings.ToLower(subjectType), strings.ToLower(resourceType), resourceID, strings.ToLower(action)}
	keys := make([]string, 0, len(attributes))
	for key := range attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, key+"="+attributes[key])
	}
	return strings.Join(parts, "\x00")
}

func (s *Service) matchesCondition(expression, tenantID, subjectID, resourceID string, attributes map[string]string) (bool, error) {
	if strings.TrimSpace(expression) == "" {
		return true, nil
	}
	ast, issues := s.cel.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return false, issues.Err()
	}
	program, err := s.cel.Program(ast)
	if err != nil {
		return false, err
	}
	result, _, err := program.Eval(map[string]any{"tenant_id": tenantID, "subject_id": subjectID, "resource_id": resourceID, "attributes": attributes})
	if err != nil {
		return false, err
	}
	matched, ok := result.Value().(bool)
	if !ok {
		return false, errors.New("ABAC condition must return boolean")
	}
	return matched, nil
}

func (s *Service) mutate(ctx context.Context, tenantID, subjectID, subjectType, reason string, fields audit.Fields, operation func(*sqlx.Tx) error) error {
	err := s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if err := operation(tx); err != nil {
			return err
		}
		policyVersion, err := s.repository.BumpPolicyVersion(ctx, tx, tenantID, fields.UpdatedAt, fields.UpdatedBy)
		if err != nil {
			return err
		}
		event := &authorizationv1.AuthorizationChangedEvent{TenantId: tenantID, SubjectId: subjectID, SubjectType: subjectTypeProto(subjectType), PolicyVersion: policyVersion, Reason: reason}
		envelope, err := eventbus.NewEnvelope(eventbus.Metadata{EventID: uuid.NewString(), EventType: "platform.authorization.v1.AuthorizationChanged", AggregateID: tenantID, AggregateType: "authorization_policy", TenantID: tenantID, SchemaVersion: 1, ActorID: fields.UpdatedBy, OccurredAt: fields.UpdatedAt}, event)
		if err != nil {
			return fmt.Errorf("build authorization event: %w", err)
		}
		encoded, err := proto.Marshal(envelope)
		if err != nil {
			return fmt.Errorf("marshal authorization event: %w", err)
		}
		return s.repository.AddOutbox(ctx, tx, OutboxEvent{ID: envelope.GetEventId(), Subject: "platform.authorization.changed.v1", Envelope: encoded, AvailableAt: fields.UpdatedAt, AuditFields: auditFields(fields)})
	})
	err = translate(err)
	if err == nil {
		s.invalidateTenant(tenantID)
	}
	return err
}

func auditFields(value audit.Fields) AuditFields {
	return AuditFields{Version: value.Version, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, CreatedBy: value.CreatedBy, UpdatedBy: value.UpdatedBy}
}
func normalizePage(page, pageSize int) (int, int, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		return 0, 0, apperror.Invalid("page_size must not exceed 100", nil)
	}
	return page, pageSize, nil
}
func validDataScope(value string) bool {
	switch value {
	case "none", "self", "organization", "tenant", "all":
		return true
	}
	return false
}
func validSubjectType(value string) bool {
	switch value {
	case "membership", "service_account", "group", "user":
		return true
	}
	return false
}
func scopeRank(value string) int {
	switch value {
	case "self":
		return 1
	case "organization":
		return 2
	case "tenant":
		return 3
	case "all":
		return 4
	}
	return 0
}
func appendUnique(values []string, value string) []string {
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}
func subjectTypeProto(value string) authorizationv1.SubjectType {
	switch value {
	case "membership":
		return authorizationv1.SubjectType_SUBJECT_TYPE_MEMBERSHIP
	case "service_account":
		return authorizationv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT
	case "group":
		return authorizationv1.SubjectType_SUBJECT_TYPE_GROUP
	case "user":
		return authorizationv1.SubjectType_SUBJECT_TYPE_USER
	}
	return authorizationv1.SubjectType_SUBJECT_TYPE_UNSPECIFIED
}
func translate(err error) error {
	if err == nil {
		return nil
	}
	var appErr *apperror.Error
	if errors.As(err, &appErr) {
		return err
	}
	if errors.Is(err, ErrNotFound) {
		return apperror.NotFound("authorization resource not found")
	}
	if errors.Is(err, ErrStaleVersion) {
		return apperror.StaleVersion(err)
	}
	if authorizationUniqueViolation(err) {
		return apperror.Conflict("authorization resource already exists", err)
	}
	return apperror.Internal(err)
}
func authorizationUniqueViolation(err error) bool {
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		return mysqlErr.Number == 1062
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

var Module = fx.Module("authorization", fx.Provide(NewRepository, NewService, NewLocalAuthorizer, NewRuntimeGroupProjection))
