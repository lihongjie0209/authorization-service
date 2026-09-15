CREATE INDEX idx_permissions_tenant_status_created ON permissions (tenant_id, status, created_at DESC, id) WHERE deleted_at IS NULL;
CREATE INDEX idx_roles_tenant_status_created ON roles (tenant_id, status, created_at DESC, id) WHERE deleted_at IS NULL;
CREATE INDEX idx_roles_tenant_scope_status ON roles (tenant_id, data_scope, status, id) WHERE deleted_at IS NULL;
CREATE INDEX idx_role_bindings_tenant_status_created ON role_bindings (tenant_id, status, created_at DESC, id) WHERE deleted_at IS NULL;
CREATE INDEX idx_role_bindings_tenant_role_status ON role_bindings (tenant_id, role_id, status, id) WHERE deleted_at IS NULL;
CREATE INDEX idx_role_bindings_tenant_org_status ON role_bindings (tenant_id, organization_unit_id, status, id) WHERE deleted_at IS NULL;
