CREATE UNIQUE INDEX uq_role_bindings_subject_role
    ON role_bindings (tenant_id, subject_type, subject_id, role_id);

INSERT IGNORE INTO permissions (id, tenant_id, code, name, resource_type, action, status, version, created_at, updated_at, created_by, updated_by, condition_expression)
VALUES ('platform-super-admin-permission', '__platform__', 'platform.super-admin', 'Platform super administrator', '*', '*', 'active', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'platform-bootstrap', 'platform-bootstrap', '');

INSERT IGNORE INTO roles (id, tenant_id, code, name, description, data_scope, status, version, created_at, updated_at, created_by, updated_by)
VALUES ('platform-super-admin-role', '__platform__', 'platform-super-admin', 'Platform super administrator', 'Full access to platform-scope administration', 'all', 'active', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'platform-bootstrap', 'platform-bootstrap');

INSERT IGNORE INTO role_permissions (id, tenant_id, role_id, permission_id, status, version, created_at, updated_at, created_by, updated_by)
SELECT 'platform-super-admin-role-permission', '__platform__', r.id, p.id, 'active', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'platform-bootstrap', 'platform-bootstrap'
FROM roles r, permissions p
WHERE r.tenant_id = '__platform__' AND r.code = 'platform-super-admin'
  AND p.tenant_id = '__platform__' AND p.code = 'platform.super-admin';
