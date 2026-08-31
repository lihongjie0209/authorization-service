DELETE FROM role_bindings WHERE tenant_id = '__platform__' AND role_id = 'platform-super-admin-role';
DELETE FROM role_permissions WHERE tenant_id = '__platform__' AND id = 'platform-super-admin-role-permission';
DELETE FROM roles WHERE tenant_id = '__platform__' AND id = 'platform-super-admin-role';
DELETE FROM permissions WHERE tenant_id = '__platform__' AND id = 'platform-super-admin-permission';
DROP INDEX IF EXISTS uq_role_bindings_subject_role;
