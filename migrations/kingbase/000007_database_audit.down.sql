DROP TRIGGER IF EXISTS authorization_processed_events_audit_row ON authorization_processed_events;
DROP TRIGGER IF EXISTS authorization_subject_groups_audit_row ON authorization_subject_groups;
DROP TRIGGER IF EXISTS authorization_policy_versions_audit_row ON authorization_policy_versions;
DROP TRIGGER IF EXISTS role_bindings_audit_row ON role_bindings;
DROP TRIGGER IF EXISTS role_permissions_audit_row ON role_permissions;
DROP TRIGGER IF EXISTS roles_audit_row ON roles;
DROP TRIGGER IF EXISTS permissions_audit_row ON permissions;
DROP FUNCTION IF EXISTS authorization_audit_row();

ALTER TABLE authorization_outbox_events DROP COLUMN deleted_by, DROP COLUMN deleted_at;
ALTER TABLE authorization_processed_events DROP COLUMN deleted_by, DROP COLUMN deleted_at;
ALTER TABLE authorization_subject_groups DROP COLUMN deleted_by, DROP COLUMN deleted_at;
ALTER TABLE authorization_policy_versions DROP COLUMN deleted_by, DROP COLUMN deleted_at;
ALTER TABLE role_bindings DROP COLUMN deleted_by, DROP COLUMN deleted_at;
ALTER TABLE role_permissions DROP COLUMN deleted_by, DROP COLUMN deleted_at;
ALTER TABLE roles DROP COLUMN deleted_by, DROP COLUMN deleted_at;
ALTER TABLE permissions DROP COLUMN deleted_by, DROP COLUMN deleted_at;

