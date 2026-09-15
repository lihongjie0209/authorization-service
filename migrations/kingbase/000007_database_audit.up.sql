CREATE OR REPLACE FUNCTION authorization_audit_row()
RETURNS trigger LANGUAGE plpgsql AS $audit$
DECLARE actor_id TEXT := NULLIF(current_setting('app.actor_id', true), '');
BEGIN
  IF actor_id IS NULL THEN RAISE EXCEPTION 'app.actor_id must be set for audited writes'; END IF;
  IF TG_OP = 'INSERT' THEN NEW.created_at := statement_timestamp(); NEW.updated_at := NEW.created_at; NEW.created_by := actor_id; NEW.updated_by := actor_id; NEW.version := 1; NEW.deleted_at := NULL; NEW.deleted_by := NULL; RETURN NEW; END IF;
  IF TG_OP = 'UPDATE' THEN NEW.created_at := OLD.created_at; NEW.created_by := OLD.created_by; NEW.updated_at := statement_timestamp(); NEW.updated_by := actor_id; NEW.version := OLD.version + 1; IF OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL THEN NEW.deleted_at := statement_timestamp(); NEW.deleted_by := actor_id; ELSIF OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS NULL THEN NEW.deleted_by := NULL; ELSE NEW.deleted_at := OLD.deleted_at; NEW.deleted_by := OLD.deleted_by; END IF; RETURN NEW; END IF;
  RAISE EXCEPTION 'physical DELETE is forbidden on audited table %, use deleted_at', TG_TABLE_NAME;
END;
$audit$;

ALTER TABLE permissions ADD COLUMN deleted_at TIMESTAMPTZ, ADD COLUMN deleted_by TEXT;
ALTER TABLE roles ADD COLUMN deleted_at TIMESTAMPTZ, ADD COLUMN deleted_by TEXT;
ALTER TABLE role_permissions ADD COLUMN deleted_at TIMESTAMPTZ, ADD COLUMN deleted_by TEXT;
ALTER TABLE role_bindings ADD COLUMN deleted_at TIMESTAMPTZ, ADD COLUMN deleted_by TEXT;
ALTER TABLE authorization_policy_versions ADD COLUMN deleted_at TIMESTAMPTZ, ADD COLUMN deleted_by TEXT;
ALTER TABLE authorization_subject_groups ADD COLUMN deleted_at TIMESTAMPTZ, ADD COLUMN deleted_by TEXT;
ALTER TABLE authorization_processed_events ADD COLUMN deleted_at TIMESTAMPTZ, ADD COLUMN deleted_by TEXT;
ALTER TABLE authorization_outbox_events ADD COLUMN deleted_at TIMESTAMPTZ, ADD COLUMN deleted_by TEXT;

CREATE TRIGGER permissions_audit_row BEFORE INSERT OR UPDATE OR DELETE ON permissions FOR EACH ROW EXECUTE FUNCTION authorization_audit_row();
CREATE TRIGGER roles_audit_row BEFORE INSERT OR UPDATE OR DELETE ON roles FOR EACH ROW EXECUTE FUNCTION authorization_audit_row();
CREATE TRIGGER role_permissions_audit_row BEFORE INSERT OR UPDATE OR DELETE ON role_permissions FOR EACH ROW EXECUTE FUNCTION authorization_audit_row();
CREATE TRIGGER role_bindings_audit_row BEFORE INSERT OR UPDATE OR DELETE ON role_bindings FOR EACH ROW EXECUTE FUNCTION authorization_audit_row();
CREATE TRIGGER authorization_policy_versions_audit_row BEFORE INSERT OR UPDATE OR DELETE ON authorization_policy_versions FOR EACH ROW EXECUTE FUNCTION authorization_audit_row();
CREATE TRIGGER authorization_subject_groups_audit_row BEFORE INSERT OR UPDATE OR DELETE ON authorization_subject_groups FOR EACH ROW EXECUTE FUNCTION authorization_audit_row();
CREATE TRIGGER authorization_processed_events_audit_row BEFORE INSERT OR UPDATE OR DELETE ON authorization_processed_events FOR EACH ROW EXECUTE FUNCTION authorization_audit_row();

COMMENT ON TABLE authorization_outbox_events IS 'High-volume bounded-retention exception: audit columns are populated by the owning transaction; published rows are physically purged in bounded batches.';

