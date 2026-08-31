CREATE INDEX authorization_outbox_retention_idx ON authorization_outbox_events (published_at, id);
