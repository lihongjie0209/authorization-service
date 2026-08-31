CREATE INDEX authorization_outbox_retention_idx ON authorization_outbox_events (published_at, id) WHERE published_at IS NOT NULL;
