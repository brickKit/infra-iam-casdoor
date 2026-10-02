DROP INDEX IF EXISTS webhook_deliveries_due_idx;
ALTER TABLE webhook_deliveries DROP COLUMN IF EXISTS next_attempt_at;
ALTER TABLE webhook_deliveries DROP COLUMN IF EXISTS attempts;
