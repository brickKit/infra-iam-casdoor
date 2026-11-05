-- Foundations item 4, T9c (assembly protocol 15, 6.6): a session records the deployment's recovery generation it was
-- created in; a full recovery advances the generation, and every session from before ends (reason recovery).
ALTER TABLE iam_session ADD COLUMN recovery_generation bigint;
UPDATE iam_session SET recovery_generation = (SELECT generation FROM be_recovery_generation);
ALTER TABLE iam_session ALTER COLUMN recovery_generation SET NOT NULL;
ALTER TABLE iam_session DROP CONSTRAINT iam_session_end_reason_check;
ALTER TABLE iam_session ADD CONSTRAINT iam_session_end_reason_check
    CHECK (end_reason IN ('logout', 'idle', 'absolute', 'disabled', 'frozen', 'revoked', 'password', 'second_factor',
        'forced', 'recovery'));
CREATE INDEX iam_session_live_generation ON iam_session (recovery_generation) WHERE ended_at IS NULL;
