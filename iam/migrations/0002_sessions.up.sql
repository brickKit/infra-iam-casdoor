-- Foundations item 2 (be-protocol P8.27, P8.28; security 02 TI11): an account is bound by the provider's issuer and
-- subject, never by an e-mail or a login name, and carries its security version; the session generation, never
-- used, goes (staleness follows the account's version); a password change is a reason a session ends.
ALTER TABLE iam_account ADD COLUMN issuer text NOT NULL DEFAULT '';   -- '' only for rows bound before: adopted at start
ALTER TABLE iam_account ADD COLUMN security_version bigint NOT NULL DEFAULT 1 CHECK (security_version >= 1);
ALTER TABLE iam_account DROP CONSTRAINT iam_account_provider_provider_subject_key;
ALTER TABLE iam_account ADD CONSTRAINT iam_account_binding UNIQUE (provider, issuer, provider_subject);

ALTER TABLE iam_session DROP COLUMN generation;
ALTER TABLE iam_session DROP CONSTRAINT iam_session_end_reason_check;
ALTER TABLE iam_session ADD CONSTRAINT iam_session_end_reason_check
    CHECK (end_reason IN ('logout', 'idle', 'absolute', 'disabled', 'revoked', 'password'));
