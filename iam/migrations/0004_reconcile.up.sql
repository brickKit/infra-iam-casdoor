-- The account's status (security 09a's be.security.account_status) and what the last full comparison saw in Casdoor
-- (security 03: an external product without a reliable change sequence is compared in full, every P_pull and before
-- every echo). The product coordinate is Casdoor's updatedTime of the user: a disablement is recorded with it.
ALTER TABLE iam_account ADD COLUMN status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'disabled', 'security_frozen'));
ALTER TABLE iam_account ADD COLUMN security_mark text NOT NULL DEFAULT 'none'
    CHECK (security_mark IN ('none', 'compromised', 'suspicious'));
ALTER TABLE iam_account ADD COLUMN product_forbidden boolean;      -- NULL: never compared
ALTER TABLE iam_account ADD COLUMN product_password_at text;       -- Casdoor's lastChangePasswordTime
ALTER TABLE iam_account ADD COLUMN product_mfa text;               -- a digest of the second factors' state
ALTER TABLE iam_account ADD COLUMN product_updated text;           -- Casdoor's updatedTime: the product coordinate
ALTER TABLE iam_account ADD COLUMN product_seen_at timestamptz;

-- The member's own record of every status change it made or saw (protocol 15's evidence of a disablement, kept here
-- until the evidence store of foundations item 4): which status, from where, at which product coordinate and version.
CREATE TABLE iam_status_evidence (
    id               uuid PRIMARY KEY,
    principal        uuid NOT NULL REFERENCES iam_account,
    status           text NOT NULL,
    source           text NOT NULL CHECK (source IN ('console', 'rollback', 'adapter')),
    product_updated  text,
    security_version bigint NOT NULL,
    recorded_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX iam_status_evidence_principal ON iam_status_evidence (principal, recorded_at);

ALTER TABLE iam_session DROP CONSTRAINT iam_session_end_reason_check;
ALTER TABLE iam_session ADD CONSTRAINT iam_session_end_reason_check
    CHECK (end_reason IN ('logout', 'idle', 'absolute', 'disabled', 'revoked', 'password', 'second_factor', 'forced'));
