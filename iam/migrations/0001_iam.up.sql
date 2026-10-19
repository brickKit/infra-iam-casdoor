-- The identity member's own data (boundary card: accounts bound to the external identities, browser sessions; the
-- signing keys are files, protocol 19). The platform principal is ours: Casdoor's subject never leaves this table.
CREATE TABLE iam_account (
    principal        uuid PRIMARY KEY,                 -- the platform principal (UUIDv7), the tokens' sub
    provider         text NOT NULL,                    -- casdoor
    provider_subject text NOT NULL,                    -- the provider's stable subject (Casdoor's user id)
    username         text NOT NULL,                    -- owner/name in the provider, for people and diagnostics
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_subject)
);

-- A login in flight: the authorization request's state and PKCE verifier, for 10 minutes (protocol 20).
CREATE TABLE iam_login (
    state_hash text PRIMARY KEY,                       -- SHA-256 of the state the browser carries
    verifier   text NOT NULL,                          -- the PKCE code verifier
    return_to  text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX iam_login_created ON iam_login (created_at);

-- A browser session. The cookie holds a random secret; only its SHA-256 is stored.
CREATE TABLE iam_session (
    id_hash    text PRIMARY KEY,
    principal  uuid NOT NULL REFERENCES iam_account,
    generation integer NOT NULL DEFAULT 1,             -- advanced when the session's tokens must be renewed
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    ended_at   timestamptz,
    end_reason text CHECK (end_reason IN ('logout', 'idle', 'absolute', 'disabled', 'revoked'))
);
CREATE INDEX iam_session_principal ON iam_session (principal) WHERE ended_at IS NULL;
