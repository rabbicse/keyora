-- OpenID Connect nonce on authorization codes, and credentials for the
-- optional tutorial-compatibility API (challenge-response login).

ALTER TABLE authorization_codes ADD COLUMN nonce TEXT NOT NULL DEFAULT '';

CREATE TABLE legacy_credentials (
    user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username   TEXT NOT NULL,
    salt       TEXT NOT NULL,
    verifier   TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE (tenant_id, username)
)
