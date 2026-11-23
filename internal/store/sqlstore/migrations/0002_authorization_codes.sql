-- OAuth 2.0 authorization codes (authorization code flow with PKCE).
-- Only the SHA-256 of a code is stored; codes are single use and short lived.

CREATE TABLE authorization_codes (
    id             TEXT PRIMARY KEY,
    code_hash      TEXT NOT NULL UNIQUE,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id     TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    scope          TEXT NOT NULL,
    created_at     BIGINT NOT NULL,
    expires_at     BIGINT NOT NULL,
    used_at        BIGINT
);
CREATE INDEX idx_authorization_codes_expires ON authorization_codes (expires_at)
