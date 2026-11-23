-- Keyora initial schema.
-- Portable across PostgreSQL and SQLite: timestamps are Unix milliseconds
-- (BIGINT), list-valued columns are JSON text.

CREATE TABLE tenants (
    id         TEXT PRIMARY KEY,
    slug       TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE applications (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    type               TEXT NOT NULL,
    client_id          TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT NOT NULL,
    redirect_uris      TEXT NOT NULL,
    allowed_origins    TEXT NOT NULL,
    access_token_ttl   BIGINT NOT NULL,
    refresh_token_ttl  BIGINT NOT NULL,
    status             TEXT NOT NULL,
    created_at         BIGINT NOT NULL,
    updated_at         BIGINT NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE TABLE users (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email          TEXT NOT NULL,
    name           TEXT NOT NULL,
    password_hash  TEXT NOT NULL,
    status         TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL,
    failed_logins  INTEGER NOT NULL DEFAULT 0,
    locked_until   BIGINT,
    last_login_at  BIGINT,
    created_at     BIGINT NOT NULL,
    updated_at     BIGINT NOT NULL,
    UNIQUE (tenant_id, email)
);
CREATE INDEX idx_users_tenant_created ON users (tenant_id, created_at);

CREATE TABLE permissions (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at  BIGINT NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE TABLE roles (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at  BIGINT NOT NULL,
    updated_at  BIGINT NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE TABLE role_permissions (
    role_id       TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX idx_user_roles_role ON user_roles (role_id);

CREATE TABLE sessions (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    ip             TEXT NOT NULL,
    user_agent     TEXT NOT NULL,
    created_at     BIGINT NOT NULL,
    last_used_at   BIGINT NOT NULL,
    expires_at     BIGINT NOT NULL,
    revoked_at     BIGINT
);
CREATE INDEX idx_sessions_user ON sessions (tenant_id, user_id);
CREATE INDEX idx_sessions_expires ON sessions (expires_at);

CREATE TABLE refresh_tokens (
    id         TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at    BIGINT
);
CREATE INDEX idx_refresh_tokens_session ON refresh_tokens (session_id);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens (expires_at);

CREATE TABLE verification_tokens (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose    TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at    BIGINT
);
CREATE INDEX idx_verification_tokens_expires ON verification_tokens (expires_at);

CREATE TABLE audit_events (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type       TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id   TEXT NOT NULL,
    target_id  TEXT NOT NULL,
    ip         TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    request_id TEXT NOT NULL,
    metadata   TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX idx_audit_tenant_created ON audit_events (tenant_id, created_at);
CREATE INDEX idx_audit_tenant_type ON audit_events (tenant_id, type)
