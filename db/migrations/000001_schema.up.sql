-- Initial schema for the k8Shell Identity service.

CREATE SCHEMA IF NOT EXISTS identity;

-- organizations groups users into named tenants (e.g. a company or a university).
-- Every user must belong to exactly one organization.
CREATE TABLE identity.organizations (
    name          varchar  not null primary key,  -- short unique identifier
    description   text                            -- human-readable description
);

-- users is the central identity table.
-- A record is created on first login and refreshed from the configured identity
-- provider when the cached record expires (expires_at).
CREATE TABLE identity.users (
    username       varchar      not null primary key,
    organization   varchar      not null references identity.organizations(name),

    -- account state
    is_valid       boolean      not null,        -- false = account disabled
    locked         boolean      not null,        -- true = all logins blocked
    expires_at     TIMESTAMPTZ  not null,        -- re-fetch from provider after this

    -- POSIX identity
    uid            integer      not null unique, -- POSIX UID
    gid            integer      not null,        -- primary POSIX GID

    -- profile
    fullname       varchar,
    email          varchar,
    shell          varchar,                      -- login shell path
    sudo           boolean      not null default false, -- sudo access

    -- authentication
    password       varchar,                      -- hashed; NULL for external auth
    auths          character varying[],          -- allowed auth methods
    auth_keys      character varying[],          -- authorized SSH public keys

    -- provider metadata
    source         varchar,                      -- owning identity provider name
    roles          character varying[],          -- RBAC roles
    blueprints     character varying[],          -- available k8shell blueprints

    -- JWT token refresh coordination
    current_token_id            TEXT,            -- JTI of the last issued JWT
    token_expires_at            TIMESTAMPTZ,     -- expiry of current_token_id
    token_refresh_claimed_until TIMESTAMPTZ      -- refresh lease expiry
);

-- Speeds up the background token-refresh loop (finds near-expiry tokens).
CREATE INDEX idx_users_token_expires_at ON identity.users (token_expires_at)
    WHERE token_expires_at IS NOT NULL;

-- external_credentials stores credentials for external services (e.g. Docker).
-- A user may have multiple credentials, but only one per service URL
CREATE TABLE identity.external_credentials (
    id             SERIAL PRIMARY KEY,
    username       VARCHAR     NOT NULL REFERENCES identity.users(username) ON DELETE CASCADE,
    service_name   VARCHAR     NOT NULL,
    service_url    VARCHAR     NOT NULL,  -- base URL of the external service
    external_id    VARCHAR     NOT NULL,  -- user identifier on the external service
    external_token VARCHAR     NOT NULL,  -- OAuth or API token
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active      BOOLEAN     NOT NULL DEFAULT TRUE,

    UNIQUE(username, service_url)
);

CREATE INDEX idx_external_creds_username ON identity.external_credentials (username);
CREATE INDEX idx_external_creds_service  ON identity.external_credentials (service_name);

-- Seed the built-in organizations.
INSERT INTO identity.organizations (name, description) VALUES
    ('default', 'Default organization');
