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
    blueprints     character varying[]           -- available k8shell blueprints
);

-- user_credentials stores credentials for external services.
-- credential_source controls how the secret is resolved at request time
-- values are: stored, kubernetes, or a named identity provider for dynamic git credentials.
CREATE TABLE identity.user_credentials (
    id                SERIAL PRIMARY KEY,
    username          VARCHAR     NOT NULL REFERENCES identity.users(username) ON DELETE CASCADE,

    -- service identification
    service_name      VARCHAR     NOT NULL,  -- one of: 'registry', 'git', 'kubernetes'
    service_scope     VARCHAR     NOT NULL,  -- registry/git URL (static); namespace (k8s); provider URL (git dynamic)

    -- credential subject identifies the principal for which the credential is valid 
    subject           VARCHAR     NOT NULL,  -- login name (static) or service account name (k8s)

    -- how to resolve the secret at request time
    credential_source VARCHAR     NOT NULL DEFAULT 'stored',
                                            -- 'stored' | 'kubernetes' | <idp-name>

    -- stored secret — NULL for dynamic credentials
    secret            VARCHAR,               -- OAuth token, API key, password; NULL = dynamic

    -- lifecycle
    is_active         BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- a user may have at most one credential per (service, scope, identity) tuple
    UNIQUE (username, service_name, service_scope, subject),

    -- only known service types are accepted
    CONSTRAINT chk_service_name
        CHECK (service_name IN ('registry', 'git', 'kubernetes')),

    -- secret must be present for stored credentials and absent for dynamic ones
    CONSTRAINT chk_credential_source_secret
        CHECK (
            (credential_source = 'stored'  AND secret IS NOT NULL)
            OR
            (credential_source != 'stored' AND secret IS NULL)
        ),

    -- kubernetes rows must always be dynamic via TokenRequest
    CONSTRAINT chk_kubernetes_credential_source
        CHECK (service_name != 'kubernetes' OR credential_source = 'kubernetes'),

    -- registry rows must always be static
    CONSTRAINT chk_registry_credential_source
        CHECK (service_name != 'registry' OR credential_source = 'stored')
);

CREATE INDEX idx_user_creds_username ON identity.user_credentials (username);
CREATE INDEX idx_user_creds_service  ON identity.user_credentials (service_name);

-- Seed the built-in organizations.
INSERT INTO identity.organizations (name, description) VALUES
    ('default', 'Default organization');

