-- Initial schema for the k8Shell Identity service.

CREATE SCHEMA IF NOT EXISTS identity;

-- organizations groups users into named tenants (e.g. a company or a university).
-- Every user must belong to exactly one organization.
CREATE TABLE identity.organizations (
    name          varchar  not null primary key,  -- short unique identifier
    description   text,                           -- human-readable description
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Role registry for the k8Shell Identity service.
--
-- Roles are flat, opaque name strings assignable to identity.users.roles.
-- This table answers only whether a role exists; any meaning encoded in its
-- name (e.g. the "<group>-admin" convention) is interpreted at the policy
-- layer, not here.
--
-- A role name is scoped to its organization: the same name may be defined
-- independently by different organizations (idx_roles_org_name enforces
-- uniqueness per org). org IS NULL means the role is global, assignable
-- regardless of a user's organization; idx_roles_global_name_uniq keeps
-- global role names unique on their own, since a plain UNIQUE(org, name)
-- index does not treat two NULLs as equal.
CREATE TABLE identity.roles (
    name        varchar     not null,
    description text,
    org         varchar references identity.organizations(name), -- NULL = global
    created_at  TIMESTAMPTZ not null default now()
);

CREATE UNIQUE INDEX idx_roles_org_name ON identity.roles (org, name);
CREATE UNIQUE INDEX idx_roles_global_name_uniq ON identity.roles (name) WHERE org IS NULL;

-- Seed baseline roles outside the CreateRole RPC path, since role creation
-- will eventually require an authz decision based on the caller's roles,
-- which is circular for the very first org-admin.
INSERT INTO identity.roles (name, description) VALUES
    ('admin', 'Full administrative access globally'),
    ('org-admin', 'Full administrative access within an organization');

-- role_blueprints maps a role to the blueprints it grants. A user's
-- effective blueprint set (see FindUser/ListUsers in internal/db/user.go) is
-- the union of blueprints across every role in identity.users.roles,
-- resolved org-scoped-or-global the same way identity.roles itself is
-- (an org-scoped entry for the user's own organization, plus any global
-- entries). No FK to identity.roles(name, org): identity.users.roles already
-- stores plain role names with no org qualifier and no FK (see DeleteRole's
-- in-use check), so role_blueprints follows the same precedent and is kept
-- in sync at the application layer instead — DeleteRole removes a role's
-- role_blueprints rows in the same transaction it deletes the role.
CREATE TABLE identity.role_blueprints (
    id          SERIAL      PRIMARY KEY,
    role        varchar     not null,
    org         varchar references identity.organizations(name), -- NULL = global role
    blueprint   varchar     not null,
    created_at  TIMESTAMPTZ not null default now()
);

-- Same dual-index pattern as idx_roles_org_name/idx_roles_global_name_uniq
-- above: a plain UNIQUE(role, org, blueprint) index doesn't dedupe NULL-org
-- rows against each other, so a separate partial index enforces uniqueness
-- for global (org IS NULL) entries.
CREATE UNIQUE INDEX idx_role_blueprints_org_uniq ON identity.role_blueprints (role, org, blueprint);
CREATE UNIQUE INDEX idx_role_blueprints_global_uniq ON identity.role_blueprints (role, blueprint) WHERE org IS NULL;
CREATE INDEX idx_role_blueprints_role ON identity.role_blueprints (role);

-- Seed full ("*") blueprint access for the baseline roles above.
INSERT INTO identity.role_blueprints (role, org, blueprint) VALUES
    ('admin', NULL, '*'),
    ('org-admin', NULL, '*');

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
    fullname         varchar,
    email            varchar,
    shell            varchar,                 -- login shell path
    sudo             boolean not null default false, -- sudo access
    manage_repos     varchar,                 -- optional repo management link 
    git_address      varchar,                 -- optional git address for git operations

    -- authentication
    password       varchar,                      -- hashed; NULL for external auth
    auth_keys      character varying[],          -- authorized SSH public keys

    -- provider metadata
    source         varchar,                      -- owning identity provider name
    roles          character varying[]           -- RBAC roles
);

-- Emails must be unique across users when present. Partial index so that
-- users without an email (NULL or '') never collide with one another.
CREATE UNIQUE INDEX idx_users_email_unique ON identity.users (email)
    WHERE email IS NOT NULL AND email <> '';

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
    last_used_at      TIMESTAMPTZ,            -- set when the credential's secret is resolved for use

    -- a user may have at most one credential per (service, scope) pair, regardless of subject
    CONSTRAINT user_credentials_uniq_key UNIQUE (username, service_name, service_scope),

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

-- access_tokens stores Personal Access Tokens (PATs) for users.
-- The raw token is never stored; only sha256(token) in hex is kept.
-- Scopes cap the token to a subset of the owning user's policy permissions.
CREATE TABLE identity.access_tokens (
    id            BIGSERIAL   PRIMARY KEY,
    token_hash    TEXT        NOT NULL UNIQUE,  -- hex(sha256(raw_token))
    username      VARCHAR     NOT NULL REFERENCES identity.users(username) ON DELETE CASCADE,
    name          TEXT        NOT NULL,          -- human label, e.g. "k8shell-cli laptop"
    scopes        TEXT[]      NOT NULL,          -- allowed action scopes
    expires_at    TIMESTAMPTZ,                   -- NULL = never expires
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at  TIMESTAMPTZ,
    is_active     BOOLEAN     NOT NULL DEFAULT TRUE,
    token_preview VARCHAR(15)                     -- first chars of raw_token, for display only
);

CREATE INDEX idx_access_tokens_username ON identity.access_tokens (username);

-- Seed the built-in organizations.
INSERT INTO identity.organizations (name, description) VALUES
    ('default', 'Default organization');

-- Only one access token may ever exist per (username, name) pair, regardless of
-- active state. This makes "renew" (rotate the existing token in place) well-defined:
-- there is at most one token to renew for a given name. A revoked token's name
-- is reactivated (not duplicated) by renewing it.
CREATE UNIQUE INDEX idx_access_tokens_username_name
    ON identity.access_tokens (username, name);

-- onboard_rules controls whether a new user may onboard, and what they get
-- when they do. A row is either:
--   - a pattern rule (username_pattern contains '*'), admin-authored, e.g.
--     idp='github', username_pattern='*', action='waitlist' as that idp's
--     catch-all/default; or
--   - a concrete decision (username_pattern has no '*'), either
--     admin-authored (a one-off allow/reject for a specific person) or
--     system-inserted the first time that exact user hits a 'waitlist'
--     pattern rule.
--
-- org is the destination org a matching user is placed into (NOT a scope
-- filter like identity.roles.org) — it always names exactly one
-- organization, replacing whatever the identity provider itself reported.
-- roles/sudo are the attributes applied to the user when a row resolves to
-- 'allow'
CREATE TABLE identity.onboard_rules (
    id                SERIAL PRIMARY KEY,
    idp               varchar     not null,  -- provider name, 'local', or '*' (any)
    username_pattern  varchar     not null,  -- exact username, or a pattern containing '*'
    org               varchar     not null references identity.organizations(name),
    action            varchar     not null,  -- 'allow' | 'reject' | 'waitlist'
    priority          integer     not null default 100, -- lower wins among matching rows of the same specificity

    -- status tracks the outcome of an actual onboarding attempt against this
    -- row, separate from action (the configured policy/decision): 'none'
    -- (no attempt yet — the default for admin-authored rules), 'pending'
    -- (a user hit this as a 'waitlist' decision, no admin decision yet),
    -- 'rejected' (a user was rejected, either directly by an action='reject'
    -- rule or by an admin rejecting a waitlisted request), 'onboarded' (the
    -- user was actually created in identity.users). Set by the application
    -- layer as onboarding attempts resolve, not admin-editable directly.
    status            varchar     not null default 'none',

    -- attributes applied to the user when this row resolves to 'allow'.
    -- roles must be valid within org (org-scoped-or-global, same
    -- resolution as ListRoles(org)) — enforced at the application layer by
    -- CreateOnboardRule/UpdateOnboardRule, same precedent as
    -- identity.role_blueprints having no FK to identity.roles.
    roles             varchar[]   not null default '{}',
    sudo              boolean     not null default false,

    -- display metadata for system-inserted (waitlist-hit) rows, so an admin
    -- can see who's asking without a fresh provider round-trip
    fullname          varchar,
    email             varchar,

    note              text,                  -- admin comment / rejection reason
    requested_at      TIMESTAMPTZ,           -- set only for system-inserted rows
    decided_at        TIMESTAMPTZ,           -- set when action moves out of 'waitlist'
    decided_by        varchar,               -- admin username who approved/rejected

    created_at        TIMESTAMPTZ not null default now(),
    updated_at        TIMESTAMPTZ not null default now(),

    CONSTRAINT chk_onboard_rule_action CHECK (action IN ('allow', 'reject', 'waitlist')),
    CONSTRAINT chk_onboard_rule_status CHECK (status IN ('none', 'pending', 'approved', 'rejected', 'onboarded')),
    -- org is part of the key so the same idp can define independent rules
    -- (including separate wildcard '*' catch-alls) per destination org.
    CONSTRAINT onboard_rules_uniq UNIQUE (idp, username_pattern, org)
);

-- Speeds up both ResolveOnboardDecision's per-idp candidate fetch and
-- listing the waitlist (action = 'waitlist') for the admin approval queue.
CREATE INDEX idx_onboard_rules_idp_action ON identity.onboard_rules (idp, action);

-- organization_env_vars stores environment variables shared by every user in
-- an organization. keys are normalized to upper case by the application
-- layer before being stored or queried (see chk_org_env_var_key), so lookups
-- are effectively case-insensitive.
CREATE TABLE identity.organization_env_vars (
    id          SERIAL      PRIMARY KEY,
    org         varchar     NOT NULL REFERENCES identity.organizations(name) ON DELETE CASCADE,
    key         varchar     NOT NULL,
    value       text        NOT NULL,
    is_secret   boolean     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT organization_env_vars_uniq UNIQUE (org, key),

    -- valid POSIX environment variable name, already upper-cased
    CONSTRAINT chk_org_env_var_key CHECK (key ~ '^[A-Z_][A-Z0-9_]*$')
);

-- user_env_vars stores environment variables owned by a single user. A key
-- present here overrides the same key defined on the user's organization
-- (see identity.organization_env_vars) — the effective value for a user is
-- resolved at the application layer, not via a view or join here.
CREATE TABLE identity.user_env_vars (
    id          SERIAL      PRIMARY KEY,
    username    varchar     NOT NULL REFERENCES identity.users(username) ON DELETE CASCADE,
    key         varchar     NOT NULL,
    value       text        NOT NULL,
    is_secret   boolean     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT user_env_vars_uniq UNIQUE (username, key),

    -- valid POSIX environment variable name, already upper-cased
    CONSTRAINT chk_user_env_var_key CHECK (key ~ '^[A-Z_][A-Z0-9_]*$')
);
