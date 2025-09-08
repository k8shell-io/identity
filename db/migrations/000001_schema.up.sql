-- This SQL script creates the initial schema for the database

-- organizations table to store organization information
CREATE TABLE organizations (
    name          varchar      not null primary key,
    description   text
);

-- users table to store user information
CREATE TABLE users (
    username       varchar      not null    primary key,
    organization   varchar      not null    references organizations(name),
    is_valid       boolean      not null,
    expires_at     TIMESTAMPTZ  not null,
    uid            integer      not null    unique,
    gid            integer      not null,
    fullname       varchar,
    access_token   varchar,
    email          varchar,
    password       varchar,
    auths          character    varying[],
    auth_keys      character    varying[],
    locked         boolean      not null,
    failed_logins  integer      not null,
    channels       character    varying[],
    envs           character    varying[],
    roles          character    varying[],
    blueprints     character    varying[],
    source         varchar
);

CREATE INDEX idx_users_access_token ON users (access_token);

-- external_credentials table to store external service credentials for users
CREATE TABLE external_credentials (
    id             SERIAL PRIMARY KEY,
    username       VARCHAR NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    service_name   VARCHAR NOT NULL CHECK (service_name IN ('registry', 'github', 'gitlab', 'bitbucket')),
    service_url    VARCHAR NOT NULL,
    external_id    VARCHAR NOT NULL,
    external_token VARCHAR NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active      BOOLEAN NOT NULL DEFAULT TRUE,

    UNIQUE(username, service_url)
);

-- Create indexes separately
CREATE INDEX idx_external_creds_username ON external_credentials (username);
CREATE INDEX idx_external_creds_service ON external_credentials (service_name);

CREATE TABLE sessions (
    session_id serial primary key,
    username   varchar   not null references users(username), 
    proxy_id   varchar,
    proxy_pid  integer,
    client     varchar,
    client_ip  varchar,
    start_time timestamp not null,
    end_time   timestamp,
    workspace  varchar   not null,
    bytes_in   bigint   not null,
    bytes_out  bigint   not null,
    channels   character varying[],
    prov_time  float not null default 0.0,
    unique (username, start_time, workspace)
);

CREATE INDEX ix_sessions_workspace
    on sessions (workspace);

-- provider_info table to store onboarding user information with OAuth providers
CREATE TABLE provider_info (
    username          VARCHAR NOT NULL,
    provider          VARCHAR NOT NULL,
    status            VARCHAR NOT NULL CHECK (status IN ('ready', 'pending', 'error', 'expired', 'invalid')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_code         VARCHAR NOT NULL,
    device_code       VARCHAR NOT NULL,
    expires_at        TIMESTAMPTZ,
    verification_uri  TEXT NOT NULL,
    access_token      TEXT NOT NULL,
    refresh_token     TEXT NOT NULL,
    
    PRIMARY KEY (username, provider)
);

INSERT INTO organizations (name, description) VALUES
    ('default', 'Default organization'),
    ('ctu', 'Users onboarded via Usermap'),
    ('github', 'Users onboarded via GitHub');