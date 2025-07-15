-- This SQL script creates the initial schema for the database

-- users table to store user information
CREATE TABLE users (
    username       varchar      not null    primary key,
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

CREATE TABLE sessions (
    session_id serial primary key,
    username   varchar   not null references users,
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