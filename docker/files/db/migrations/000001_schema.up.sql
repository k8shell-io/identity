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

-- provider_info table to store onboarding user information with OAuth providers
CREATE TABLE provider_info (
    username          VARCHAR NOT NULL,
    provider          VARCHAR NOT NULL,
    status            VARCHAR NOT NULL CHECK (status IN ('ready', 'pending', 'error', 'expired')),
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