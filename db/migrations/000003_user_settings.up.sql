-- user_settings stores one row per user: an opaque settings blob Identity
-- never parses (data), plus the subset of settings Identity itself
-- validates and enforces (session_idle_timeout_seconds today; more
-- controlled columns are added here as they're introduced in
-- ControlledSettings). PutUserSettings is a plain UPSERT — last-write-wins,
-- no optimistic-concurrency check — version is an informational counter
-- incremented on every write, not compared against the caller's value.
-- octet_length(data) mirrors the ~64KB cap re-enforced at the application
-- layer in internal/server/user_settings.go, since other internal callers
-- could bypass api-server's own cap.
CREATE TABLE identity.user_settings (
    username                      varchar     NOT NULL PRIMARY KEY REFERENCES identity.users(username) ON DELETE CASCADE,
    version                       integer     NOT NULL DEFAULT 1,
    data                          bytea       NOT NULL DEFAULT '',
    session_idle_timeout_seconds  integer,             -- NULL = unset, use the platform default
    updated_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_user_settings_data_size CHECK (octet_length(data) <= 65536)
);
