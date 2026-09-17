-- announcements are markdown messages from platform admins to users.
-- created_by is not FK'd to identity.users (same precedent as
-- onboard_rules.decided_by) so an announcement survives its author's
-- account being deleted. orgs names the organizations this announcement
-- applies to; empty means every organization (global) — not FK'd per
-- element (Postgres arrays don't support that), validated at the
-- application layer instead, same precedent as onboard_rules.roles against
-- identity.roles. starts_at/ends_at bound an optional validity period; a
-- NULL bound is open on that side.
CREATE TABLE identity.announcements (
    id          SERIAL      PRIMARY KEY,
    title       varchar     NOT NULL,
    body        text        NOT NULL,              -- markdown content
    created_by  varchar     NOT NULL,               -- author username
    orgs        varchar[]   NOT NULL DEFAULT '{}',  -- empty = every organization (global)
    starts_at   TIMESTAMPTZ,
    ends_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_announcement_period CHECK (starts_at IS NULL OR ends_at IS NULL OR starts_at <= ends_at)
);

CREATE INDEX idx_announcements_orgs ON identity.announcements USING GIN (orgs);

-- announcement_reads tracks which users have read which announcement, and
-- when — the source of both an announcement's read count and a user's
-- unread listing (an announcement not read once, per this table).
CREATE TABLE identity.announcement_reads (
    announcement_id integer     NOT NULL REFERENCES identity.announcements(id) ON DELETE CASCADE,
    username        varchar     NOT NULL REFERENCES identity.users(username) ON DELETE CASCADE,
    read_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (announcement_id, username)
);

CREATE INDEX idx_announcement_reads_username ON identity.announcement_reads (username);
