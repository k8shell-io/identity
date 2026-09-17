-- announcements are markdown messages from platform admins to users, given
-- in one or more languages via identity.announcement_translations (there is
-- no title/body here — every announcement is translated, even if only into
-- one language). name is an admin-facing label only — not translated, not
-- shown to end users — so admins can tell announcements apart in a listing.
-- created_by is not FK'd to identity.users (same precedent as
-- onboard_rules.decided_by) so an announcement survives its author's
-- account being deleted. orgs names the organizations this announcement
-- applies to; empty means every organization (global). roles further scopes
-- it to specific roles within those orgs; empty means every role. Neither
-- orgs nor roles is FK'd per element (Postgres arrays don't support that),
-- validated at the application layer instead, same precedent as
-- onboard_rules.roles against identity.roles. active toggles visibility in
-- the user-facing listings without deleting the row. starts_at/ends_at
-- bound an optional validity period; a NULL bound is open on that side.
CREATE TABLE identity.announcements (
    id          SERIAL      PRIMARY KEY,
    name        varchar     NOT NULL,               -- admin-facing label; not translated/user-visible
    created_by  varchar     NOT NULL,               -- author username
    orgs        varchar[]   NOT NULL DEFAULT '{}',  -- empty = every organization (global)
    roles       varchar[]   NOT NULL DEFAULT '{}',  -- empty = every role within orgs
    active      boolean     NOT NULL DEFAULT TRUE,  -- false hides it from user-facing listings
    starts_at   TIMESTAMPTZ,
    ends_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_announcement_period CHECK (starts_at IS NULL OR ends_at IS NULL OR starts_at <= ends_at)
);

CREATE INDEX idx_announcements_orgs  ON identity.announcements USING GIN (orgs);
CREATE INDEX idx_announcements_roles ON identity.announcements USING GIN (roles);

-- announcement_translations holds an announcement's body per language.
-- Every announcement must have at least one translation — Postgres can't
-- express "at least one child row" as a table-level CHECK, so this is
-- enforced at the application layer (CreateAnnouncement rejects an empty
-- translation list, and UpdateAnnouncement never allows the set to be
-- emptied).
CREATE TABLE identity.announcement_translations (
    announcement_id integer     NOT NULL REFERENCES identity.announcements(id) ON DELETE CASCADE,
    lang            varchar(35) NOT NULL,  -- BCP 47 language tag, e.g. 'en', 'en-US'
    body            text        NOT NULL,  -- markdown content

    PRIMARY KEY (announcement_id, lang)
);

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
