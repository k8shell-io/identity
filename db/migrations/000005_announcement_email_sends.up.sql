-- announcement_email_sends tracks which users have already been sent a
-- given announcement's email — the source of truth that guarantees an
-- announcement is emailed to a user at most once, mirroring
-- announcement_reads' shape. A row is inserted as a claim right before the
-- send attempt (see Server.sendAnnouncementEmailToCandidate) and left in
-- place on success; on a send failure the claim is deleted so a later tick
-- retries. Relying on this table's PRIMARY KEY for the insert's
-- ON CONFLICT DO NOTHING is what makes the claim safe under concurrent
-- ticks/replicas without any extra locking.
CREATE TABLE identity.announcement_email_sends (
    announcement_id integer     NOT NULL REFERENCES identity.announcements(id) ON DELETE CASCADE,
    username        varchar     NOT NULL REFERENCES identity.users(username) ON DELETE CASCADE,
    sent_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (announcement_id, username)
);

CREATE INDEX idx_announcement_email_sends_username ON identity.announcement_email_sends (username);
