-- email_enabled marks an announcement as eligible to be sent by email, in
-- addition to a user's own announcementsByEmail opt-in (an opaque key inside
-- identity.user_settings.data) -- an announcement is only emailed to a user
-- when both are true. No sender exists yet; this only records the flag.
ALTER TABLE identity.announcements ADD COLUMN email_enabled boolean NOT NULL DEFAULT FALSE;
