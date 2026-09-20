-- mail_sends is an append-only log of every outbound email identity has
-- actually sent (password-reset and announcement), written only on a
-- successful send — a failed send never reached the relay's quota, so it's
-- never logged here. Its sole purpose is rolling-24h recipient-rate
-- accounting (see Server.remainingMailBudget /
-- MailRateLimitConfig.DailyRecipientCap), e.g. to stay under a personal
-- Gmail account's undocumented ~500-recipients/24h send cap when SMTP is
-- pointed at one. Not a delivery audit log — no retention/cleanup job
-- exists yet; rows accumulate indefinitely, which is fine at expected
-- volumes but worth revisiting if that changes.
CREATE TABLE identity.mail_sends (
    id        SERIAL      PRIMARY KEY,
    kind      varchar     NOT NULL,  -- 'announcement' | 'password_reset'
    recipient varchar     NOT NULL,
    sent_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mail_sends_sent_at ON identity.mail_sends (sent_at);
