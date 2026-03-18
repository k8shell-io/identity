-- Add JWT token storage and distributed refresh coordination columns to users

ALTER TABLE users ADD COLUMN jwt_token TEXT;
ALTER TABLE users ADD COLUMN token_expires_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN token_refresh_claimed_until TIMESTAMPTZ;

-- Index to efficiently query users whose tokens are expiring soon.
CREATE INDEX idx_users_token_expires_at ON users (token_expires_at)
    WHERE token_expires_at IS NOT NULL;
