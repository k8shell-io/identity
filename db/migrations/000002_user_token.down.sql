DROP INDEX IF EXISTS idx_users_token_expires_at;
ALTER TABLE users DROP COLUMN IF EXISTS token_refresh_claimed_until;
ALTER TABLE users DROP COLUMN IF EXISTS token_expires_at;
ALTER TABLE users DROP COLUMN IF EXISTS current_token_id;
