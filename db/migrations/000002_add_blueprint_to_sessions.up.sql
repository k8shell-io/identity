-- Add blueprint field and remove prov_time from sessions table

ALTER TABLE sessions ADD COLUMN blueprint VARCHAR;
ALTER TABLE sessions DROP COLUMN prov_time;