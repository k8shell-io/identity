-- Remove blueprint field and restore prov_time to sessions table

ALTER TABLE sessions DROP COLUMN blueprint;
ALTER TABLE sessions ADD COLUMN prov_time FLOAT NOT NULL DEFAULT 0.0;