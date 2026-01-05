PRAGMA foreign_keys=ON;

ALTER TABLE forms ADD COLUMN available_from TEXT;
ALTER TABLE forms ADD COLUMN available_until TEXT;
ALTER TABLE forms ADD COLUMN password_required INTEGER NOT NULL DEFAULT 0;
ALTER TABLE forms ADD COLUMN password_salt TEXT;
ALTER TABLE forms ADD COLUMN password_hash TEXT;
