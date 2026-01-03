PRAGMA foreign_keys=ON;

ALTER TABLE submissions ADD COLUMN deleted_at TEXT;
ALTER TABLE submissions ADD COLUMN deleted_by TEXT;
ALTER TABLE submissions ADD COLUMN deleted_reason TEXT;

ALTER TABLE users ADD COLUMN deleted_by TEXT;
ALTER TABLE users ADD COLUMN deleted_reason TEXT;

ALTER TABLE templates ADD COLUMN created_by TEXT;

CREATE INDEX IF NOT EXISTS idx_submissions_deleted_at ON submissions(deleted_at);
