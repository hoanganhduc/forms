PRAGMA foreign_keys=ON;

ALTER TABLE email_logs ADD COLUMN deleted_at TEXT;
ALTER TABLE email_logs ADD COLUMN deleted_by TEXT;
ALTER TABLE email_logs ADD COLUMN deleted_reason TEXT;
