PRAGMA foreign_keys=ON;

ALTER TABLE submissions ADD COLUMN created_ip TEXT;
ALTER TABLE submissions ADD COLUMN created_user_agent TEXT;
ALTER TABLE submissions ADD COLUMN submitter_provider TEXT;
ALTER TABLE submissions ADD COLUMN submitter_email TEXT;
ALTER TABLE submissions ADD COLUMN submitter_github_username TEXT;
