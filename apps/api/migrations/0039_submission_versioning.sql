PRAGMA foreign_keys=ON;

-- Add save_all_versions field to forms table
ALTER TABLE forms ADD COLUMN save_all_versions INTEGER NOT NULL DEFAULT 0;

-- Create submission_versions table for storing historical versions
CREATE TABLE IF NOT EXISTS submission_versions (
  id TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL,
  form_id TEXT NOT NULL,
  user_id TEXT,
  payload_json TEXT NOT NULL,
  version_number INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_by TEXT,
  FOREIGN KEY(submission_id) REFERENCES submissions(id),
  FOREIGN KEY(form_id) REFERENCES forms(id),
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(created_by) REFERENCES users(id)
);

-- Indexes for efficient version queries
CREATE INDEX IF NOT EXISTS idx_submission_versions_submission_id ON submission_versions(submission_id);
CREATE INDEX IF NOT EXISTS idx_submission_versions_form_id ON submission_versions(form_id);
CREATE INDEX IF NOT EXISTS idx_submission_versions_created_at ON submission_versions(created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_submission_versions_unique ON submission_versions(submission_id, version_number);
