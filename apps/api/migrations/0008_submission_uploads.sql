PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS submission_uploads (
  id TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL,
  form_id TEXT NOT NULL,
  user_id TEXT NULL,
  field_key TEXT NOT NULL,
  original_name TEXT NOT NULL,
  content_type TEXT NULL,
  size_bytes INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  r2_key TEXT NOT NULL,
  uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
  deleted_at TEXT NULL,
  deleted_by TEXT NULL,
  deleted_reason TEXT NULL,
  FOREIGN KEY(submission_id) REFERENCES submissions(id),
  FOREIGN KEY(form_id) REFERENCES forms(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_uploads_submission_id ON submission_uploads(submission_id);
CREATE INDEX IF NOT EXISTS idx_uploads_form_id ON submission_uploads(form_id);
CREATE INDEX IF NOT EXISTS idx_uploads_user_id ON submission_uploads(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_uploads_submission_field_sha ON submission_uploads(submission_id, field_key, sha256);
