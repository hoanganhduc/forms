PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS submission_upload_sessions (
  id TEXT PRIMARY KEY,
  form_id TEXT NOT NULL,
  form_slug TEXT NOT NULL,
  field_id TEXT NOT NULL,
  submission_id TEXT NOT NULL,
  user_id TEXT,
  original_name TEXT NOT NULL,
  content_type TEXT,
  size_bytes INTEGER NOT NULL,
  sha256 TEXT,
  r2_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'initialized',
  file_item_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(form_id) REFERENCES forms(id),
  FOREIGN KEY(submission_id) REFERENCES submissions(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_upload_sessions_submission_id ON submission_upload_sessions(submission_id);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_user_id ON submission_upload_sessions(user_id);
