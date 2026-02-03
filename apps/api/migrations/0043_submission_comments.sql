CREATE TABLE IF NOT EXISTS submission_comments (
  id TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL,
  author_user_id TEXT NOT NULL,
  author_role TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  deleted_at TEXT,
  deleted_by TEXT,
  deleted_reason TEXT,
  FOREIGN KEY(submission_id) REFERENCES submissions(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS submission_comments_submission_id_idx ON submission_comments(submission_id);
CREATE INDEX IF NOT EXISTS submission_comments_author_user_id_idx ON submission_comments(author_user_id);
