PRAGMA foreign_keys=ON;

DROP TABLE IF EXISTS submission_uploads_vt;

CREATE TABLE submission_uploads_vt (
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
  vt_analysis_id TEXT NULL,
  vt_status TEXT NULL,
  vt_verdict TEXT NULL,
  vt_malicious INTEGER NULL,
  vt_suspicious INTEGER NULL,
  vt_undetected INTEGER NULL,
  vt_timeout INTEGER NULL,
  vt_last_checked_at TEXT NULL,
  vt_error TEXT NULL,
  FOREIGN KEY(submission_id) REFERENCES submissions(id),
  FOREIGN KEY(form_id) REFERENCES forms(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

INSERT INTO submission_uploads_vt (
  id,
  submission_id,
  form_id,
  user_id,
  field_key,
  original_name,
  content_type,
  size_bytes,
  sha256,
  r2_key,
  uploaded_at,
  deleted_at,
  deleted_by,
  deleted_reason
)
SELECT
  id,
  submission_id,
  form_id,
  user_id,
  field_key,
  original_name,
  content_type,
  size_bytes,
  sha256,
  r2_key,
  uploaded_at,
  deleted_at,
  deleted_by,
  deleted_reason
FROM submission_uploads;

DROP TABLE submission_uploads;
ALTER TABLE submission_uploads_vt RENAME TO submission_uploads;

CREATE INDEX IF NOT EXISTS idx_uploads_submission_id ON submission_uploads(submission_id);
CREATE INDEX IF NOT EXISTS idx_uploads_form_id ON submission_uploads(form_id);
CREATE INDEX IF NOT EXISTS idx_uploads_user_id ON submission_uploads(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_uploads_submission_field_sha ON submission_uploads(submission_id, field_key, sha256);
