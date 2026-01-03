PRAGMA foreign_keys=ON;

ALTER TABLE templates ADD COLUMN file_rules_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE forms ADD COLUMN file_rules_json TEXT NULL;

CREATE TABLE IF NOT EXISTS submission_files (
  id TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL,
  field_key TEXT NOT NULL,
  original_name TEXT NOT NULL,
  content_type TEXT,
  size INTEGER,
  sha256 TEXT,
  r2_key TEXT NOT NULL,
  uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
  vt_analysis_id TEXT,
  vt_status TEXT,
  vt_verdict TEXT,
  vt_malicious INTEGER,
  vt_suspicious INTEGER,
  vt_undetected INTEGER,
  vt_timeout INTEGER,
  vt_last_checked_at TEXT,
  final_drive_file_id TEXT,
  finalized_at TEXT,
  deleted_at TEXT,
  deleted_by TEXT,
  FOREIGN KEY(submission_id) REFERENCES submissions(id)
);

CREATE INDEX IF NOT EXISTS idx_submission_files_submission_id ON submission_files(submission_id);
CREATE INDEX IF NOT EXISTS idx_submission_files_vt_status ON submission_files(vt_status);
CREATE INDEX IF NOT EXISTS idx_submission_files_finalized_at ON submission_files(finalized_at);
