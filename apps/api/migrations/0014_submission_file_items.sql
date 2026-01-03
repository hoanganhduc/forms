PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS submission_file_items (
  id TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL,
  form_id TEXT NOT NULL,
  form_slug TEXT NOT NULL,
  field_id TEXT NOT NULL,
  original_name TEXT NOT NULL,
  mime_type TEXT,
  size_bytes INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
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
  drive_web_view_link TEXT,
  final_drive_file_id TEXT,
  finalized_at TEXT,
  deleted_at TEXT,
  deleted_by TEXT,
  deleted_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_sfi_submission_id ON submission_file_items(submission_id);
CREATE INDEX IF NOT EXISTS idx_sfi_form_slug ON submission_file_items(form_slug);
CREATE INDEX IF NOT EXISTS idx_sfi_vt_status ON submission_file_items(vt_status);
