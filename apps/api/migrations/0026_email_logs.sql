PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS email_logs (
  id TEXT PRIMARY KEY,
  to_email TEXT NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL,
  error TEXT,
  submission_id TEXT,
  form_id TEXT,
  form_slug TEXT,
  form_title TEXT,
  canvas_course_id TEXT,
  canvas_section_id TEXT,
  triggered_by TEXT,
  trigger_source TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_email_logs_created_at ON email_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_email_logs_submission_id ON email_logs(submission_id);
CREATE INDEX IF NOT EXISTS idx_email_logs_to_email ON email_logs(to_email);
