PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS canvas_enroll_queue (
  id TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL,
  form_id TEXT NOT NULL,
  course_id TEXT NOT NULL,
  section_id TEXT,
  submitter_name TEXT,
  submitter_email TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  next_run_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS canvas_enroll_deadletters (
  id TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL,
  course_id TEXT NOT NULL,
  section_id TEXT,
  submitter_email TEXT,
  error TEXT,
  attempts INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS health_status_logs (
  id TEXT PRIMARY KEY,
  service TEXT NOT NULL,
  status TEXT NOT NULL,
  message TEXT,
  checked_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_canvas_enroll_queue_next ON canvas_enroll_queue(next_run_at);
CREATE INDEX IF NOT EXISTS idx_health_status_service ON health_status_logs(service, checked_at);
