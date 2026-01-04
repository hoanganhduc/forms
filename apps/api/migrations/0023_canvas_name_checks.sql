PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS canvas_name_checks (
  user_id TEXT NOT NULL,
  course_id TEXT NOT NULL,
  first_submission_at TEXT NOT NULL,
  last_alert_at TEXT,
  last_checked_at TEXT,
  resolved_at TEXT,
  PRIMARY KEY (user_id, course_id)
);
