PRAGMA foreign_keys=ON;

ALTER TABLE routine_tasks ADD COLUMN last_log_id TEXT;

CREATE TABLE IF NOT EXISTS routine_task_runs (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  run_at TEXT NOT NULL DEFAULT (datetime('now')),
  status TEXT NOT NULL,
  message TEXT
);

INSERT OR IGNORE INTO routine_tasks (id, name, cron, enabled) VALUES
  ('test_notice', 'Test notice task', '0 6 * * *', 0);
