PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS routine_tasks (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  cron TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_run_at TEXT,
  last_status TEXT,
  last_error TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO routine_tasks (id, name, cron, enabled) VALUES
  ('canvas_sync', 'Canvas course/section sync', '0 2 * * *', 1),
  ('canvas_name_mismatch', 'Canvas name mismatch checker', '0 3 * * *', 1),
  ('backup_forms_templates', 'Backup forms + templates', '0 4 * * 0', 0),
  ('empty_trash', 'Empty trash', '0 5 * * 0', 0);
