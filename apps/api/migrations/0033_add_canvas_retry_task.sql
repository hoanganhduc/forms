PRAGMA foreign_keys=ON;

INSERT OR IGNORE INTO routine_tasks (id, name, cron, enabled) VALUES
  ('canvas_retry_queue', 'Canvas retry queue processor', '*/15 * * * *', 1);
