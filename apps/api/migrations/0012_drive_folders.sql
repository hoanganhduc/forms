PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS drive_folders (
  form_slug TEXT PRIMARY KEY,
  drive_folder_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS drive_user_folders (
  form_slug TEXT NOT NULL,
  user_key TEXT NOT NULL,
  drive_user_folder_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY(form_slug, user_key)
);
