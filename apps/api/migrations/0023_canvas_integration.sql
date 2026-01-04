PRAGMA foreign_keys=ON;

ALTER TABLE forms ADD COLUMN canvas_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE forms ADD COLUMN canvas_course_id TEXT;
ALTER TABLE forms ADD COLUMN canvas_allowed_section_ids_json TEXT;
CREATE INDEX IF NOT EXISTS idx_forms_canvas_course_id ON forms(canvas_course_id);

ALTER TABLE submissions ADD COLUMN canvas_enroll_status TEXT;
ALTER TABLE submissions ADD COLUMN canvas_enroll_error TEXT;
ALTER TABLE submissions ADD COLUMN canvas_course_id TEXT;
ALTER TABLE submissions ADD COLUMN canvas_section_id TEXT;
ALTER TABLE submissions ADD COLUMN canvas_enrolled_at TEXT;

CREATE TABLE IF NOT EXISTS canvas_courses_cache (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  code TEXT,
  workflow_state TEXT,
  account_id TEXT,
  term_id TEXT,
  updated_at TEXT NOT NULL,
  raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS canvas_sections_cache (
  id TEXT PRIMARY KEY,
  course_id TEXT NOT NULL,
  name TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  raw_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_canvas_sections_course ON canvas_sections_cache(course_id);
