PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS templates (
  id TEXT PRIMARY KEY,
  key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  schema_json TEXT NOT NULL,
  is_public INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT,
  deleted_at TEXT,
  deleted_by TEXT,
  deleted_reason TEXT
);

CREATE TABLE IF NOT EXISTS forms (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  description TEXT,
  template_id TEXT,
  is_public INTEGER NOT NULL DEFAULT 1,
  is_locked INTEGER NOT NULL DEFAULT 0,
  locked_at TEXT,
  locked_reason TEXT,
  locked_by TEXT,
  auth_policy TEXT NOT NULL DEFAULT 'optional',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_by TEXT,
  updated_at TEXT,
  updated_by TEXT,
  deleted_at TEXT,
  deleted_by TEXT,
  deleted_reason TEXT,
  FOREIGN KEY(template_id) REFERENCES templates(id)
);

CREATE TABLE IF NOT EXISTS form_versions (
  id TEXT PRIMARY KEY,
  form_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  schema_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_by TEXT,
  UNIQUE(form_id, version),
  FOREIGN KEY(form_id) REFERENCES forms(id)
);

CREATE INDEX IF NOT EXISTS idx_forms_is_public ON forms(is_public);
CREATE INDEX IF NOT EXISTS idx_forms_slug ON forms(slug);
CREATE INDEX IF NOT EXISTS idx_templates_key ON templates(key);
CREATE INDEX IF NOT EXISTS idx_forms_deleted_at ON forms(deleted_at);

INSERT OR IGNORE INTO templates (id, key, name, schema_json, is_public)
VALUES (
  'tpl_hus_vi_1',
  'hus_vi_1',
  'HUS VI Basic',
  '{"fields":[{"id":"first_name","type":"text","label":"First name","required":true},{"id":"email","type":"email","label":"Email","required":true}]}',
  1
);

INSERT OR IGNORE INTO forms (id, slug, title, description, template_id, is_public, is_locked, auth_policy)
VALUES (
  'form_hus_demo_1',
  'hus-demo-1',
  'HUS Demo 1',
  'Demo form seeded from migration.',
  'tpl_hus_vi_1',
  1,
  0,
  'optional'
);

INSERT OR IGNORE INTO form_versions (id, form_id, version, schema_json)
VALUES (
  'fv_form_hus_demo_1_v1',
  'form_hus_demo_1',
  1,
  '{"fields":[{"id":"first_name","type":"text","label":"First name","required":true},{"id":"email","type":"email","label":"Email","required":true}]}'
);
