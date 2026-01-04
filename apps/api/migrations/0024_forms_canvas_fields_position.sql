PRAGMA foreign_keys=ON;

ALTER TABLE forms
ADD COLUMN canvas_fields_position TEXT NOT NULL DEFAULT 'bottom';
