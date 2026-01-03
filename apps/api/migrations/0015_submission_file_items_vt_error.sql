PRAGMA foreign_keys=ON;

ALTER TABLE submission_file_items ADD COLUMN vt_error TEXT;
ALTER TABLE submission_file_items ADD COLUMN drive_web_view_link TEXT;
