PRAGMA foreign_keys=ON;

CREATE INDEX IF NOT EXISTS idx_submissions_user_form
ON submissions(user_id, form_id);
