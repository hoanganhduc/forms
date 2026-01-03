PRAGMA foreign_keys=ON;

WITH ranked AS (
  SELECT
    id,
    ROW_NUMBER() OVER (
      PARTITION BY form_id, user_id
      ORDER BY COALESCE(updated_at, created_at) DESC
    ) AS rn
  FROM submissions
  WHERE user_id IS NOT NULL
)
DELETE FROM submissions
WHERE id IN (SELECT id FROM ranked WHERE rn > 1);

CREATE UNIQUE INDEX IF NOT EXISTS idx_submissions_form_user_unique
ON submissions(form_id, user_id)
WHERE user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_submissions_form_id_created_at
ON submissions(form_id, created_at);

CREATE INDEX IF NOT EXISTS idx_submissions_user_id
ON submissions(user_id);
