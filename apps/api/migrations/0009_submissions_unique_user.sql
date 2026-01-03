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

CREATE UNIQUE INDEX IF NOT EXISTS idx_submissions_form_user
ON submissions(form_id, user_id)
WHERE user_id IS NOT NULL;
