PRAGMA foreign_keys=ON;

WITH ranked AS (
  SELECT
    id,
    ROW_NUMBER() OVER (
      PARTITION BY submission_id, field_key, sha256
      ORDER BY uploaded_at DESC
    ) AS rn
  FROM submission_uploads
  WHERE deleted_at IS NULL
)
DELETE FROM submission_uploads
WHERE id IN (SELECT id FROM ranked WHERE rn > 1);

DROP INDEX IF EXISTS idx_uploads_submission_field_sha;
CREATE UNIQUE INDEX IF NOT EXISTS idx_uploads_submission_field_sha
ON submission_uploads(submission_id, field_key, sha256)
WHERE deleted_at IS NULL;
