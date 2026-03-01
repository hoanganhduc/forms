PRAGMA foreign_keys=ON;

ALTER TABLE forms ADD COLUMN resubmission_period_days INTEGER DEFAULT 14;
ALTER TABLE forms ADD COLUMN reminder_repeat_days INTEGER DEFAULT 2;

UPDATE forms
SET
  resubmission_period_days = CASE
    WHEN reminder_frequency IS NULL OR trim(reminder_frequency) = '' THEN COALESCE(resubmission_period_days, 14)
    WHEN lower(trim(reminder_frequency)) = 'daily' THEN 1
    WHEN lower(trim(reminder_frequency)) = 'weekly' THEN 7
    WHEN lower(trim(reminder_frequency)) = 'monthly' THEN 30
    WHEN lower(trim(reminder_frequency)) LIKE '%:days' THEN CAST(substr(lower(trim(reminder_frequency)), 1, instr(lower(trim(reminder_frequency)), ':') - 1) AS INTEGER)
    WHEN lower(trim(reminder_frequency)) LIKE '%:weeks' THEN CAST(substr(lower(trim(reminder_frequency)), 1, instr(lower(trim(reminder_frequency)), ':') - 1) AS INTEGER) * 7
    WHEN lower(trim(reminder_frequency)) LIKE '%:months' THEN CAST(substr(lower(trim(reminder_frequency)), 1, instr(lower(trim(reminder_frequency)), ':') - 1) AS INTEGER) * 30
    ELSE COALESCE(resubmission_period_days, 14)
  END,
  reminder_repeat_days = COALESCE(reminder_repeat_days, 2);

CREATE TABLE IF NOT EXISTS form_reminder_recipients (
  form_id TEXT NOT NULL,
  recipient_key TEXT NOT NULL,
  user_id TEXT,
  email TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  latest_submission_at TEXT,
  last_submission_id TEXT,
  first_due_at TEXT,
  next_reminder_at TEXT,
  last_reminder_sent_at TEXT,
  last_reminder_status TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (form_id, recipient_key)
);

CREATE INDEX IF NOT EXISTS idx_form_reminder_recipients_due
  ON form_reminder_recipients(next_reminder_at, enabled);
CREATE INDEX IF NOT EXISTS idx_form_reminder_recipients_form
  ON form_reminder_recipients(form_id, enabled);
CREATE INDEX IF NOT EXISTS idx_form_reminder_recipients_user
  ON form_reminder_recipients(user_id);

WITH submission_recipients AS (
  SELECT
    f.id AS form_id,
    s.id AS submission_id,
    s.user_id AS user_id,
    lower(
      trim(
        COALESCE(
          s.submitter_email,
          (
            SELECT ui.email
            FROM user_identities ui
            WHERE ui.user_id = s.user_id
              AND ui.email IS NOT NULL
            ORDER BY CASE ui.provider WHEN 'google' THEN 0 ELSE 1 END, ui.created_at ASC
            LIMIT 1
          )
        )
      )
    ) AS email,
    CASE
      WHEN COALESCE(
        s.submitter_email,
        (
          SELECT ui.email
          FROM user_identities ui
          WHERE ui.user_id = s.user_id
            AND ui.email IS NOT NULL
          ORDER BY CASE ui.provider WHEN 'google' THEN 0 ELSE 1 END, ui.created_at ASC
          LIMIT 1
        )
      ) IS NOT NULL THEN 'email:' || lower(
        trim(
          COALESCE(
            s.submitter_email,
            (
              SELECT ui.email
              FROM user_identities ui
              WHERE ui.user_id = s.user_id
                AND ui.email IS NOT NULL
              ORDER BY CASE ui.provider WHEN 'google' THEN 0 ELSE 1 END, ui.created_at ASC
              LIMIT 1
            )
          )
        )
      )
      WHEN s.user_id IS NOT NULL THEN 'user:' || s.user_id
      ELSE NULL
    END AS recipient_key,
    COALESCE(s.updated_at, s.created_at) AS activity_at
  FROM forms f
  JOIN submissions s ON s.form_id = f.id
  WHERE f.deleted_at IS NULL
    AND s.deleted_at IS NULL
),
latest_recipients AS (
  SELECT
    sr.form_id,
    sr.recipient_key,
    MAX(sr.activity_at) AS latest_submission_at
  FROM submission_recipients sr
  WHERE sr.recipient_key IS NOT NULL
  GROUP BY sr.form_id, sr.recipient_key
),
recipient_details AS (
  SELECT
    lr.form_id,
    lr.recipient_key,
    (
      SELECT sr.user_id
      FROM submission_recipients sr
      WHERE sr.form_id = lr.form_id
        AND sr.recipient_key = lr.recipient_key
      ORDER BY datetime(sr.activity_at) DESC, sr.submission_id DESC
      LIMIT 1
    ) AS user_id,
    (
      SELECT sr.email
      FROM submission_recipients sr
      WHERE sr.form_id = lr.form_id
        AND sr.recipient_key = lr.recipient_key
      ORDER BY datetime(sr.activity_at) DESC, sr.submission_id DESC
      LIMIT 1
    ) AS email,
    (
      SELECT sr.submission_id
      FROM submission_recipients sr
      WHERE sr.form_id = lr.form_id
        AND sr.recipient_key = lr.recipient_key
      ORDER BY datetime(sr.activity_at) DESC, sr.submission_id DESC
      LIMIT 1
    ) AS last_submission_id,
    lr.latest_submission_at
  FROM latest_recipients lr
),
recipient_logs AS (
  SELECT
    rd.form_id,
    rd.recipient_key,
    rd.user_id,
    rd.email,
    rd.last_submission_id,
    rd.latest_submission_at,
    (
      SELECT MAX(e.created_at)
      FROM email_logs e
      WHERE e.form_id = rd.form_id
        AND e.trigger_source = 'periodic_reminder'
        AND e.deleted_at IS NULL
        AND lower(trim(e.to_email)) = rd.email
    ) AS last_reminder_sent_at,
    (
      SELECT e.status
      FROM email_logs e
      WHERE e.form_id = rd.form_id
        AND e.trigger_source = 'periodic_reminder'
        AND e.deleted_at IS NULL
        AND lower(trim(e.to_email)) = rd.email
      ORDER BY datetime(e.created_at) DESC
      LIMIT 1
    ) AS last_reminder_status
  FROM recipient_details rd
)
INSERT OR REPLACE INTO form_reminder_recipients (
  form_id,
  recipient_key,
  user_id,
  email,
  enabled,
  latest_submission_at,
  last_submission_id,
  first_due_at,
  next_reminder_at,
  last_reminder_sent_at,
  last_reminder_status,
  created_at,
  updated_at
)
SELECT
  rl.form_id,
  rl.recipient_key,
  rl.user_id,
  rl.email,
  1,
  rl.latest_submission_at,
  rl.last_submission_id,
  datetime(rl.latest_submission_at, '+' || COALESCE(f.resubmission_period_days, 14) || ' days'),
  CASE
    WHEN rl.last_reminder_sent_at IS NOT NULL
      AND datetime(rl.last_reminder_sent_at) >= datetime(rl.latest_submission_at, '+' || COALESCE(f.resubmission_period_days, 14) || ' days')
      THEN datetime(rl.last_reminder_sent_at, '+' || COALESCE(f.reminder_repeat_days, 2) || ' days')
    ELSE datetime(rl.latest_submission_at, '+' || COALESCE(f.resubmission_period_days, 14) || ' days')
  END,
  rl.last_reminder_sent_at,
  rl.last_reminder_status,
  datetime('now'),
  datetime('now')
FROM recipient_logs rl
JOIN forms f ON f.id = rl.form_id
WHERE rl.recipient_key IS NOT NULL;
