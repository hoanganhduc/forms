-- Migration number: 0037 	 2024-05-24T00:00:00.000Z
-- Add periodic reminder settings to forms
ALTER TABLE forms ADD COLUMN reminder_enabled INTEGER DEFAULT 0;
ALTER TABLE forms ADD COLUMN reminder_frequency TEXT DEFAULT 'weekly';

-- Add periodic_reminders task
INSERT OR IGNORE INTO routine_tasks (id, name, cron, enabled) VALUES ('periodic_reminders', 'Periodic form reminders', '0 9 * * *', 1);
