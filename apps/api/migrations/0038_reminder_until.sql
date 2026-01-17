-- Migration number: 0038      2024-05-25T00:00:00.000Z
-- Add reminder expiration date to forms
ALTER TABLE forms ADD COLUMN reminder_until TEXT;
