-- NOTE: SQLite/D1 cannot safely drop a column with active foreign keys without
-- rebuilding dependent tables. We intentionally leave the column in place
-- and treat it as deprecated in code.
SELECT 1;
