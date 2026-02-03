ALTER TABLE submission_comments ADD COLUMN parent_comment_id TEXT;
ALTER TABLE submission_comments ADD COLUMN quote_comment_id TEXT;
CREATE INDEX IF NOT EXISTS submission_comments_parent_comment_id_idx ON submission_comments(parent_comment_id);
CREATE INDEX IF NOT EXISTS submission_comments_quote_comment_id_idx ON submission_comments(quote_comment_id);
