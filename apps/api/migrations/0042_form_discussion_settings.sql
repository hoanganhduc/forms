ALTER TABLE forms ADD COLUMN discussion_enabled INTEGER DEFAULT 0;
ALTER TABLE forms ADD COLUMN discussion_markdown_enabled INTEGER DEFAULT 1;
ALTER TABLE forms ADD COLUMN discussion_html_enabled INTEGER DEFAULT 0;
ALTER TABLE forms ADD COLUMN discussion_mathjax_enabled INTEGER DEFAULT 0;
