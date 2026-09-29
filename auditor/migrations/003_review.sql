-- Human review of a finding (the dashboard's "verdict feedback"), separate from the LLM's
-- own llm_verdict/llm_explanation. `findings.status` already exists (default 'open') and is
-- now the review workflow field: open | acknowledged | resolved | false_positive.

ALTER TABLE findings ADD COLUMN IF NOT EXISTS reviewed_by   text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS reviewed_note text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS reviewed_at   timestamptz;
