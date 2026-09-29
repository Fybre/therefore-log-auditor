-- Per-tenant option to suppress digest emails on days with nothing new to report (the report
-- file is still written either way - this only affects whether it's emailed).
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS digest_only_on_new boolean NOT NULL DEFAULT false;
