ALTER TABLE live_settings ADD COLUMN poll_interval_seconds integer NOT NULL DEFAULT 15
    CHECK (poll_interval_seconds BETWEEN 5 AND 60);
