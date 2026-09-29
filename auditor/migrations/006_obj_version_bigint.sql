-- obj_version is parsed from Therefore's log lines as a plain integer, but at least one real
-- log line uses 4294967295 (0xFFFFFFFF, an unsigned-32-bit sentinel) which overflows Postgres's
-- 4-byte `integer` column and aborted that file's COPY (caught and skipped by collector.py, but
-- it's a real gap in ingested data). bigint comfortably holds any 32-bit value, signed or not.
ALTER TABLE events ALTER COLUMN obj_version TYPE bigint;
