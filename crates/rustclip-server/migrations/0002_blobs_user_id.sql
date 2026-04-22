-- Scope blob access by owner.
--
-- Before this migration any authenticated device could download /
-- delete any blob by guessing its UUID. Now the `user_id` is stored
-- on each row at upload time and SELECT/DELETE queries join on
-- `auth.user_id` to refuse cross-user access.

ALTER TABLE blobs ADD COLUMN user_id BLOB;

-- Pre-existing rows have NULL user_id. They belonged to whichever
-- clip_event references them. Backfill from that association so
-- upgrades don't orphan existing uploads, then enforce NOT-NULL at
-- the application layer (SQLite cannot ALTER a column to NOT NULL
-- without a table rewrite, and orphan rows are swept out by the
-- background sweeper anyway).
UPDATE blobs
SET user_id = (
    SELECT ce.user_id
    FROM clip_events ce
    WHERE ce.blob_id = blobs.id
    LIMIT 1
)
WHERE user_id IS NULL;

CREATE INDEX blobs_user_id ON blobs(user_id);
