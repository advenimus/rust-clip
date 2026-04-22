-- M5: device tokens get an expiry.
--
-- Pre-migration rows have NULL expires_at which is treated as
-- "no expiry" for back-compat; the client can rotate them via
-- POST /api/v1/auth/refresh before they ever get a deadline.
-- Devices enrolled after this migration receive a 90-day TTL.
ALTER TABLE devices ADD COLUMN expires_at INTEGER;
CREATE INDEX devices_expiry ON devices(expires_at) WHERE expires_at IS NOT NULL;
