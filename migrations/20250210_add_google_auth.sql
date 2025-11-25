-- Migration: add Google authentication support, remove legacy is_paid flag
-- Run with: psql -d <database> -f migrations/20250210_add_google_auth.sql

BEGIN;

-- Drop legacy paid flag if it still exists
ALTER TABLE users
    DROP COLUMN IF EXISTS is_paid;

-- Allow password-based accounts to be optional so Google-only users can exist
ALTER TABLE users
    ALTER COLUMN password_hash DROP NOT NULL;

-- Add Google auth columns if they are missing
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS google_id TEXT,
    ADD COLUMN IF NOT EXISTS avatar_url TEXT;

-- Ensure google_id is unique when present
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id
    ON users(google_id)
    WHERE google_id IS NOT NULL;

COMMIT;

